import asyncio
import logging

from app.config import settings

logger = logging.getLogger(__name__)


def detect_format(raw: str) -> str:
    """Detect syslog RFC 5424 vs RFC 3164 by version field after priority."""
    stripped = raw.lstrip()
    if stripped.startswith("<") and ">" in stripped:
        after_priority = stripped[stripped.index(">") + 1:]
        if after_priority.startswith("1 "):
            return "syslog_rfc5424"
    return "syslog_rfc3164"


def _handle_line(raw: str) -> None:
    from app.ingest.pipeline import process_line
    source = detect_format(raw)
    try:
        process_line(source, raw, strict=False)
    except Exception as exc:
        logger.warning(f"Syslog ingest failed ({source}): {exc}")


class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def datagram_received(self, data: bytes, addr) -> None:
        raw = data.decode("utf-8", errors="replace").strip()
        if raw:
            self._loop.run_in_executor(None, _handle_line, raw)

    def error_received(self, exc: Exception) -> None:
        logger.error(f"Syslog UDP error: {exc}")


async def _handle_tcp(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    loop = asyncio.get_event_loop()
    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            raw = line.decode("utf-8", errors="replace").strip()
            if raw:
                loop.run_in_executor(None, _handle_line, raw)
    except Exception:
        pass
    finally:
        writer.close()


async def start_syslog_listeners() -> list:
    """Start configured syslog UDP and TCP servers. Returns server objects for cleanup."""
    servers: list = []
    loop = asyncio.get_event_loop()

    udp_port = settings.tinysiem_syslog_udp_port
    if udp_port > 0:
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _UDPProtocol(loop),
                local_addr=("0.0.0.0", udp_port),
            )
            servers.append(transport)
            logger.info(f"Syslog UDP listener started on port {udp_port}")
        except Exception as exc:
            logger.error(f"Failed to start syslog UDP listener on port {udp_port}: {exc}")

    tcp_port = settings.tinysiem_syslog_tcp_port
    if tcp_port > 0:
        try:
            server = await asyncio.start_server(_handle_tcp, "0.0.0.0", tcp_port)
            servers.append(server)
            logger.info(f"Syslog TCP listener started on port {tcp_port}")
        except Exception as exc:
            logger.error(f"Failed to start syslog TCP listener on port {tcp_port}: {exc}")

    return servers


def stop_syslog_listeners(servers: list) -> None:
    for server in servers:
        try:
            server.close()
        except Exception:
            pass

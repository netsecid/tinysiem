import asyncio
import ipaddress
import logging

from app.config import settings

logger = logging.getLogger(__name__)

_dropped_counts = {"cidr": 0, "size": 0}


def _parse_allowed_networks() -> list:
    raw = settings.tinysiem_syslog_allow_cidrs.strip()
    if not raw:
        return []
    networks = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            networks.append(ipaddress.ip_network(chunk, strict=False))
        except ValueError:
            logger.warning(f"Ignoring invalid syslog CIDR entry: {chunk!r}")
    return networks


def _is_ip_allowed(ip_str: str, networks: list) -> bool:
    if not networks:
        return True
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in networks)


def get_dropped_counts() -> dict:
    return dict(_dropped_counts)


def reset_dropped_counts() -> None:
    _dropped_counts["cidr"] = 0
    _dropped_counts["size"] = 0


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
    def __init__(self, loop: asyncio.AbstractEventLoop, allowed_networks: list) -> None:
        self._loop = loop
        self._allowed_networks = allowed_networks

    def datagram_received(self, data: bytes, addr) -> None:
        if len(data) > settings.tinysiem_syslog_max_bytes:
            _dropped_counts["size"] += 1
            return
        if not _is_ip_allowed(addr[0], self._allowed_networks):
            _dropped_counts["cidr"] += 1
            return
        raw = data.decode("utf-8", errors="replace").strip()
        if raw:
            self._loop.run_in_executor(None, _handle_line, raw)

    def error_received(self, exc: Exception) -> None:
        logger.error(f"Syslog UDP error: {exc}")


async def _handle_tcp(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    loop = asyncio.get_event_loop()
    peer = writer.get_extra_info("peername")
    peer_ip = peer[0] if peer else None
    allowed_networks = _parse_allowed_networks()
    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            if len(line) > settings.tinysiem_syslog_max_bytes:
                _dropped_counts["size"] += 1
                continue
            if peer_ip and not _is_ip_allowed(peer_ip, allowed_networks):
                _dropped_counts["cidr"] += 1
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
    allowed_networks = _parse_allowed_networks()

    udp_port = settings.tinysiem_syslog_udp_port
    if udp_port > 0:
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _UDPProtocol(loop, allowed_networks),
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

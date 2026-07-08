import ipaddress
from unittest.mock import MagicMock

from app.listeners.syslog import (
    _UDPProtocol,
    _is_ip_allowed,
    _parse_allowed_networks,
    get_dropped_counts,
    reset_dropped_counts,
)


def test_parse_allowed_networks_empty_means_allow_all(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "tinysiem_syslog_allow_cidrs", "")
    assert _parse_allowed_networks() == []


def test_parse_allowed_networks_parses_multiple_cidrs(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "tinysiem_syslog_allow_cidrs", "10.0.0.0/8, 192.168.1.5")
    nets = _parse_allowed_networks()
    assert len(nets) == 2
    assert ipaddress.ip_address("10.1.2.3") in nets[0]


def test_parse_allowed_networks_ignores_invalid_entries(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "tinysiem_syslog_allow_cidrs", "10.0.0.0/8, not-a-cidr")
    nets = _parse_allowed_networks()
    assert len(nets) == 1


def test_is_ip_allowed_empty_networks_allows_any():
    assert _is_ip_allowed("1.2.3.4", []) is True


def test_is_ip_allowed_matches_cidr():
    nets = [ipaddress.ip_network("10.0.0.0/8")]
    assert _is_ip_allowed("10.1.2.3", nets) is True
    assert _is_ip_allowed("192.168.1.1", nets) is False


def test_udp_drops_oversized_datagram(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "tinysiem_syslog_max_bytes", 10)
    reset_dropped_counts()
    proto = _UDPProtocol(loop=MagicMock(), allowed_networks=[])
    proto.datagram_received(b"x" * 20, ("1.2.3.4", 5000))
    assert get_dropped_counts()["size"] == 1


def test_udp_drops_disallowed_source_ip(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "tinysiem_syslog_max_bytes", 8192)
    reset_dropped_counts()
    nets = [ipaddress.ip_network("10.0.0.0/8")]
    proto = _UDPProtocol(loop=MagicMock(), allowed_networks=nets)
    proto.datagram_received(b"<34>test", ("192.168.1.1", 5000))
    assert get_dropped_counts()["cidr"] == 1


def test_udp_allows_matching_source_ip():
    reset_dropped_counts()
    nets = [ipaddress.ip_network("10.0.0.0/8")]
    loop = MagicMock()
    proto = _UDPProtocol(loop=loop, allowed_networks=nets)
    proto.datagram_received(b"<34>test", ("10.1.1.1", 5000))
    loop.run_in_executor.assert_called_once()
    assert get_dropped_counts()["cidr"] == 0


async def test_health_reports_syslog_dropped_counts(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert "syslog_dropped" in resp.json()["listeners"]

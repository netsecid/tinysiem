"""Tests for built-in decoders (syslog, windows event, cloudtrail, iptables)."""
from datetime import datetime
from pathlib import Path

import pytest

from app.decoder import engine as decoder_engine

DECODERS_DIR = Path(__file__).parent.parent / "decoder" / "decoders"

RFC3164_SAMPLE = "<34>Jan 15 10:30:00 myhost sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2"
RFC5424_SAMPLE = "<34>1 2024-01-15T10:30:00.000000+00:00 myhost sshd 1234 - - Failed password for root"
WINDOWS_EVENT_SAMPLE = '{"@timestamp":"2024-01-15T10:30:00Z","message":"An account failed to log on.","winlog":{"event_id":4625,"computer_name":"WORKSTATION1"},"source":{"ip":"192.168.1.100"},"user":{"name":"Administrator"},"event":{"action":"logon-failed"}}'
CLOUDTRAIL_SAMPLE = '{"eventTime":"2024-01-15T10:30:00Z","eventName":"ConsoleLogin","sourceIPAddress":"203.0.113.1","userAgent":"Mozilla/5.0","eventID":"abc-123","userIdentity":{"type":"IAMUser","userName":"admin"},"awsRegion":"us-east-1","responseElements":{"ConsoleLogin":"Failure"}}'
IPTABLES_SAMPLE = "Jan 15 10:30:00 server kernel: [123456.789] IN=eth0 OUT= SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=12345 DPT=22"


def setup_module(_):
    decoder_engine.load_decoders(DECODERS_DIR)


def test_syslog_rfc3164_decodes():
    event = decoder_engine.decode("syslog_rfc3164", RFC3164_SAMPLE)
    assert event is not None
    assert event["source"] == "syslog_rfc3164"


def test_syslog_rfc3164_fields():
    event = decoder_engine.decode("syslog_rfc3164", RFC3164_SAMPLE)
    assert event is not None
    extra = event.get("extra", {})
    assert extra.get("hostname") == "myhost"
    assert extra.get("program") == "sshd"
    assert extra.get("pid") == "1234"
    assert "Failed password" in extra.get("message", "")


def test_syslog_rfc3164_no_match_returns_none():
    event = decoder_engine.decode("syslog_rfc3164", "not a syslog line at all")
    assert event is None


def test_syslog_rfc5424_decodes():
    event = decoder_engine.decode("syslog_rfc5424", RFC5424_SAMPLE)
    assert event is not None
    assert event["source"] == "syslog_rfc5424"


def test_syslog_rfc5424_fields():
    event = decoder_engine.decode("syslog_rfc5424", RFC5424_SAMPLE)
    assert event is not None
    extra = event.get("extra", {})
    assert extra.get("hostname") == "myhost"
    assert extra.get("program") == "sshd"
    assert "Failed password" in extra.get("message", "")


def test_windows_event_decodes():
    event = decoder_engine.decode("windows_event", WINDOWS_EVENT_SAMPLE)
    assert event is not None
    assert event["source"] == "windows_event"


def test_windows_event_nested_field():
    event = decoder_engine.decode("windows_event", WINDOWS_EVENT_SAMPLE)
    assert event is not None
    assert event.get("source_ip") == "192.168.1.100"
    extra = event.get("extra", {})
    assert extra.get("computer") == "WORKSTATION1"


def test_aws_cloudtrail_decodes():
    event = decoder_engine.decode("aws_cloudtrail", CLOUDTRAIL_SAMPLE)
    assert event is not None
    assert event["source"] == "aws_cloudtrail"


def test_aws_cloudtrail_fields():
    event = decoder_engine.decode("aws_cloudtrail", CLOUDTRAIL_SAMPLE)
    assert event is not None
    assert event.get("source_ip") == "203.0.113.1"
    assert event.get("method") == "ConsoleLogin"
    extra = event.get("extra", {})
    assert extra.get("region") == "us-east-1"


def test_iptables_decodes():
    event = decoder_engine.decode("iptables", IPTABLES_SAMPLE)
    assert event is not None
    assert event["source"] == "iptables"


def test_iptables_fields():
    event = decoder_engine.decode("iptables", IPTABLES_SAMPLE)
    assert event is not None
    assert event.get("source_ip") == "192.168.1.100"
    assert event.get("method") == "TCP"
    extra = event.get("extra", {})
    assert extra.get("dst_port") == "22"


# --- ufw firewall log (rsyslog ISO8601 + kernel [UFW BLOCK] KV) ---

UFW_TCP_SAMPLE = (
    "2026-08-09T00:00:06.643004+08:00 localhost kernel: [UFW BLOCK] IN=eth0 OUT= "
    "MAC=52:54:00:43:8e:0a:fe:ee:58:cb:8e:59:08:00 SRC=45.205.1.240 DST=10.11.10.56 "
    "LEN=40 TOS=0x08 PREC=0x60 TTL=240 ID=54321 PROTO=TCP SPT=38711 DPT=18182 "
    "WINDOW=65535 RES=0x00 SYN URGP=0 "
)
UFW_ICMP_SAMPLE = (
    "2026-08-09T00:00:06.643004+08:00 localhost kernel: [UFW BLOCK] IN=eth0 OUT= "
    "MAC=52:54:00:43:8e:0a:fe:ee:58:cb:8e:59:08:00 SRC=141.98.10.109 DST=10.11.10.56 "
    "LEN=84 TOS=0x00 PREC=0x00 TTL=242 ID=10038 PROTO=ICMP TYPE=8 CODE=0 "
)


def test_ufw_tcp_decodes():
    event = decoder_engine.decode("ufw", UFW_TCP_SAMPLE)
    assert event is not None
    assert event["source"] == "ufw"
    assert event.get("source_ip") == "45.205.1.240"
    assert event.get("method") == "TCP"
    extra = event.get("extra", {})
    assert extra.get("action") == "BLOCK"
    assert extra.get("dst_port") == "18182"
    assert extra.get("src_port") == "38711"


def test_ufw_event_time_converted_to_utc():
    event = decoder_engine.decode("ufw", UFW_TCP_SAMPLE)
    assert event is not None
    # 2026-08-09T00:00:06+08:00 == 2026-08-08T16:00:06Z — stored naive UTC.
    assert event["event_time"] == datetime(2026, 8, 8, 16, 0, 6, 643004)


def test_ufw_icmp_no_ports():
    event = decoder_engine.decode("ufw", UFW_ICMP_SAMPLE)
    assert event is not None
    assert event.get("method") == "ICMP"
    assert event.get("source_ip") == "141.98.10.109"
    extra = event.get("extra", {})
    assert "dst_port" not in extra
    assert "src_port" not in extra


def test_ufw_no_match_returns_none():
    event = decoder_engine.decode("ufw", "not a ufw line at all")
    assert event is None


# --- fail2ban log (custom format, local-time timestamps) ---

FAIL2BAN_FOUND_SAMPLE = (
    "2026-08-09 00:01:01,040 fail2ban.filter         [1751546]: INFO    "
    "[sshd] Found 204.168.201.227 - 2026-08-09 00:01:00"
)
FAIL2BAN_BAN_SAMPLE = (
    "2026-08-09 00:02:04,205 fail2ban.actions        [1751546]: NOTICE  "
    "[sshd] Ban 113.161.39.122"
)
FAIL2BAN_UNBAN_SAMPLE = (
    "2026-08-09 00:01:52,984 fail2ban.actions        [1751546]: NOTICE  "
    "[sshd] Unban 113.161.39.122"
)


def test_fail2ban_found_decodes():
    event = decoder_engine.decode("fail2ban", FAIL2BAN_FOUND_SAMPLE)
    assert event is not None
    assert event["source"] == "fail2ban"
    assert event.get("source_ip") == "204.168.201.227"
    assert event.get("method") == "Found"
    extra = event.get("extra", {})
    assert extra.get("jail") == "sshd"
    assert extra.get("level") == "INFO"
    assert extra.get("component") == "filter"


def test_fail2ban_ban_decodes():
    event = decoder_engine.decode("fail2ban", FAIL2BAN_BAN_SAMPLE)
    assert event is not None
    assert event.get("source_ip") == "113.161.39.122"
    assert event.get("method") == "Ban"
    extra = event.get("extra", {})
    assert extra.get("jail") == "sshd"
    assert extra.get("level") == "NOTICE"


def test_fail2ban_unban_decodes():
    event = decoder_engine.decode("fail2ban", FAIL2BAN_UNBAN_SAMPLE)
    assert event is not None
    assert event.get("method") == "Unban"
    assert event.get("source_ip") == "113.161.39.122"


def test_fail2ban_event_time_declared_tz_to_utc():
    event = decoder_engine.decode("fail2ban", FAIL2BAN_BAN_SAMPLE)
    assert event is not None
    # Log is server-local +08:00 (no offset written) — decoder declares timestamp_tz.
    # 2026-08-09 00:02:04 +08:00 == 2026-08-08 16:02:04Z — stored naive UTC.
    assert event["event_time"] == datetime(2026, 8, 8, 16, 2, 4)


def test_fail2ban_no_match_returns_none():
    event = decoder_engine.decode("fail2ban", "2026-08-09 00:00:02,453 fail2ban.server [1751546]: INFO    rollover performed on /var/log/fail2ban.log")
    assert event is None

"""Tests for built-in decoders (syslog, windows event, cloudtrail, iptables)."""
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

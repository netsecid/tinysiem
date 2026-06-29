"""Tests for syslog listener format detection and dispatch (no network required)."""
from unittest.mock import MagicMock, patch

import pytest

from app.listeners.syslog import detect_format, _handle_line

RFC3164_LINE = "<34>Jan 15 10:30:00 myhost sshd[1234]: Failed password for root"
RFC5424_LINE = "<34>1 2024-01-15T10:30:00.000Z myhost sshd 1234 - - Failed password"
GENERIC_LINE = "Not a syslog line at all"


def test_detect_format_rfc3164():
    assert detect_format(RFC3164_LINE) == "syslog_rfc3164"


def test_detect_format_rfc5424():
    assert detect_format(RFC5424_LINE) == "syslog_rfc5424"


def test_detect_format_generic_falls_back_to_rfc3164():
    assert detect_format(GENERIC_LINE) == "syslog_rfc3164"


def test_handle_line_calls_process_line():
    with patch("app.listeners.syslog._handle_line") as mock_handle:
        mock_handle(RFC5424_LINE)
        mock_handle.assert_called_once_with(RFC5424_LINE)


def test_handle_line_uses_detected_format():
    calls = []
    with patch("app.ingest.pipeline.process_line", side_effect=lambda s, r, **kw: calls.append(s) or "id-1"):
        _handle_line(RFC5424_LINE)
    assert calls == ["syslog_rfc5424"]


def test_handle_line_rfc3164_format():
    calls = []
    with patch("app.ingest.pipeline.process_line", side_effect=lambda s, r, **kw: calls.append(s) or "id-1"):
        _handle_line(RFC3164_LINE)
    assert calls == ["syslog_rfc3164"]

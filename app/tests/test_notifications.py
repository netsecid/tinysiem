"""Tests for the notifications module."""
import uuid
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

import pytest


def _test_alert():
    return {
        "alert_id": str(uuid.uuid4()),
        "rule_name": "test-rule",
        "severity": "high",
        "triggered_at": datetime.now(timezone.utc).isoformat(),
        "source_ip": "1.2.3.4",
        "summary": "Test alert",
        "mitre_tactic": "Test",
        "mitre_technique": "T0000",
    }


def test_should_notify_high_severity():
    from app.notifications.sender import should_notify
    with patch("app.notifications.sender.settings") as mock_settings:
        mock_settings.tinysiem_notify_min_sev = "high"
        assert should_notify("high") is True
        assert should_notify("critical") is True


def test_should_notify_low_excluded():
    from app.notifications.sender import should_notify
    with patch("app.notifications.sender.settings") as mock_settings:
        mock_settings.tinysiem_notify_min_sev = "high"
        assert should_notify("low") is False
        assert should_notify("medium") is False


def test_send_email_skipped_when_no_host():
    from app.notifications.sender import send_email
    with patch("app.notifications.sender.settings") as mock_settings:
        mock_settings.tinysiem_smtp_host = ""
        mock_settings.tinysiem_smtp_to = ""
        send_email(_test_alert())  # must not raise


def test_send_webhook_skipped_when_no_url():
    from app.notifications.sender import send_webhook
    with patch("app.notifications.sender.settings") as mock_settings:
        mock_settings.tinysiem_webhook_url = ""
        send_webhook(_test_alert())  # must not raise


def test_notify_calls_nothing_below_min_sev():
    from app.notifications.sender import notify
    with patch("app.notifications.sender.settings") as mock_settings, \
         patch("app.notifications.sender.send_email") as mock_email, \
         patch("app.notifications.sender.send_webhook") as mock_webhook:
        mock_settings.tinysiem_notify_min_sev = "high"
        alert = _test_alert()
        alert["severity"] = "low"
        notify(alert)
        mock_email.assert_not_called()
        mock_webhook.assert_not_called()


async def test_notifications_test_endpoint_requires_admin(client, analyst_headers):
    resp = await client.post("/notifications/test", json={"channel": "all"}, headers=analyst_headers)
    assert resp.status_code == 403


async def test_notifications_test_endpoint_skipped_when_not_configured(client, admin_headers):
    resp = await client.post("/notifications/test", json={"channel": "all"}, headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    # Both channels should show "sent" (they skip silently when not configured)
    assert "email" in data or "webhook" in data


async def test_notifications_config_endpoint(client, admin_headers):
    resp = await client.get("/notifications/config", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "email_enabled" in data
    assert "webhook_enabled" in data
    assert "min_severity" in data
    assert data["email_enabled"] is False  # SMTP host not set in test env

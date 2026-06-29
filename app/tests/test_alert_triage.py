"""Tests for alert triage workflow (GET/PATCH /alerts/{id}, /alerts/triage-summary)."""
import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest


def _make_alert(alert_id=None, severity="medium"):
    return {
        "alert_id": alert_id or str(uuid.uuid4()),
        "triggered_at": datetime.now(timezone.utc).isoformat(),
        "rule_name": "test-rule",
        "severity": severity,
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1595",
        "event_id": str(uuid.uuid4()),
        "source_ip": "10.0.0.1",
        "summary": "Test alert",
    }


@pytest.fixture
def alerts_file(tmp_path):
    """Write a temp alerts JSONL file with one alert and patch settings to point at it."""
    alert = _make_alert()
    log_path = tmp_path / "alerts.log"
    log_path.write_text(json.dumps(alert) + "\n")
    with patch("app.config.settings.tinysiem_alerts_path", str(log_path)):
        yield log_path, alert


async def test_get_alerts_includes_triage_fields(client, admin_headers, alerts_file):
    _, alert = alerts_file
    resp = await client.get("/alerts", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    found = next((a for a in data["alerts"] if a["alert_id"] == alert["alert_id"]), None)
    assert found is not None
    assert found["status"] == "open"
    assert found["notes"] == ""
    assert found["assigned_to"] == ""


async def test_triage_summary_returns_counts(client, admin_headers, alerts_file):
    resp = await client.get("/alerts/triage-summary", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "open" in data
    assert "investigating" in data
    assert "resolved" in data


async def test_get_single_alert(client, admin_headers, alerts_file):
    _, alert = alerts_file
    resp = await client.get(f"/alerts/{alert['alert_id']}", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["alert_id"] == alert["alert_id"]
    assert data["status"] == "open"


async def test_get_single_alert_not_found(client, admin_headers, alerts_file):
    resp = await client.get(f"/alerts/{uuid.uuid4()}", headers=admin_headers)
    assert resp.status_code == 404


async def test_patch_alert_status(client, admin_headers, alerts_file):
    _, alert = alerts_file
    resp = await client.patch(
        f"/alerts/{alert['alert_id']}",
        json={"status": "investigating"},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "investigating"


async def test_patch_alert_invalid_status(client, admin_headers, alerts_file):
    _, alert = alerts_file
    resp = await client.patch(
        f"/alerts/{alert['alert_id']}",
        json={"status": "invalid-status"},
        headers=admin_headers,
    )
    assert resp.status_code == 422


async def test_patch_alert_not_found(client, admin_headers):
    resp = await client.patch(
        f"/alerts/{uuid.uuid4()}",
        json={"status": "resolved"},
        headers=admin_headers,
    )
    assert resp.status_code == 404


async def test_patch_alert_partial_update(client, admin_headers, alerts_file):
    _, alert = alerts_file
    alert_id = alert["alert_id"]
    # Set initial state
    await client.patch(f"/alerts/{alert_id}", json={"status": "investigating", "notes": "first note"}, headers=admin_headers)
    # Patch only notes — status should remain
    resp = await client.patch(f"/alerts/{alert_id}", json={"notes": "updated note"}, headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "investigating"
    assert data["notes"] == "updated note"


async def test_patch_alert_requires_auth(client, alerts_file):
    _, alert = alerts_file
    resp = await client.patch(f"/alerts/{alert['alert_id']}", json={"status": "resolved"})
    assert resp.status_code == 401


async def test_triage_summary_requires_auth(client):
    resp = await client.get("/alerts/triage-summary")
    assert resp.status_code == 401


async def test_patch_alert_sets_assigned_to(client, admin_headers, alerts_file):
    _, alert = alerts_file
    resp = await client.patch(
        f"/alerts/{alert['alert_id']}",
        json={"assigned_to": "analyst1"},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["assigned_to"] == "analyst1"


async def test_alerts_list_supports_status_filter(client, admin_headers, alerts_file):
    _, alert = alerts_file
    alert_id = alert["alert_id"]
    # Move alert to resolved
    await client.patch(f"/alerts/{alert_id}", json={"status": "resolved"}, headers=admin_headers)
    # Filter by resolved — should find it
    resp = await client.get("/alerts?status=resolved", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["total"] >= 1
    # Filter by open — should not find it
    resp2 = await client.get("/alerts?status=open", headers=admin_headers)
    assert all(a["alert_id"] != alert_id for a in resp2.json()["alerts"])

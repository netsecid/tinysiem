import uuid
import pytest
from datetime import datetime


async def _ingest_event(client, auth_headers, source_ip="1.2.3.4", status_code=200):
    """Helper: ingest a raw nginx log and return the event from the events list."""
    raw = f'{source_ip} - - [01/Jul/2026:10:00:00 +0000] "GET /test HTTP/1.1" {status_code} 512 "-" "curl/8.0"'
    resp = await client.post(
        "/ingest/raw",
        json={"source": "nginx", "raw": raw},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    events_resp = await client.get(f"/events?source_ip={source_ip}&limit=1", headers=auth_headers)
    return events_resp.json()["events"][0]


async def test_get_event_by_id_returns_full_record(client, auth_headers):
    event = await _ingest_event(client, auth_headers, source_ip="10.0.0.1")
    event_id = event["id"]
    resp = await client.get(f"/events/{event_id}", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == event_id
    assert data["source"] == "nginx"
    assert data["source_ip"] == "10.0.0.1"
    assert "raw" in data
    assert "ingested_at" in data


async def test_get_event_by_id_not_found(client, auth_headers):
    resp = await client.get(f"/events/{uuid.uuid4()}", headers=auth_headers)
    assert resp.status_code == 404


async def test_get_event_by_id_requires_auth(client):
    resp = await client.get(f"/events/{uuid.uuid4()}")
    assert resp.status_code == 401


async def test_get_alert_cases_unlinked(client, analyst_headers):
    """Alert not in any case returns empty list."""
    resp = await client.get("/alerts/nonexistent-alert-id/cases", headers=analyst_headers)
    assert resp.status_code == 200
    assert resp.json() == {"cases": []}


async def test_get_alert_cases_linked(client, analyst_headers, auth_headers):
    """Alert linked to a case returns that case."""
    import json
    from pathlib import Path
    from app.alerts.file_writer import write_alert
    from app.cases import store as case_store
    from app.config import settings

    rule = {"name": "test-link-rule", "severity": "medium"}
    event = {"id": str(uuid.uuid4()), "source_ip": "3.3.3.3"}
    write_alert(rule, event)

    path = Path(settings.tinysiem_alerts_path)
    alerts = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    alert_id = [a for a in alerts if a.get("rule_name") == "test-link-rule"][-1]["alert_id"]

    cr = await client.post("/cases", json={"title": "Link Test Case"}, headers=analyst_headers)
    case_id = cr.json()["case_id"]
    await client.post(f"/cases/{case_id}/alerts", json={"alert_ids": [alert_id]}, headers=analyst_headers)

    resp = await client.get(f"/alerts/{alert_id}/cases", headers=analyst_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["cases"]) == 1
    assert data["cases"][0]["case_id"] == case_id
    assert data["cases"][0]["title"] == "Link Test Case"
    assert "linked_at" in data["cases"][0]

    # Cleanup: remove case so test_cases.py::test_list_cases_empty sees an empty table
    case_store.delete_case(case_id)


async def test_get_alert_cases_requires_auth(client):
    resp = await client.get("/alerts/some-alert-id/cases")
    assert resp.status_code == 401

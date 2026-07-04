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

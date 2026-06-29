"""Tests for POST /ingest/beats (Elasticsearch bulk format)."""
import json

import pytest


def _bulk_body(*docs) -> bytes:
    """Build an ES bulk ndjson body from doc dicts."""
    lines = []
    for doc in docs:
        lines.append(json.dumps({"index": {"_index": "filebeat"}}))
        lines.append(json.dumps(doc))
    return "\n".join(lines).encode()


async def test_beats_single_event(client, admin_headers):
    body = _bulk_body({"message": "hello world", "fields": {"source": "syslog_rfc3164"}})
    resp = await client.post("/ingest/beats", content=body, headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["took"] == 1
    assert not data["errors"]


async def test_beats_multiple_events(client, admin_headers):
    body = _bulk_body(
        {"message": "line one", "fields": {"source": "syslog_rfc3164"}},
        {"message": "line two", "fields": {"source": "syslog_rfc3164"}},
    )
    resp = await client.post("/ingest/beats", content=body, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["took"] == 2


async def test_beats_uses_fields_source(client, admin_headers):
    body = _bulk_body({"message": "test log", "fields": {"source": "nginx"}})
    resp = await client.post("/ingest/beats", content=body, headers=admin_headers)
    assert resp.status_code == 200


async def test_beats_uses_agent_type_fallback(client, admin_headers):
    body = _bulk_body({"message": "test log", "agent": {"type": "filebeat"}})
    resp = await client.post("/ingest/beats", content=body, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["took"] == 1


async def test_beats_fallback_source_beats(client, admin_headers):
    body = _bulk_body({"message": "no source field at all"})
    resp = await client.post("/ingest/beats", content=body, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["took"] == 1


async def test_beats_requires_auth(client):
    body = _bulk_body({"message": "test"})
    resp = await client.post("/ingest/beats", content=body)
    assert resp.status_code == 401

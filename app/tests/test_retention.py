"""Tests for log retention and archiving."""
import json
import os
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest


def _insert_old_event(days_ago=35):
    from app.storage import duckdb_store
    event_id = str(uuid.uuid4())
    event = {
        "id": event_id,
        "source": "nginx",
        "ingested_at": datetime.utcnow() - timedelta(days=days_ago),
        "event_time": None,
        "source_ip": "10.0.0.1",
        "method": "GET",
        "uri": "/old",
        "status_code": 200,
        "response_size": 100,
        "user_agent": "test",
        "referer": None,
        "raw": "old event",
        "extra": {},
    }
    duckdb_store.insert_event(event)
    return event_id


async def test_retention_status_returns_structure(client, admin_headers):
    resp = await client.get("/retention/status", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "online_events" in data
    assert "retention_days" in data
    assert "archive_files" in data
    assert "last_run" in data


async def test_retention_status_requires_admin(client, analyst_headers):
    resp = await client.get("/retention/status", headers=analyst_headers)
    assert resp.status_code == 403


async def test_run_retention_no_old_events(client, admin_headers, tmp_path):
    with patch("app.config.settings.tinysiem_retention_days", 30), \
         patch("app.config.settings.tinysiem_archive_path", str(tmp_path)):
        resp = await client.post("/retention/run", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "archived" in data
    assert data["archived"] == 0


async def test_run_retention_archives_old_events(client, admin_headers, tmp_path):
    event_id = _insert_old_event(days_ago=35)
    with patch("app.config.settings.tinysiem_retention_days", 30), \
         patch("app.config.settings.tinysiem_archive_path", str(tmp_path)), \
         patch("app.config.settings.tinysiem_archive_chunk_mb", 500):
        resp = await client.post("/retention/run", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["archived"] >= 1


async def test_archived_events_deleted_from_duckdb(client, admin_headers, tmp_path):
    from app.storage import duckdb_store
    event_id = _insert_old_event(days_ago=40)
    before = duckdb_store.count_all_events()
    with patch("app.config.settings.tinysiem_retention_days", 30), \
         patch("app.config.settings.tinysiem_archive_path", str(tmp_path)), \
         patch("app.config.settings.tinysiem_archive_chunk_mb", 500):
        await client.post("/retention/run", headers=admin_headers)
    after = duckdb_store.count_all_events()
    assert after < before


async def test_archive_file_created(client, admin_headers, tmp_path):
    _insert_old_event(days_ago=35)
    with patch("app.config.settings.tinysiem_retention_days", 30), \
         patch("app.config.settings.tinysiem_archive_path", str(tmp_path)), \
         patch("app.config.settings.tinysiem_archive_chunk_mb", 500):
        resp = await client.post("/retention/run", headers=admin_headers)
    data = resp.json()
    if data["archived"] > 0:
        gz_files = list(tmp_path.glob("*.jsonl.gz"))
        assert len(gz_files) >= 1


async def test_run_retention_requires_admin(client, analyst_headers):
    resp = await client.post("/retention/run", headers=analyst_headers)
    assert resp.status_code == 403


def test_count_all_events():
    from app.storage import duckdb_store
    before = duckdb_store.count_all_events()
    event = {
        "id": str(uuid.uuid4()),
        "source": "test",
        "ingested_at": datetime.utcnow(),
        "event_time": None,
        "source_ip": "1.2.3.4",
        "method": "GET",
        "uri": "/count-test",
        "status_code": 200,
        "response_size": 0,
        "user_agent": "test",
        "referer": None,
        "raw": "count test",
        "extra": {},
    }
    duckdb_store.insert_event(event)
    after = duckdb_store.count_all_events()
    assert after == before + 1


def test_delete_events_by_ids():
    from app.storage import duckdb_store
    event_id = str(uuid.uuid4())
    duckdb_store.insert_event({
        "id": event_id, "source": "test", "ingested_at": datetime.utcnow(),
        "event_time": None, "source_ip": None, "method": None, "uri": None,
        "status_code": None, "response_size": None, "user_agent": None,
        "referer": None, "raw": "delete test", "extra": {},
    })
    deleted = duckdb_store.delete_events_by_ids([event_id])
    assert deleted == 1
    result = duckdb_store.query_events(q="delete test")
    assert all(e["id"] != event_id for e in result["events"])

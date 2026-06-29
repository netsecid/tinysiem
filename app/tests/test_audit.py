"""Tests for v0.9 audit logging."""
import time
import uuid
from unittest.mock import patch

import pytest

from app.audit import store as audit
from app.storage import duckdb_store


def _latest_audit(event_type: str, actor: str = None) -> dict | None:
    result = duckdb_store.query_audit(event_type=event_type, actor=actor, limit=1)
    return result["items"][0] if result["items"] else None


# ── Direct store tests ────────────────────────────────────────────────────────

def test_log_event_creates_entry():
    uid = str(uuid.uuid4())
    audit.log_event(
        "test.event", "create", "success",
        actor=f"tester-{uid}",
        resource_type="test", resource_id="res-1",
        detail={"key": "value"},
        ip_address="127.0.0.1",
        duration_ms=42,
    )
    result = duckdb_store.query_audit(actor=f"tester-{uid}")
    assert result["total"] == 1
    item = result["items"][0]
    assert item["event_type"] == "test.event"
    assert item["action"] == "create"
    assert item["status"] == "success"
    assert item["ip_address"] == "127.0.0.1"
    assert item["duration_ms"] == 42
    assert item["detail"]["key"] == "value"


def test_log_event_never_raises():
    """Audit writes must not propagate exceptions."""
    with patch("app.storage.duckdb_store.insert_audit_event", side_effect=RuntimeError("db down")):
        audit.log_event("test.event", "create")  # must not raise


# ── Auth audit ────────────────────────────────────────────────────────────────

async def test_login_success_creates_audit(client):
    resp = await client.post("/auth/login", json={"username": "admin", "password": "admin"})
    assert resp.status_code == 200
    entry = _latest_audit("auth.login", actor="admin")
    assert entry is not None
    assert entry["status"] == "success"


async def test_login_failure_creates_audit(client):
    resp = await client.post("/auth/login", json={"username": "admin", "password": "wrongpass"})
    assert resp.status_code == 401
    entry = _latest_audit("auth.login", actor="admin")
    assert entry is not None
    assert entry["status"] == "failure"


# ── GET /audit authorization ──────────────────────────────────────────────────

async def test_audit_list_requires_admin(client, analyst_headers):
    resp = await client.get("/audit", headers=analyst_headers)
    assert resp.status_code == 403


async def test_audit_list_requires_auth(client):
    resp = await client.get("/audit")
    assert resp.status_code == 401


async def test_audit_list_returns_entries(client, admin_headers):
    resp = await client.get("/audit", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "items" in data
    assert isinstance(data["items"], list)


async def test_audit_list_filters_by_event_type(client, admin_headers):
    uid = str(uuid.uuid4())
    audit.log_event("custom.test", "action", actor=f"u-{uid}")
    resp = await client.get(f"/audit?event_type=custom.test&actor=u-{uid}", headers=admin_headers)
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["event_type"] == "custom.test"


async def test_audit_list_filters_by_status(client, admin_headers):
    uid = str(uuid.uuid4())
    audit.log_event("x.test", "a", "success", actor=f"s-{uid}")
    audit.log_event("x.test", "a", "failure", actor=f"s-{uid}")
    resp = await client.get(f"/audit?status=failure&actor=s-{uid}", headers=admin_headers)
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["status"] == "failure"


async def test_audit_facets_structure(client, admin_headers):
    resp = await client.get("/audit/facets", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "event_type" in data
    assert "actor" in data
    assert "status" in data
    assert isinstance(data["event_type"], list)


# ── Parser / Rule CRUD audit ──────────────────────────────────────────────────

async def test_parser_create_creates_audit(client, admin_headers):
    uid = str(uuid.uuid4())[:8]
    name = f"test-{uid}"
    yaml_text = (
        f"name: {name}\nsource: test-src-{uid}\ntype: regex\n"
        f"pattern: '^(?P<msg>.+)$'\nfields:\n  message: msg\n"
    )
    resp = await client.post("/parsers", json={"name": name, "yaml_text": yaml_text}, headers=admin_headers)
    assert resp.status_code == 201
    entry = _latest_audit("parser.create")
    assert entry is not None
    assert entry["action"] == "created"
    assert entry["resource_id"] == name


async def test_rule_create_creates_audit(client, admin_headers):
    uid = str(uuid.uuid4())[:8]
    name = f"test-rule-{uid}"
    yaml_text = (
        f"name: {name}\nseverity: low\nsource: nginx\n"
        f"condition:\n  type: field_match\n  field: method\n  value: GET\n  operator: eq\n"
    )
    resp = await client.post("/rules", json={"name": name, "yaml_text": yaml_text}, headers=admin_headers)
    assert resp.status_code == 201
    entry = _latest_audit("rule.create")
    assert entry is not None
    assert entry["resource_id"] == name


# ── AI call audit ─────────────────────────────────────────────────────────────

async def test_ai_call_logged_on_generate_parser(client, admin_headers):
    mock_yaml = (
        "name: mock-parser\nsource: mock\ntype: regex\n"
        "pattern: '^(?P<msg>.+)$'\nfields:\n  message: msg\n"
    )
    with patch("app.ai.claude._get_client") as mock_client:
        mock_resp = mock_client.return_value.messages.create.return_value
        mock_resp.content = [type("C", (), {"text": mock_yaml})()]
        resp = await client.post(
            "/parsers/generate",
            json={"log_sample": "sample log line for testing"},
            headers=admin_headers,
        )
    assert resp.status_code == 200
    entry = _latest_audit("ai.call")
    assert entry is not None
    assert entry["action"] == "generate_parser"
    assert entry["detail"]["model"] == "claude-sonnet-4-6"
    assert "prompt_preview" in entry["detail"]
    assert "duration_ms" in entry["detail"]


# ── User management audit ─────────────────────────────────────────────────────

async def test_user_create_creates_audit(client, superadmin_headers):
    uid = str(uuid.uuid4())[:8]
    username = f"audituser-{uid}"
    resp = await client.post(
        "/users",
        json={"username": username, "password": "pass123", "role": "analyst"},
        headers=superadmin_headers,
    )
    assert resp.status_code == 201
    entry = _latest_audit("user.create")
    assert entry is not None
    assert entry["resource_id"] == username
    assert entry["detail"]["target_role"] == "analyst"

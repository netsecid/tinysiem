"""Tests for Cases & Workflow (v1.0) and Log Sources."""
import pytest


# ── Cases ──────────────────────────────────────────────────────────────────────

async def test_list_cases_empty(client, analyst_headers):
    resp = await client.get("/cases", headers=analyst_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["cases"] == []


async def test_create_case_minimal(client, analyst_headers):
    resp = await client.post("/cases", json={"title": "Test Case Alpha"}, headers=analyst_headers)
    assert resp.status_code == 201
    data = resp.json()
    assert data["title"] == "Test Case Alpha"
    assert data["status"] == "open"
    assert data["severity"] == "medium"
    assert "case_id" in data
    assert "created_at" in data


async def test_create_case_full(client, analyst_headers):
    payload = {
        "title": "Brute Force Attempt",
        "description": "Multiple failed SSH logins.",
        "severity": "high",
        "assignee": "alice",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110",
        "tags": ["brute-force", "ssh"],
    }
    resp = await client.post("/cases", json=payload, headers=analyst_headers)
    assert resp.status_code == 201
    data = resp.json()
    assert data["severity"] == "high"
    assert data["assignee"] == "alice"
    assert "brute-force" in data["tags"]


async def test_create_case_invalid_severity(client, analyst_headers):
    resp = await client.post("/cases", json={"title": "Bad", "severity": "extreme"}, headers=analyst_headers)
    assert resp.status_code == 422


async def test_create_case_requires_auth(client):
    resp = await client.post("/cases", json={"title": "No Auth"})
    assert resp.status_code == 401


async def test_get_case(client, analyst_headers):
    cr = await client.post("/cases", json={"title": "Get Me"}, headers=analyst_headers)
    case_id = cr.json()["case_id"]
    resp = await client.get(f"/cases/{case_id}", headers=analyst_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["case_id"] == case_id
    assert "comments" in data
    assert "alerts" in data
    # System comment auto-created on creation
    assert any(c["is_system"] for c in data["comments"])


async def test_get_case_not_found(client, analyst_headers):
    resp = await client.get("/cases/nonexistent-id", headers=analyst_headers)
    assert resp.status_code == 404


async def test_patch_case_status(client, analyst_headers):
    cr = await client.post("/cases", json={"title": "Patch Me"}, headers=analyst_headers)
    case_id = cr.json()["case_id"]
    resp = await client.patch(f"/cases/{case_id}", json={"status": "investigating"}, headers=analyst_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "investigating"


async def test_close_case_requires_resolution(client, analyst_headers):
    cr = await client.post("/cases", json={"title": "Close No Res"}, headers=analyst_headers)
    case_id = cr.json()["case_id"]
    resp = await client.patch(f"/cases/{case_id}", json={"status": "resolved"}, headers=analyst_headers)
    assert resp.status_code == 422


async def test_close_case_with_resolution(client, analyst_headers):
    cr = await client.post("/cases", json={"title": "Close With Res"}, headers=analyst_headers)
    case_id = cr.json()["case_id"]
    resp = await client.patch(
        f"/cases/{case_id}",
        json={"status": "resolved", "resolution": "true_positive"},
        headers=analyst_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "resolved"
    assert data["resolution"] == "true_positive"
    assert data["closed_at"] is not None


async def test_add_comment(client, analyst_headers):
    cr = await client.post("/cases", json={"title": "Comment Test"}, headers=analyst_headers)
    case_id = cr.json()["case_id"]
    resp = await client.post(
        f"/cases/{case_id}/comments",
        json={"body": "Investigating the alert now."},
        headers=analyst_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["body"] == "Investigating the alert now."
    assert data["is_system"] is False


async def test_edit_comment(client, analyst_headers):
    cr = await client.post("/cases", json={"title": "Edit Comment"}, headers=analyst_headers)
    case_id = cr.json()["case_id"]
    add = await client.post(
        f"/cases/{case_id}/comments", json={"body": "Original"}, headers=analyst_headers
    )
    cid = add.json()["comment_id"]
    resp = await client.put(
        f"/cases/{case_id}/comments/{cid}", json={"body": "Edited"}, headers=analyst_headers
    )
    assert resp.status_code == 200
    assert resp.json()["body"] == "Edited"
    assert resp.json()["edited_at"] is not None


async def test_delete_comment(client, analyst_headers):
    cr = await client.post("/cases", json={"title": "Del Comment"}, headers=analyst_headers)
    case_id = cr.json()["case_id"]
    add = await client.post(
        f"/cases/{case_id}/comments", json={"body": "To delete"}, headers=analyst_headers
    )
    cid = add.json()["comment_id"]
    resp = await client.delete(f"/cases/{case_id}/comments/{cid}", headers=analyst_headers)
    assert resp.status_code == 204


async def test_link_and_unlink_alert(client, analyst_headers):
    cr = await client.post("/cases", json={"title": "Alert Link"}, headers=analyst_headers)
    case_id = cr.json()["case_id"]
    link_resp = await client.post(
        f"/cases/{case_id}/alerts",
        json={"alert_ids": ["fake-alert-001"]},
        headers=analyst_headers,
    )
    assert link_resp.status_code == 200
    assert "fake-alert-001" in link_resp.json()["linked"]

    unlink_resp = await client.delete(
        f"/cases/{case_id}/alerts/fake-alert-001", headers=analyst_headers
    )
    assert unlink_resp.status_code == 204


async def test_delete_case_requires_admin(client, analyst_headers):
    cr = await client.post("/cases", json={"title": "Delete Me"}, headers=analyst_headers)
    case_id = cr.json()["case_id"]
    resp = await client.delete(f"/cases/{case_id}", headers=analyst_headers)
    assert resp.status_code == 403


async def test_delete_case_admin(client, analyst_headers, admin_headers):
    cr = await client.post("/cases", json={"title": "Admin Delete"}, headers=analyst_headers)
    case_id = cr.json()["case_id"]
    resp = await client.delete(f"/cases/{case_id}", headers=admin_headers)
    assert resp.status_code == 204
    get_resp = await client.get(f"/cases/{case_id}", headers=analyst_headers)
    assert get_resp.status_code == 404


async def test_case_facets(client, analyst_headers):
    await client.post("/cases", json={"title": "Facet Case", "severity": "high"}, headers=analyst_headers)
    resp = await client.get("/cases/facets", headers=analyst_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert "severity" in data


# ── Log Sources ─────────────────────────────────────────────────────────────────

async def test_list_sources_empty(client, analyst_headers):
    resp = await client.get("/sources", headers=analyst_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "sources" in data
    assert "summary" in data
    assert "total" in data["summary"]


async def test_list_sources_requires_auth(client):
    resp = await client.get("/sources")
    assert resp.status_code == 401

"""Tests for Custom Dashboard (v1.2)."""
import uuid


# ── API ────────────────────────────────────────────────────────────────────────

async def test_get_dashboard_default(client, analyst_headers):
    r = await client.get("/dashboard", headers=analyst_headers)
    assert r.status_code == 200
    d = r.json()
    assert "widgets" in d
    assert isinstance(d["widgets"], list)
    assert len(d["widgets"]) > 0


async def test_get_dashboard_requires_auth(client):
    r = await client.get("/dashboard")
    assert r.status_code == 401


async def test_save_and_get_dashboard(client, analyst_headers):
    widgets = [
        {
            "widget_id": str(uuid.uuid4()),
            "type": "event_volume",
            "title": "My Events",
            "grid_position": {"row": 0, "col": 0, "width": 2, "height": 1},
            "config": {"time_range": "24h", "buckets": 24},
        }
    ]
    r = await client.put(
        "/dashboard",
        json={"title": "My Custom Dashboard", "widgets": widgets},
        headers=analyst_headers,
    )
    assert r.status_code == 200
    saved = r.json()
    assert saved["title"] == "My Custom Dashboard"
    assert len(saved["widgets"]) == 1
    assert saved["widgets"][0]["type"] == "event_volume"


async def test_save_dashboard_too_many_widgets(client, analyst_headers):
    widgets = [
        {
            "widget_id": str(uuid.uuid4()),
            "type": "top_ips",
            "title": f"Widget {i}",
            "grid_position": {"row": i, "col": 0, "width": 1, "height": 1},
            "config": {},
        }
        for i in range(21)
    ]
    r = await client.put("/dashboard", json={"title": "Too Many", "widgets": widgets}, headers=analyst_headers)
    assert r.status_code == 400


async def test_reset_dashboard(client, analyst_headers):
    await client.put(
        "/dashboard",
        json={"title": "To Reset", "widgets": []},
        headers=analyst_headers,
    )
    r = await client.delete("/dashboard", headers=analyst_headers)
    assert r.status_code == 204
    # After reset, should return default
    r2 = await client.get("/dashboard", headers=analyst_headers)
    assert r2.status_code == 200
    assert len(r2.json()["widgets"]) > 0


async def test_export_html(client, analyst_headers):
    r = await client.post("/dashboard/export/html", headers=analyst_headers)
    assert r.status_code == 200
    assert "text/html" in r.headers.get("content-type", "")
    assert "dashboard" in r.headers.get("content-disposition", "").lower()
    body = r.text
    assert "<html" in body
    assert "__DASHBOARD_DATA__" in body


async def test_export_html_requires_auth(client):
    r = await client.post("/dashboard/export/html")
    assert r.status_code == 401


# ── Store unit tests ───────────────────────────────────────────────────────────

def test_get_default_dashboard():
    from app.dashboard import store as ds
    result = ds.get_dashboard("user-who-has-no-saved-dashboard")
    assert result["widgets"]
    assert result["dashboard_id"] is None


def test_upsert_and_get_dashboard():
    from app.dashboard import store as ds
    owner = f"testuser-{uuid.uuid4().hex[:6]}"
    widgets = [
        {"widget_id": "w1", "type": "top_ips", "title": "IPs", "grid_position": {}, "config": {}}
    ]
    ds.upsert_dashboard(owner, "My Dash", widgets)
    result = ds.get_dashboard(owner)
    assert result["title"] == "My Dash"
    assert result["widgets"][0]["type"] == "top_ips"
    assert result["dashboard_id"] is not None


def test_upsert_replaces_existing():
    from app.dashboard import store as ds
    owner = f"replace-{uuid.uuid4().hex[:6]}"
    ds.upsert_dashboard(owner, "First", [{"widget_id": "a", "type": "top_ips", "title": "A", "grid_position": {}, "config": {}}])
    ds.upsert_dashboard(owner, "Second", [{"widget_id": "b", "type": "case_status", "title": "B", "grid_position": {}, "config": {}}])
    result = ds.get_dashboard(owner)
    assert result["title"] == "Second"
    assert result["widgets"][0]["type"] == "case_status"
    assert len(result["widgets"]) == 1


def test_delete_dashboard():
    from app.dashboard import store as ds
    owner = f"del-{uuid.uuid4().hex[:6]}"
    ds.upsert_dashboard(owner, "To Delete", [])
    assert ds.delete_dashboard(owner) is True
    result = ds.get_dashboard(owner)
    assert result["dashboard_id"] is None


def test_delete_nonexistent_dashboard():
    from app.dashboard import store as ds
    assert ds.delete_dashboard(f"ghost-{uuid.uuid4().hex}") is False

"""DuckDB CRUD for per-user dashboard layouts."""
import json
import uuid
from datetime import datetime
from typing import Optional

from app.storage.duckdb_store import _get_conn, _lock  # noqa: PLC2701

_DEFAULT_WIDGETS = [
    {"widget_id": "default-1", "type": "event_volume",  "title": "Event Volume (24h)",  "grid_position": {"row": 0, "col": 0, "width": 2, "height": 1}, "config": {"time_range": "24h", "buckets": 48}},
    {"widget_id": "default-2", "type": "alert_severity", "title": "Alert Severity",      "grid_position": {"row": 0, "col": 2, "width": 1, "height": 1}, "config": {"time_range": "7d"}},
    {"widget_id": "default-3", "type": "top_ips",        "title": "Top Source IPs",      "grid_position": {"row": 1, "col": 0, "width": 1, "height": 1}, "config": {"limit": 10, "time_range": "24h"}},
    {"widget_id": "default-4", "type": "top_sources",    "title": "Top Log Sources",     "grid_position": {"row": 1, "col": 1, "width": 1, "height": 1}, "config": {"time_range": "24h"}},
    {"widget_id": "default-5", "type": "recent_alerts",  "title": "Recent Alerts",       "grid_position": {"row": 1, "col": 2, "width": 1, "height": 1}, "config": {"limit": 5}},
    {"widget_id": "default-6", "type": "case_status",    "title": "Open Cases",          "grid_position": {"row": 2, "col": 0, "width": 1, "height": 1}, "config": {}},
]


def get_dashboard(owner: str) -> dict:
    with _lock:
        row = _get_conn().execute(
            "SELECT dashboard_id, owner, title, widgets, created_at, updated_at "
            "FROM dashboards WHERE owner = ?",
            [owner],
        ).fetchone()
    if not row:
        return {
            "dashboard_id": None,
            "owner": owner,
            "title": "Dashboard",
            "widgets": _DEFAULT_WIDGETS,
        }
    did, own, title, widgets_raw, created_at, updated_at = row
    widgets = json.loads(widgets_raw) if isinstance(widgets_raw, str) else widgets_raw
    return {
        "dashboard_id": did,
        "owner": own,
        "title": title,
        "widgets": widgets,
        "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else created_at,
        "updated_at": updated_at.isoformat() if hasattr(updated_at, "isoformat") else updated_at,
    }


def upsert_dashboard(owner: str, title: str, widgets: list) -> dict:
    """Create or replace the user's dashboard. Uses DELETE+INSERT to avoid DuckDB UPDATE bug."""
    now = datetime.utcnow()
    widgets_json = json.dumps(widgets)
    with _lock:
        existing = _get_conn().execute(
            "SELECT dashboard_id, created_at FROM dashboards WHERE owner = ?", [owner]
        ).fetchone()
        if existing:
            dashboard_id, created_at = existing[0], existing[1]
            _get_conn().execute("DELETE FROM dashboards WHERE dashboard_id = ?", [dashboard_id])
        else:
            dashboard_id = str(uuid.uuid4())
            created_at = now
        _get_conn().execute(
            "INSERT INTO dashboards (dashboard_id, owner, title, widgets, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?)",
            [dashboard_id, owner, title, widgets_json, created_at, now],
        )
    return get_dashboard(owner)


def delete_dashboard(owner: str) -> bool:
    with _lock:
        row = _get_conn().execute(
            "SELECT dashboard_id FROM dashboards WHERE owner = ?", [owner]
        ).fetchone()
        if not row:
            return False
        _get_conn().execute("DELETE FROM dashboards WHERE dashboard_id = ?", [row[0]])
    return True

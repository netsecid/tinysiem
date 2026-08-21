"""API endpoints for /dashboard."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.auth import AuthUser, require_analyst
from app.audit import store as audit
from app.dashboard import fidelity as fidelity_telemetry
from app.dashboard import store as dstore
from app.rules import engine as rule_engine
from app.storage import duckdb_store

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

_MAX_WIDGETS = 20


class Widget(BaseModel):
    widget_id: str
    type: str
    title: str = ""
    grid_position: dict = Field(default_factory=dict)
    config: dict = Field(default_factory=dict)


class SaveDashboardRequest(BaseModel):
    title: str = Field("Dashboard", max_length=100)
    widgets: list[Widget] = Field(default_factory=list)


@router.get("")
def get_dashboard(actor: AuthUser = Depends(require_analyst)):
    return dstore.get_dashboard(actor.username)


@router.put("")
def save_dashboard(req: SaveDashboardRequest, actor: AuthUser = Depends(require_analyst)):
    if len(req.widgets) > _MAX_WIDGETS:
        raise HTTPException(status_code=400, detail=f"Maximum {_MAX_WIDGETS} widgets allowed")
    widgets = [w.model_dump() for w in req.widgets]
    result = dstore.upsert_dashboard(actor.username, req.title, widgets)
    audit.log_event(
        "dashboard.save", "saved", actor.username,
        detail={"owner": actor.username, "widget_count": len(widgets)},
    )
    return result


@router.delete("", status_code=204)
def reset_dashboard(actor: AuthUser = Depends(require_analyst)):
    dstore.delete_dashboard(actor.username)
    audit.log_event(
        "dashboard.reset", "reset", actor.username,
        detail={"owner": actor.username},
    )


@router.post("/export/html")
def export_html(actor: AuthUser = Depends(require_analyst)):
    from app.dashboard.renderer import build_html_export
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    html = build_html_export(actor.username)
    audit.log_event(
        "dashboard.export", "html_export", actor.username,
        detail={"owner": actor.username},
    )
    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": f'attachment; filename="dashboard-{ts}.html"'},
    )


_ALLOWED_FIDELITY_WINDOWS = (60, 3600, 86400)


@router.get("/fidelity")
def get_fidelity(
    window: int = 60,
    _: AuthUser = Depends(require_analyst),
):
    """Executive "SOC pipeline" snapshot — sources with live EPS, detection
    engine stats, and case outcomes with a headline Fidelity %.

    ``window`` selects the rolling window for volume metrics: 60s, 1h, or 24h.
    For 60s the EPS/alerts counters are in-process (zero-I/O on the ingest
    path); for 1h/24h we fall back to a read-only SELECT over the events
    table because the in-memory deque only holds the last ~60s of timestamps.
    Outcomes are always all-time (cumulative) — ``fidelity_pct`` is a
    detection-quality KPI, not a throughput metric, so it is intentionally
    NOT windowed.
    """
    if window not in _ALLOWED_FIDELITY_WINDOWS:
        raise HTTPException(
            status_code=422,
            detail=f"window must be one of {_ALLOWED_FIDELITY_WINDOWS}",
        )
    snap = fidelity_telemetry.snapshot(window_seconds=window)
    activity = duckdb_store.query_source_activity()
    activity_by_source = {a["source"]: a["status"] for a in activity}
    # Merge telemetry (events/rate) with persistent source-status (status is
    # owned by the storage layer; events/rate is owned by telemetry).
    seen = set()
    sources_out = []
    for s in snap["sources"]:
        name = s["name"]
        seen.add(name)
        sources_out.append({
            "name": name,
            "events": s["events"],
            "rate": s["rate"],
            "status": activity_by_source.get(name, "silent"),
            "parse_fail_count": s["parse_fail_count"],
        })
    # Sources that exist in the DB but produced no events in the chosen window
    # — still show them, with rate=0, so the UI doesn't drop them silently.
    for name, status in activity_by_source.items():
        if name in seen:
            continue
        sources_out.append({
            "name": name,
            "events": 0,
            "rate": 0.0,
            "status": status,
            "parse_fail_count": 0,
        })
    sources_out.sort(key=lambda s: s["name"])

    resolved_counts = {"true_positive": 0, "false_positive": 0, "benign": 0, "undetermined": 0}
    cases_open = 0
    cases_investigating = 0
    conn = duckdb_store._get_conn()  # noqa: PLC2701 — intentional internal access
    with duckdb_store._lock:
        res_rows = conn.execute(
            "SELECT resolution, COUNT(*) FROM cases WHERE status='resolved' GROUP BY resolution"
        ).fetchall()
        for r in res_rows:
            if r[0] in resolved_counts:
                resolved_counts[r[0]] = r[1]
        cases_open = conn.execute(
            "SELECT COUNT(*) FROM cases WHERE status='open'"
        ).fetchone()[0]
        cases_investigating = conn.execute(
            "SELECT COUNT(*) FROM cases WHERE status='investigating'"
        ).fetchone()[0]

    tp = resolved_counts["true_positive"]
    fp = resolved_counts["false_positive"]
    bn = resolved_counts["benign"]
    total_resolved = tp + fp + bn + resolved_counts["undetermined"]
    denom = tp + fp + bn
    if denom <= 0:
        fidelity_pct = None
    else:
        fidelity_pct = round(100.0 * tp / denom, 2)

    return {
        "window_seconds": window,
        "window_label": snap["window_label"],
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "totals": snap["totals"],
        "sources": sources_out,
        "engine": {
            "rules_loaded": rule_engine.loaded_rules_count(),
        },
        "outcomes": {
            "cases_open": cases_open,
            "cases_investigating": cases_investigating,
            "resolved": resolved_counts,
            "total_resolved": total_resolved,
            "fidelity_pct": fidelity_pct,
            "scope": "all_time",
        },
    }

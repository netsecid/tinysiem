import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.auth import AuthUser, require_analyst
from app.config import settings
from app.cases import store as case_store
from app.storage.csv_export import rows_to_csv

router = APIRouter(prefix="/alerts", tags=["alerts"])


def _parse_dt(ts: Optional[str]) -> datetime:
    if not ts:
        return datetime.min
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
    except (ValueError, AttributeError):
        return datetime.min


def _read_all_alerts() -> list[dict]:
    from app.storage.duckdb_store import get_triage_map
    path = Path(settings.tinysiem_alerts_path)
    if not path.exists():
        return []
    alerts = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    triage = get_triage_map()
    for a in alerts:
        aid = a.get("alert_id", "")
        t = triage.get(aid, {})
        a["status"] = t.get("status", "open")
        a["notes"] = t.get("notes", "")
        a["assigned_to"] = t.get("assigned_to", "")
        a["triage_updated_at"] = t.get("updated_at")
        a["triage_updated_by"] = t.get("updated_by", "")
    return alerts


def _apply_filters(
    alerts: list[dict],
    severity: Optional[str],
    rule_name: Optional[str],
    source_ip: Optional[str],
    status: Optional[str],
    q: Optional[str],
    start: Optional[datetime],
    end: Optional[datetime],
) -> list[dict]:
    if severity:
        alerts = [a for a in alerts if (a.get("severity") or "").lower() == severity.lower()]
    if rule_name:
        alerts = [a for a in alerts if rule_name.lower() in (a.get("rule_name") or "").lower()]
    if source_ip:
        alerts = [a for a in alerts if source_ip in (a.get("source_ip") or "")]
    if status:
        alerts = [a for a in alerts if (a.get("status") or "open").lower() == status.lower()]
    if q:
        ql = q.lower()
        alerts = [a for a in alerts if ql in json.dumps(a).lower()]
    if start:
        s = start.replace(tzinfo=None) if start.tzinfo else start
        alerts = [a for a in alerts if _parse_dt(a.get("triggered_at")) >= s]
    if end:
        e = end.replace(tzinfo=None) if end.tzinfo else end
        alerts = [a for a in alerts if _parse_dt(a.get("triggered_at")) <= e]
    return alerts


_VALID_STATUSES = {"open", "investigating", "resolved"}

_CSV_EXPORT_CAP = 10_000
_ALERT_CSV_COLUMNS = [
    "alert_id", "triggered_at", "rule_name", "severity", "source_ip",
    "mitre_tactic", "mitre_technique", "status", "summary",
]


class TriagePatch(BaseModel):
    status: Optional[str] = None
    notes: Optional[str] = None
    assigned_to: Optional[str] = None


@router.get("/triage-summary")
def triage_summary(_: AuthUser = Depends(require_analyst)):
    alerts = _read_all_alerts()
    counts = Counter(a.get("status", "open") for a in alerts)
    return {
        "open": counts.get("open", 0),
        "investigating": counts.get("investigating", 0),
        "resolved": counts.get("resolved", 0),
    }


@router.get("")
def list_alerts(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = None,
    rule_name: Optional[str] = None,
    source_ip: Optional[str] = None,
    status: Optional[str] = None,
    q: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    format: Optional[str] = None,
    _: AuthUser = Depends(require_analyst),
):
    alerts = _read_all_alerts()
    alerts = _apply_filters(alerts, severity, rule_name, source_ip, status, q, start, end)
    alerts.sort(key=lambda a: a.get("triggered_at", ""), reverse=True)
    if format == "csv":
        csv_text = rows_to_csv(alerts[:_CSV_EXPORT_CAP], _ALERT_CSV_COLUMNS)
        return StreamingResponse(
            iter([csv_text]),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="alerts.csv"'},
        )
    total = len(alerts)
    return {"total": total, "alerts": alerts[offset: offset + limit]}


@router.get("/facets")
def alert_facets(_: AuthUser = Depends(require_analyst)):
    alerts = _read_all_alerts()
    sev_counts = Counter(a.get("severity") or "unknown" for a in alerts)
    rule_counts = Counter(a.get("rule_name") or "unknown" for a in alerts)
    status_counts = Counter(a.get("status", "open") for a in alerts)
    sev_order = ["critical", "high", "medium", "low", "unknown"]
    severity_facets = [
        {"value": s, "count": sev_counts[s]}
        for s in sev_order if s in sev_counts
    ]
    rule_facets = [
        {"value": k, "count": v}
        for k, v in rule_counts.most_common(20)
    ]
    return {
        "severity": severity_facets,
        "rule_name": rule_facets,
        "status": [{"value": k, "count": v} for k, v in status_counts.most_common()],
    }


@router.get("/{alert_id}")
def get_alert(alert_id: str, _: AuthUser = Depends(require_analyst)):
    alerts = _read_all_alerts()
    for a in alerts:
        if a.get("alert_id") == alert_id:
            return a
    raise HTTPException(status_code=404, detail="Alert not found")


@router.get("/{alert_id}/cases")
def get_alert_cases(alert_id: str, _: AuthUser = Depends(require_analyst)):
    cases = case_store.get_cases_for_alert(alert_id)
    return {"cases": cases}


@router.patch("/{alert_id}")
def patch_alert(
    alert_id: str,
    body: TriagePatch,
    current_user: AuthUser = Depends(require_analyst),
):
    from app.storage.duckdb_store import upsert_triage
    if body.status is not None and body.status not in _VALID_STATUSES:
        raise HTTPException(status_code=422, detail=f"status must be one of {sorted(_VALID_STATUSES)}")
    alerts = _read_all_alerts()
    existing = next((a for a in alerts if a.get("alert_id") == alert_id), None)
    if not existing:
        raise HTTPException(status_code=404, detail="Alert not found")
    new_status = body.status if body.status is not None else existing.get("status", "open")
    new_notes = body.notes if body.notes is not None else existing.get("notes", "")
    new_assigned = body.assigned_to if body.assigned_to is not None else existing.get("assigned_to", "")
    upsert_triage(alert_id, new_status, new_notes, new_assigned, current_user.username)
    existing["status"] = new_status
    existing["notes"] = new_notes
    existing["assigned_to"] = new_assigned
    from app.audit import store as audit
    audit.log_event(
        "alert.triage", "triage", "success",
        actor=current_user.username, actor_role=current_user.role,
        resource_type="alert", resource_id=alert_id,
        detail={
            "alert_id": alert_id,
            "new_status": new_status,
            "assigned_to": new_assigned,
            "notes_updated": body.notes is not None,
        },
    )
    return existing

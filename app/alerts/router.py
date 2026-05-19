import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Query

from app.auth import verify_api_key
from app.config import settings

router = APIRouter(prefix="/alerts", tags=["alerts"])


def _parse_dt(ts: Optional[str]) -> datetime:
    if not ts:
        return datetime.min
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
    except (ValueError, AttributeError):
        return datetime.min


def _read_all_alerts() -> list[dict]:
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
    return alerts


def _apply_filters(
    alerts: list[dict],
    severity: Optional[str],
    rule_name: Optional[str],
    source_ip: Optional[str],
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


@router.get("")
def list_alerts(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = None,
    rule_name: Optional[str] = None,
    source_ip: Optional[str] = None,
    q: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    _: str = Depends(verify_api_key),
):
    alerts = _read_all_alerts()
    alerts = _apply_filters(alerts, severity, rule_name, source_ip, q, start, end)
    alerts.sort(key=lambda a: a.get("triggered_at", ""), reverse=True)
    total = len(alerts)
    return {"total": total, "alerts": alerts[offset: offset + limit]}


@router.get("/facets")
def alert_facets(_: str = Depends(verify_api_key)):
    alerts = _read_all_alerts()
    sev_counts = Counter(a.get("severity") or "unknown" for a in alerts)
    rule_counts = Counter(a.get("rule_name") or "unknown" for a in alerts)
    sev_order = ["critical", "high", "medium", "low", "unknown"]
    severity_facets = [
        {"value": s, "count": sev_counts[s]}
        for s in sev_order if s in sev_counts
    ]
    rule_facets = [
        {"value": k, "count": v}
        for k, v in rule_counts.most_common(20)
    ]
    return {"severity": severity_facets, "rule_name": rule_facets}

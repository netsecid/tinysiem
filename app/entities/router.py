from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends

from app.auth import AuthUser, require_analyst
from app.storage import duckdb_store

router = APIRouter(prefix="/entities", tags=["entities"])


@router.get("/ip/{value}")
def get_ip_entity(value: str, _: AuthUser = Depends(require_analyst)):
    from app.alerts.router import read_all_alerts
    from app.cases import store as case_store

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=7)
    summary = duckdb_store.get_ip_summary(value, start, end)

    all_alerts = read_all_alerts()
    related_alerts = [a for a in all_alerts if a.get("source_ip") == value]
    related_alerts.sort(key=lambda a: a.get("triggered_at", ""), reverse=True)

    case_ids_seen: set = set()
    related_cases = []
    for alert in related_alerts[:50]:
        for c in case_store.get_cases_for_alert(alert.get("alert_id", "")):
            if c["case_id"] not in case_ids_seen:
                case_ids_seen.add(c["case_id"])
                related_cases.append(c)

    return {
        "ip": value,
        **summary,
        "related_alerts": related_alerts[:50],
        "related_cases": related_cases,
    }

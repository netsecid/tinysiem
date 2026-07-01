from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel

from app.audit import store as audit
from app.auth import AuthUser, require_admin, require_analyst

router = APIRouter(prefix="/baselines", tags=["baselines"])


@router.get("")
def list_baselines(
    source: Optional[str] = None,
    hour_of_day: Optional[int] = None,
    day_of_week: Optional[int] = None,
    _: AuthUser = Depends(require_analyst),
):
    from app.baselines import store as baseline_store
    return {"baselines": baseline_store.list_baselines(source=source, hour_of_day=hour_of_day, day_of_week=day_of_week)}


@router.get("/violations")
def list_violations(
    source: Optional[str] = None,
    severity: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    limit: int = 100,
    offset: int = 0,
    _: AuthUser = Depends(require_analyst),
):
    from app.baselines import store as baseline_store
    return baseline_store.query_violations(
        source=source, severity=severity, acknowledged=acknowledged,
        start=start, end=end, limit=limit, offset=offset,
    )


class AcknowledgeRequest(BaseModel):
    acknowledged: bool


@router.patch("/violations/{violation_id}")
def acknowledge_violation(
    violation_id: str,
    req: AcknowledgeRequest,
    actor: AuthUser = Depends(require_analyst),
):
    from app.baselines import store as baseline_store
    if not baseline_store.acknowledge_violation(violation_id):
        raise HTTPException(status_code=404, detail="Violation not found")
    audit.log_event(
        "baseline.violation", "acknowledged", "success",
        actor=actor.username, actor_role=actor.role,
        resource_type="baseline_violation", resource_id=violation_id,
        detail={"acknowledged": req.acknowledged},
    )
    return {"status": "updated"}


@router.delete("/{source}", status_code=204)
def reset_baselines(source: str, actor: AuthUser = Depends(require_admin)):
    from app.baselines import store as baseline_store
    count = baseline_store.delete_baselines_for_source(source)
    audit.log_event(
        "baseline.reset", "reset", "success",
        actor=actor.username, actor_role=actor.role,
        resource_type="baseline", resource_id=source,
        detail={"deleted_count": count, "source": source},
    )
    return Response(status_code=204)

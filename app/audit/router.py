from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query

from app.auth import AuthUser, require_superadmin
from app.storage import duckdb_store

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
def list_audit(
    event_type: Optional[str] = None,
    actor: Optional[str] = None,
    resource_type: Optional[str] = None,
    action: Optional[str] = None,
    status: Optional[str] = None,
    q: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _: AuthUser = Depends(require_superadmin),
):
    return duckdb_store.query_audit(
        event_type=event_type,
        actor=actor,
        resource_type=resource_type,
        action=action,
        status=status,
        q=q,
        start=start,
        end=end,
        limit=limit,
        offset=offset,
    )


@router.get("/facets")
def audit_facets(
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    _: AuthUser = Depends(require_superadmin),
):
    return duckdb_store.get_audit_facets(start=start, end=end)

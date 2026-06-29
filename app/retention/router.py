from fastapi import APIRouter, Depends

from app.audit import store as audit
from app.auth import AuthUser, require_admin
from app.retention.archiver import archive_old_events, get_retention_status

router = APIRouter(prefix="/retention", tags=["retention"])


@router.get("/status")
def retention_status(_: AuthUser = Depends(require_admin)):
    return get_retention_status()


@router.post("/run")
def run_retention(actor: AuthUser = Depends(require_admin)):
    result = archive_old_events()
    audit.log_event(
        "system.retention", "run", "success",
        actor=actor.username, actor_role=actor.role,
        resource_type="system",
        detail={"archived": result.get("archived", 0), "files": result.get("files", [])},
    )
    return result

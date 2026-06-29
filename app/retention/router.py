from fastapi import APIRouter, Depends

from app.auth import AuthUser, require_admin
from app.retention.archiver import archive_old_events, get_retention_status

router = APIRouter(prefix="/retention", tags=["retention"])


@router.get("/status")
def retention_status(_: AuthUser = Depends(require_admin)):
    return get_retention_status()


@router.post("/run")
def run_retention(_: AuthUser = Depends(require_admin)):
    return archive_old_events()

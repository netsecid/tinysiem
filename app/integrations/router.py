"""API endpoints for /integrations."""
import asyncio
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.auth import AuthUser, require_admin, require_analyst
from app.audit import store as audit
from app.integrations import store as istore
from app.integrations.drivers import DRIVERS
from app.crypto import MasterKeyNotConfigured

router = APIRouter(prefix="/integrations", tags=["integrations"])


def _require_master_key():
    from app.config import settings
    if not settings.tinysiem_master_key:
        raise HTTPException(
            status_code=503,
            detail="TINYSIEM_MASTER_KEY is not configured. Set it in your .env file to use integrations.",
        )


class CreateIntegrationRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    integration_type: str
    schedule_minutes: int = Field(15, ge=1, le=1440)
    config: dict = Field(default_factory=dict)
    credentials: dict = Field(default_factory=dict)


class UpdateIntegrationRequest(BaseModel):
    name: Optional[str] = None
    enabled: Optional[bool] = None
    schedule_minutes: Optional[int] = Field(None, ge=1, le=1440)
    config: Optional[dict] = None
    credentials: Optional[dict] = None


@router.get("/types")
def list_types(_: AuthUser = Depends(require_analyst)):
    return {
        "types": [
            {
                "integration_type": getattr(d, "integration_type", k),
                "display_name": getattr(d, "display_name", k),
                "credential_fields": getattr(d, "credential_fields", []),
                "config_fields": getattr(d, "config_fields", []),
            }
            for k, d in DRIVERS.items()
        ]
    }


@router.get("")
def list_integrations(_: AuthUser = Depends(require_analyst)):
    return {"integrations": istore.list_integrations()}


@router.post("", status_code=201)
def create_integration(
    req: CreateIntegrationRequest,
    actor: AuthUser = Depends(require_admin),
):
    _require_master_key()
    if req.integration_type not in DRIVERS:
        raise HTTPException(status_code=400, detail=f"Unknown integration type: {req.integration_type}")
    try:
        integ = istore.create_integration(
            name=req.name,
            integration_type=req.integration_type,
            config=req.config,
            credentials=req.credentials,
            schedule_minutes=req.schedule_minutes,
            created_by=actor.username,
        )
    except MasterKeyNotConfigured as e:
        raise HTTPException(status_code=503, detail=str(e))
    audit.log_event(
        "integration.create", "created", actor.username,
        detail={"integration_id": integ["integration_id"], "name": req.name, "type": req.integration_type},
    )
    return integ


@router.get("/{integration_id}")
def get_integration(
    integration_id: str,
    _: AuthUser = Depends(require_analyst),
):
    _require_master_key()
    try:
        integ = istore.get_integration(integration_id, masked=True)
    except Exception:
        raise HTTPException(status_code=503, detail="Credential decryption failed")
    if not integ:
        raise HTTPException(status_code=404, detail="Integration not found")
    return integ


@router.patch("/{integration_id}")
def update_integration(
    integration_id: str,
    req: UpdateIntegrationRequest,
    actor: AuthUser = Depends(require_admin),
):
    _require_master_key()
    if not istore.get_integration(integration_id, masked=True):
        raise HTTPException(status_code=404, detail="Integration not found")
    changed_fields = [k for k, v in req.model_dump(exclude_none=True).items() if k != "credentials"]
    try:
        updated = istore.update_integration(
            integration_id,
            name=req.name,
            enabled=req.enabled,
            config=req.config,
            credentials=req.credentials,
            schedule_minutes=req.schedule_minutes,
        )
    except MasterKeyNotConfigured as e:
        raise HTTPException(status_code=503, detail=str(e))
    audit.log_event(
        "integration.update", "updated", actor.username,
        detail={"integration_id": integration_id, "changed": changed_fields},
    )
    return updated


@router.delete("/{integration_id}", status_code=204)
def delete_integration(integration_id: str, actor: AuthUser = Depends(require_admin)):
    deleted = istore.delete_integration(integration_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Integration not found")
    audit.log_event(
        "integration.delete", "deleted", actor.username,
        detail={"integration_id": integration_id},
    )


@router.post("/{integration_id}/run", status_code=202)
async def trigger_run(integration_id: str, actor: AuthUser = Depends(require_admin)):
    _require_master_key()
    integ = istore.get_integration(integration_id, masked=True)
    if not integ:
        raise HTTPException(status_code=404, detail="Integration not found")
    from app.integrations import runner

    async def _bg():
        await runner.run_integration(integration_id, triggered_by=actor.username)

    asyncio.create_task(_bg())
    return {"integration_id": integration_id, "status": "accepted"}


@router.get("/{integration_id}/runs")
def list_runs(
    integration_id: str,
    limit: int = 20,
    status: Optional[str] = None,
    _: AuthUser = Depends(require_analyst),
):
    integ = istore.get_integration(integration_id, masked=True)
    if not integ:
        raise HTTPException(status_code=404, detail="Integration not found")
    return {"runs": istore.list_runs(integration_id, limit=limit, status=status)}

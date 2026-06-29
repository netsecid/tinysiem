import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.audit import store as audit
from app.auth import AuthUser, require_admin
from app.notifications.sender import send_email, send_webhook

router = APIRouter(prefix="/notifications", tags=["notifications"])


class TestBody(BaseModel):
    channel: str = "all"  # email | webhook | all


@router.post("/test")
def test_notification(body: TestBody, actor: AuthUser = Depends(require_admin)):
    alert = {
        "alert_id": str(uuid.uuid4()),
        "rule_name": "test-notification",
        "severity": "high",
        "triggered_at": datetime.now(timezone.utc).isoformat(),
        "source_ip": "1.2.3.4",
        "summary": "This is a TinySIEM notification test.",
        "mitre_tactic": "Test",
        "mitre_technique": "T0000",
    }
    result: dict = {}
    if body.channel in ("email", "all"):
        try:
            send_email(alert)
            result["email"] = "sent"
        except Exception as e:
            result["email"] = f"error: {e}"
    if body.channel in ("webhook", "all"):
        try:
            send_webhook(alert)
            result["webhook"] = "sent"
        except Exception as e:
            result["webhook"] = f"error: {e}"
    audit.log_event(
        "system.notification", "test", "success",
        actor=actor.username, actor_role=actor.role,
        resource_type="system",
        detail={"channel": body.channel, "result": result},
    )
    return result


@router.get("/config")
def get_notification_config(_: AuthUser = Depends(require_admin)):
    from app.config import settings
    return {
        "email_enabled": bool(settings.tinysiem_smtp_host and settings.tinysiem_smtp_to),
        "webhook_enabled": bool(settings.tinysiem_webhook_url),
        "min_severity": settings.tinysiem_notify_min_sev,
        "smtp_host": settings.tinysiem_smtp_host,
        "smtp_port": settings.tinysiem_smtp_port,
        "smtp_from": settings.tinysiem_smtp_from,
        "smtp_to": settings.tinysiem_smtp_to,
        "smtp_tls": settings.tinysiem_smtp_tls,
    }

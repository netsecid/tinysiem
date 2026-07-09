import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from app.audit import security_feed

logger = logging.getLogger(__name__)

_MAX_STR = 5000


def _trunc(s: Optional[str], n: int = _MAX_STR) -> Optional[str]:
    if s is None:
        return None
    return s if len(s) <= n else s[:n] + f"…[+{len(s)-n}]"


def log_event(
    event_type: str,
    action: str,
    status: str = "success",
    actor: str = "system",
    actor_role: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    detail: Optional[dict] = None,
    ip_address: Optional[str] = None,
    duration_ms: Optional[int] = None,
    error_msg: Optional[str] = None,
) -> None:
    """Append one audit event. Never raises — write failure goes to stderr only."""
    try:
        from app.storage import duckdb_store
        duckdb_store.insert_audit_event({
            "id": str(uuid.uuid4()),
            "ts": datetime.now(timezone.utc),
            "event_type": event_type,
            "actor": actor,
            "actor_role": actor_role,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "action": action,
            "status": status,
            "detail": json.dumps(detail) if detail else None,
            "ip_address": ip_address,
            "duration_ms": duration_ms,
            "error_msg": _trunc(error_msg, 1000),
        })
    except Exception as exc:
        logger.error(f"Audit write failed (non-fatal): {exc}")

    security_feed.feed(event_type, status, actor, ip_address, detail)

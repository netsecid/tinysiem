import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from app.config import settings

logger = logging.getLogger(__name__)

try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:
    # Windows — no fcntl; file lock is best-effort
    _HAS_FCNTL = False


def _alerts_path() -> Path:
    path = Path(settings.tinysiem_alerts_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def write_alert(rule: dict, event: dict) -> None:
    alert = {
        "alert_id": str(uuid.uuid4()),
        "triggered_at": datetime.now(timezone.utc).isoformat(),
        "rule_name": rule.get("name"),
        "severity": rule.get("severity"),
        "mitre_tactic": rule.get("mitre_tactic"),
        "mitre_technique": rule.get("mitre_technique"),
        "event_id": event.get("id"),
        "source_ip": event.get("source_ip"),
        "summary": (
            f"Rule '{rule.get('name')}' triggered on event {event.get('id')}"
        ),
    }
    # Snapshot playbook if the rule has one — preserves guidance at alert-fire time
    if rule.get("playbook"):
        alert["playbook"] = rule["playbook"]

    path = _alerts_path()

    # Rotate if file exceeds configured max size
    max_bytes = settings.tinysiem_alert_max_mb * 1024 * 1024
    if path.exists() and path.stat().st_size >= max_bytes:
        rotated = path.with_suffix(f".{int(datetime.now().timestamp())}.log")
        path.rename(rotated)

    try:
        with open(path, "a") as fh:
            if _HAS_FCNTL:
                fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                fh.write(json.dumps(alert) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            finally:
                if _HAS_FCNTL:
                    fcntl.flock(fh, fcntl.LOCK_UN)
    except Exception as exc:
        logger.error(f"Failed to write alert: {exc}")
        return

    try:
        from app.notifications.sender import notify
        notify(alert)
    except Exception as exc:
        logger.error(f"Notification dispatch failed: {exc}")

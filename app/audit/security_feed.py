import json
import logging

logger = logging.getLogger(__name__)

# Maps (event_type, status) -> a synthetic status_code so the existing threshold/field_match
# engine (which only understands top-level event schema fields) can key off outcome.
_STATUS_BY_OUTCOME = {
    ("auth.login", "failure"): 401,
    ("auth.login", "success"): 200,
    ("auth.lockout", "failure"): 429,
}

_FEED_EVENT_TYPES = {
    "auth.login", "auth.lockout",
    "user.create", "user.update", "user.delete",
    "integration.create", "integration.update", "integration.delete",
}


def feed(event_type: str, status: str, actor: str, ip_address, detail) -> None:
    """Mirror a security-relevant audit event into the detection pipeline as source
    'tinysiem_internal', so built-in rules (e.g. brute-force) can alert on attacks
    against the SIEM itself. There is no call site that invokes audit.log_event from
    inside the tinysiem_internal ingest path, so this cannot recurse.
    """
    if event_type not in _FEED_EVENT_TYPES:
        return
    payload = {
        "event_type": event_type,
        "action": event_type.split(".", 1)[-1],
        "status": status,
        "source_ip": ip_address or "",
        "status_code": _STATUS_BY_OUTCOME.get((event_type, status), 200 if status == "success" else 400),
        "actor": actor,
        "detail": detail or {},
    }
    try:
        raw = json.dumps(payload)
        from app.ingest.pipeline import process_line
        process_line("tinysiem_internal", raw, strict=False)
    except Exception as exc:
        logger.warning(f"Security feed ingest failed (non-fatal): {exc}")

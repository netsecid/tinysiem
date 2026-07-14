import json
from datetime import datetime, timezone
from typing import Optional

_VALID_TARGETS = {"events", "alerts", "cases"}

_TARGET_FILTER_KEYS = {
    "events": {"source_ip", "status_code", "status_min", "status_max", "method", "uri", "q", "start", "end"},
    "alerts": {"severity", "rule_name", "source_ip", "q", "start", "end"},
    "cases": {"status", "severity", "assignee", "q", "start", "end"},
}


def _extraction_system_prompt() -> str:
    now = datetime.now(timezone.utc).isoformat()
    return (
        "You are a search query classifier for TinySIEM, a security information and event "
        "management tool. Given a natural-language question from a security analyst, decide "
        "which data source (if any) the question is asking about, and extract the relevant filters.\n\n"
        "Valid targets and their filters:\n"
        "- \"events\": source_ip, status_code, status_min, status_max, method, uri, q, start, end\n"
        "- \"alerts\": severity, rule_name, source_ip, q, start, end\n"
        "- \"cases\": status, severity, assignee, q, start, end\n\n"
        "Rules:\n"
        "- If the question is not asking to search/filter/find data (e.g. a greeting, a general "
        "knowledge question, a question about how TinySIEM works), set \"target\" to null and leave "
        "\"filters\" empty.\n"
        "- Only include filter keys that are relevant to the question — do not invent values.\n"
        "- severity must be one of: low, medium, high, critical\n"
        "- status (cases only) must be one of: open, investigating, resolved\n"
        f"- start/end must be ISO 8601 datetime strings. The current time is {now}. If the question "
        "implies recent activity without an explicit time bound, default to the last 24 hours.\n"
        "- Output ONLY a JSON object with this exact shape, no prose, no markdown:\n"
        "{\"target\": \"events\"|\"alerts\"|\"cases\"|null, \"filters\": {...}}"
    )


def extract_search_intent(question: str) -> dict:
    from app.ai.provider_factory import get_active_provider
    provider = get_active_provider()
    result = provider.chat(system=_extraction_system_prompt(), user=question, max_tokens=500)

    try:
        parsed = json.loads(result.text.strip())
    except (json.JSONDecodeError, AttributeError, TypeError):
        return {"target": None, "filters": {}}

    if not isinstance(parsed, dict):
        return {"target": None, "filters": {}}

    target = parsed.get("target")
    if target not in _VALID_TARGETS:
        return {"target": None, "filters": {}}

    raw_filters = parsed.get("filters")
    if not isinstance(raw_filters, dict):
        raw_filters = {}

    allowed_keys = _TARGET_FILTER_KEYS[target]
    filters = {
        k: v for k, v in raw_filters.items()
        if k in allowed_keys and v not in (None, "")
    }
    return {"target": target, "filters": filters}

import json
from collections import Counter
from datetime import datetime, timezone

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


def _parse_iso_datetime(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=None)
    except (ValueError, TypeError):
        return None


def _query_events(filters: dict) -> tuple:
    from app.storage import duckdb_store
    kwargs = dict(filters)
    for key in ("status_code", "status_min", "status_max"):
        if key in kwargs:
            try:
                kwargs[key] = int(kwargs[key])
            except (TypeError, ValueError):
                del kwargs[key]
    for key in ("start", "end"):
        if key in kwargs:
            kwargs[key] = _parse_iso_datetime(kwargs[key])
    result = duckdb_store.query_events(limit=50, **kwargs)
    status_counts = Counter(
        e.get("status_code") for e in result["events"] if e.get("status_code") is not None
    )
    summary = {"status_code_breakdown": dict(status_counts.most_common(5))}
    return result["total"], summary


def _query_alerts(filters: dict) -> tuple:
    from app.alerts.router import read_all_alerts, apply_alert_filters
    alerts = read_all_alerts()
    alerts = apply_alert_filters(
        alerts,
        severity=filters.get("severity"),
        rule_name=filters.get("rule_name"),
        source_ip=filters.get("source_ip"),
        status=None,
        q=filters.get("q"),
        start=_parse_iso_datetime(filters.get("start")),
        end=_parse_iso_datetime(filters.get("end")),
    )
    severity_counts = Counter(a.get("severity") for a in alerts if a.get("severity"))
    summary = {"severity_breakdown": dict(severity_counts.most_common(5))}
    return len(alerts), summary


def _query_cases(filters: dict) -> tuple:
    from app.cases import store as case_store
    kwargs = dict(filters)
    for key in ("start", "end"):
        if key in kwargs:
            kwargs[key] = _parse_iso_datetime(kwargs[key])
    result = case_store.query_cases(limit=50, **kwargs)
    status_counts = Counter(c.get("status") for c in result["cases"] if c.get("status"))
    summary = {"status_breakdown": dict(status_counts.most_common(5))}
    return result["total"], summary


_TARGET_PAGES = {
    "events": "/ui/events.html",
    "alerts": "/ui/alerts.html",
    "cases": "/ui/cases.html",
}


def _build_link(target: str, filters: dict) -> str:
    from urllib.parse import urlencode
    qs = urlencode(filters)
    base = _TARGET_PAGES[target]
    return f"{base}?{qs}" if qs else base


def _summary_system_prompt() -> str:
    return (
        "You are a security analyst assistant for TinySIEM. Given a question and the real "
        "results of a search against the SIEM's data, write a concise 2-4 sentence answer. "
        "Be specific: cite the actual counts and notable patterns from the results provided. "
        "Do not invent data beyond what's given. Plain text only — no markdown, no bullet points."
    )


def _general_system_prompt() -> str:
    return (
        "You are a helpful assistant embedded in TinySIEM, a security information and event "
        "management tool. Answer the question concisely and practically. Plain text only — "
        "no markdown, no bullet points."
    )


def run_search(question: str, actor: str) -> dict:
    from app.ai.claude import _log_ai_call
    from app.ai.provider_factory import get_active_provider

    provider = get_active_provider()
    intent = extract_search_intent(question)
    target = intent["target"]
    filters = intent["filters"]

    start_time = datetime.now(timezone.utc)
    if target is None:
        result = provider.chat(system=_general_system_prompt(), user=question, max_tokens=400)
        duration_ms = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
        _log_ai_call("home_search", actor, question, result.text, duration_ms, success=True, model=provider.model)
        return {"answer": result.text, "link": None, "link_label": None}

    # Dispatch through the module namespace (not a pre-bound dict of function objects)
    # so that tests patching app.ai.home_search._query_events/_alerts/_cases take
    # effect — a dict built at import time would keep pointing at the originals
    # after unittest.mock.patch swaps the module attribute.
    query_fn = globals()[f"_query_{target}"]
    count, summary = query_fn(filters)
    context = f"Question: {question}\n\nReal results: {count} {target} matched.\nSummary: {summary}"
    result = provider.chat(system=_summary_system_prompt(), user=context, max_tokens=400)
    duration_ms = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
    _log_ai_call("home_search", actor, question, result.text, duration_ms, success=True, model=provider.model)

    return {
        "answer": result.text,
        "link": _build_link(target, filters),
        "link_label": f"View {count} {target}",
    }

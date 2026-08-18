import json
from collections import Counter
from datetime import datetime, timezone

_VALID_TARGETS = {"events", "alerts", "cases"}

_TARGET_FILTER_KEYS = {
    "events": {"source", "source_ip", "status_code", "status_min", "status_max", "method", "uri", "q", "start", "end"},
    "alerts": {"severity", "rule_name", "source_ip", "q", "start", "end"},
    "cases": {"status", "severity", "assignee", "q", "start", "end"},
}

# Values that appear verbatim in real SIEM data — the extraction LLM must know these
# so natural phrasing maps to filters that actually match (a bare `q` full-text search
# often returns 0 for concepts like "brute force", which live in structured fields).
_SOURCE_VALUES = ("sshd", "ufw", "fail2ban", "syslog", "nginx", "tinysiem_internal")
_METHOD_HINTS = (
    'for sshd logs: "Failed password", "Accepted", "Invalid user", "Connection closed", '
    '"Break-in attempt"; for ufw/fail2ban: the protocol or action ("Ban", "Unban", "TCP", "UDP"); '
    "for HTTP logs: the HTTP verb (GET, POST, ...)"
)
_RULE_NAME_VALUES = ("ssh-bruteforce", "fail2ban-ban", "fail2ban-unban", "ufw-repeated-blocks")


def _extraction_system_prompt() -> str:
    now = datetime.now(timezone.utc).isoformat()
    return (
        "You are a search query classifier for TinySIEM, a security information and event "
        "management tool. Given a natural-language question from a security analyst, decide "
        "which data source (if any) the question is asking about, and extract the relevant filters.\n\n"
        "Valid targets and their filters:\n"
        "- \"events\": source, source_ip, status_code, status_min, status_max, method, uri, q, start, end\n"
        "- \"alerts\": severity, rule_name, source_ip, q, start, end\n"
        "- \"cases\": status, severity, assignee, q, start, end\n\n"
        f"SIEM vocabulary — use these exact values so filters match real data:\n"
        f"- events.source values: {', '.join(_SOURCE_VALUES)}\n"
        f"- events.method values: {_METHOD_HINTS}\n"
        f"- alerts.rule_name values: {', '.join(_RULE_NAME_VALUES)}\n"
        "- \"brute force\", \"attack\", \"attacking\", \"scanning\", \"probing\" usually mean sshd "
        "events with method \"Failed password\" (or alerts with rule_name \"ssh-bruteforce\")\n"
        "- \"q\" does a free-text search of the raw log line\n\n"
        "Rules:\n"
        "- If the question is not asking to search/filter/find data (e.g. a greeting, a general "
        "knowledge question, a question about how TinySIEM works), set \"target\" to null, \"filters\" "
        "empty, and \"group_by\" null.\n"
        "- Only include filter keys that are relevant to the question — do not invent values.\n"
        "- severity must be one of: low, medium, high, critical\n"
        "- status (cases only) must be one of: open, investigating, resolved\n"
        f"- start/end must be ISO 8601 datetime strings. The current time is {now}. If the question "
        "implies recent activity without an explicit time bound, default to the last 24 hours.\n"
        "- If the question asks for the top/most frequent N IP addresses (e.g. \"top 10 ip address "
        "attacking\", \"which source ip sent the most requests\"), set \"target\" to \"events\" and "
        "\"group_by\" to \"source_ip\"; otherwise \"group_by\" must be null.\n"
        "- Output ONLY a JSON object with this exact shape, no prose, no markdown:\n"
        "{\"target\": \"events\"|\"alerts\"|\"cases\"|null, \"filters\": {...}, \"group_by\": \"source_ip\"|null}"
    )


def extract_search_intent(question: str) -> dict:
    from app.ai.provider_factory import get_active_provider
    provider = get_active_provider()
    result = provider.chat(system=_extraction_system_prompt(), user=question, max_tokens=500)
    text = (result.text or "").strip()
    if not text:
        # A reasoning model can burn its whole token budget on `reasoning_content`
        # and return an empty `content` (finish_reason=length). Surface that loudly
        # instead of silently falling back to a generic answer — the caller maps
        # RuntimeError to a 503 the UI can explain.
        raise RuntimeError(
            "AI provider returned an empty response for intent extraction — check the model "
            "configured in Settings → AI Config (reasoning models may need a larger max_tokens)."
        )

    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, AttributeError, TypeError):
        return {"target": None, "filters": {}, "group_by": None}

    if not isinstance(parsed, dict):
        return {"target": None, "filters": {}, "group_by": None}

    target = parsed.get("target")
    if target not in _VALID_TARGETS:
        return {"target": None, "filters": {}, "group_by": None}

    raw_filters = parsed.get("filters")
    if not isinstance(raw_filters, dict):
        raw_filters = {}

    allowed_keys = _TARGET_FILTER_KEYS[target]
    filters = {
        k: v for k, v in raw_filters.items()
        if k in allowed_keys and v not in (None, "")
    }

    # group_by is only meaningful for events (source_ip facet). Anything else is
    # dropped so a hallucinated value can never reach the query layer.
    group_by = parsed.get("group_by") if target == "events" else None
    if group_by not in (None, "source_ip"):
        group_by = None
    return {"target": target, "filters": filters, "group_by": group_by}


def _parse_iso_datetime(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=None)
    except (ValueError, TypeError):
        return None


def _normalize_event_filters(filters: dict) -> dict:
    """Convert raw extracted filter values into the types query_events() expects."""
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
    return kwargs


def _query_events(filters: dict) -> tuple:
    from app.storage import duckdb_store
    kwargs = _normalize_event_filters(filters)
    result = duckdb_store.query_events(limit=50, **kwargs)
    status_counts = Counter(
        e.get("status_code") for e in result["events"] if e.get("status_code") is not None
    )
    summary = {"status_code_breakdown": dict(status_counts.most_common(5))}
    return result["total"], summary


def _top_source_ips(filters: dict, limit: int = 10) -> list[dict]:
    """Top-N source IPs matching the filters, with country enrichment."""
    from app.storage import duckdb_store
    kwargs = _normalize_event_filters(filters)
    return duckdb_store.top_source_ips(**kwargs, limit=limit)


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


def _summary_system_prompt(with_table: bool = False) -> str:
    prompt = (
        "You are a security analyst assistant for TinySIEM. Given a question and the real "
        "results of a search against the SIEM's data, write a concise 2-4 sentence answer. "
        "Be specific: cite the actual counts and notable patterns from the results provided. "
        "Do not invent data beyond what's given. Plain text only — no markdown, no bullet points."
    )
    if with_table:
        prompt += (
            " A table of the top source IPs (with countries and event counts) is displayed "
            "alongside your answer, so do NOT re-list the IPs. Instead interpret the pattern: "
            "same-subnet clustering, geographic concentration, unusual proportions, or which "
            "attacker deserves the most attention."
        )
    return prompt


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
    group_by = intent.get("group_by")

    start_time = datetime.now(timezone.utc)
    if target is None:
        result = provider.chat(system=_general_system_prompt(), user=question, max_tokens=400)
        answer = (result.text or "").strip()
        if not answer:
            raise RuntimeError(
                "AI provider returned an empty response — check the model "
                "configured in Settings → AI Config."
            )
        duration_ms = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
        _log_ai_call("home_search", actor, question, answer, duration_ms, success=True, model=provider.model)
        return {"answer": answer, "link": None, "link_label": None}

    # Look up the query function at call time (not a module-level pre-bound dict)
    # so that tests patching app.ai.home_search._query_events/_alerts/_cases take
    # effect — a dict built at import time would keep pointing at the originals
    # after unittest.mock.patch swaps the module attribute.
    query_fn = {
        "events": _query_events,
        "alerts": _query_alerts,
        "cases": _query_cases,
    }[target]
    count, summary = query_fn(filters)

    # Real top-N source IPs (with countries) for the events target — rendered as a
    # table by the UI and, for "top N ip" questions, fed to the summary LLM.
    top_ips: list[dict] = []
    if target == "events":
        top_ips = _top_source_ips(filters)

    context = f"Question: {question}\n\nReal results: {count} {target} matched.\nSummary: {summary}"
    if target == "events" and group_by == "source_ip" and top_ips:
        context += "\nTop source IPs (highest event counts):\n" + "\n".join(
            f"- {t['ip']}: {t['count']} events" for t in top_ips
        )
    result = provider.chat(system=_summary_system_prompt(with_table=bool(top_ips)), user=context, max_tokens=400)
    answer = (result.text or "").strip()
    if not answer:
        raise RuntimeError(
            "AI provider returned an empty response — check the model "
            "configured in Settings → AI Config."
        )
    duration_ms = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
    _log_ai_call("home_search", actor, question, answer, duration_ms, success=True, model=provider.model)

    response: dict = {
        "answer": answer,
        "link": _build_link(target, filters),
        "link_label": f"View {count} {target}",
        "meta": {
            "target": target,
            "count": count,
            "filters": filters,
            "group_by": group_by,
        },
    }
    if target == "events":
        response["table"] = {
            "title": "Top source IPs",
            "columns": ["rank", "ip", "country", "events"],
            "rows": [
                {
                    "rank": i + 1,
                    "ip": t["ip"],
                    "country": t.get("country_code") or t.get("country_name") or "",
                    "events": t["count"],
                }
                for i, t in enumerate(top_ips)
            ],
        }
        response["breakdown"] = summary.get("status_code_breakdown", {})
    elif target == "alerts":
        response["breakdown"] = summary.get("severity_breakdown", {})
    elif target == "cases":
        response["breakdown"] = summary.get("status_breakdown", {})
    return response

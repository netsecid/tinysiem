"""Filter registry + normalizer for the AI home search.

Single source of truth for which filters each target (events/alerts/cases)
supports and how to validate/normalize the LLM-extracted values. The extraction
prompt's field list is generated from this registry, so a new filter only needs
one addition here (plus the query-layer plumbing) — no prompt drift.

normalize_filters() returns (applied, dropped): applied maps directly to query
kwargs; dropped carries {field, value, reason} so the UI can show the user what
the AI understood but couldn't apply, instead of silently ignoring it.
"""

import ipaddress
import re

from app.ai import countries

# ── value normalizers ────────────────────────────────────────────────────────


def _as_int(value) -> tuple:
    try:
        return int(str(value).strip()), None
    except (TypeError, ValueError):
        return None, f"'{value}' is not a valid number"


def _as_iso_datetime(value) -> tuple:
    from datetime import datetime
    if not isinstance(value, str):
        return None, "must be an ISO 8601 datetime string"
    v = value.strip().replace("Z", "+00:00")
    try:
        datetime.fromisoformat(v)
    except ValueError:
        return None, f"'{value}' is not a valid ISO 8601 datetime"
    return value.strip(), None


def _as_country(value) -> tuple:
    code = countries.to_code(value)
    if code is None:
        return None, f"'{value}' is not a recognized country (use ISO code like ID, RU)"
    return code, None


def _as_enum(value, allowed) -> tuple:
    v = str(value).strip().lower()
    if v not in allowed:
        return None, f"'{value}' is not one of: {', '.join(sorted(allowed))}"
    return v, None


def _as_text(value) -> tuple:
    v = str(value).strip()
    if not v:
        return None, "empty value"
    return v, None


def _as_ip(value) -> tuple:
    """source_ip: exact IP → ('source_ip_exact', ip); CIDR or 'a.b.c.x' → prefix.

    Returns ((output_key, normalized_value), err) — the output key tells the
    query layer whether to use exact equality or a prefix LIKE. Exact per user
    decision — a plain IP never matches 11.2.3.45 when filtering 1.2.3.4.
    Non-octet-aligned CIDRs (e.g. /25) degrade to the containing /24 prefix
    (over-inclusive but never silently wrong for the exact-IP case).
    """
    v = str(value).strip()
    # "45.148.10.x" / "45.148.10.*" → prefix LIKE "45.148.10.%"
    m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){0,2})\.(?:x|X|\*)$", v)
    if m:
        return ("source_ip_prefix", f"{m.group(1)}."), None
    if ":" in v:  # IPv6 — exact single addresses only
        try:
            return ("source_ip_exact", str(ipaddress.ip_address(v))), None
        except ValueError:
            return None, f"'{value}' is not a valid IP address"
    try:
        net = ipaddress.ip_network(v, strict=False)
    except ValueError:
        return None, f"'{value}' is not a valid IP address or CIDR"
    if net.num_addresses == 1:
        return ("source_ip_exact", str(net.network_address)), None
    octets = str(net.network_address).split(".")
    prefix_octets = net.prefixlen // 8
    if prefix_octets >= 4:
        return ("source_ip_exact", str(net.network_address)), None
    return ("source_ip_prefix", ".".join(octets[:prefix_octets]) + "."), None


# ── registry ─────────────────────────────────────────────────────────────────

EVENT_FILTERS: dict[str, dict] = {
    "source":              {"normalize": _as_text},
    "source_ip":           {"normalize": _as_ip},
    "method":              {"normalize": _as_text},
    "uri":                 {"normalize": _as_text},
    "user_agent":          {"normalize": _as_text},
    "referer":             {"normalize": _as_text},
    "status_code":         {"normalize": _as_int},
    "status_min":          {"normalize": _as_int},
    "status_max":          {"normalize": _as_int},
    "response_size_min":   {"normalize": _as_int},
    "response_size_max":   {"normalize": _as_int},
    "country_code":        {"normalize": _as_country},
    "city":                {"normalize": _as_text},
    "asn":                 {"normalize": _as_int},
    "q":                   {"normalize": _as_text},
    "start":               {"normalize": _as_iso_datetime},
    "end":                 {"normalize": _as_iso_datetime},
}

ALERT_FILTERS: dict[str, dict] = {
    "severity":        {"normalize": lambda v: _as_enum(v, {"low", "medium", "high", "critical"})},
    "rule_name":       {"normalize": _as_text},
    "source_ip":       {"normalize": _as_text},
    "mitre_tactic":    {"normalize": _as_text},
    "mitre_technique": {"normalize": _as_text},
    "q":               {"normalize": _as_text},
    "start":           {"normalize": _as_iso_datetime},
    "end":             {"normalize": _as_iso_datetime},
}

CASE_FILTERS: dict[str, dict] = {
    "status":    {"normalize": lambda v: _as_enum(v, {"open", "investigating", "resolved"})},
    "severity":  {"normalize": lambda v: _as_enum(v, {"low", "medium", "high", "critical"})},
    "assignee":  {"normalize": _as_text},
    "q":         {"normalize": _as_text},
    "start":     {"normalize": _as_iso_datetime},
    "end":       {"normalize": _as_iso_datetime},
}

_TARGET_REGISTRY = {
    "events": EVENT_FILTERS,
    "alerts": ALERT_FILTERS,
    "cases":  CASE_FILTERS,
}

# Fields shown to the extraction LLM in a stable, readable order.
_FIELD_ORDER = {
    "events": ["source", "source_ip", "method", "uri", "user_agent", "referer",
               "status_code", "status_min", "status_max",
               "response_size_min", "response_size_max",
               "country_code", "city", "asn", "q", "start", "end"],
    "alerts": ["severity", "rule_name", "source_ip", "mitre_tactic", "mitre_technique",
               "q", "start", "end"],
    "cases":  ["status", "severity", "assignee", "q", "start", "end"],
}


def target_field_list(target: str) -> str:
    """Comma-separated filter list for the extraction prompt (registry-derived)."""
    return ", ".join(_FIELD_ORDER.get(target, []))


def normalize_filters(target: str, raw_filters: dict) -> tuple[dict, list[dict]]:
    """Validate + normalize LLM-extracted filters.

    Returns (applied, dropped). `applied` keys are query-layer kwargs
    (e.g. source_ip_exact); `dropped` is a list of {field, value, reason}
    dicts for UI warnings and summary context.
    """
    registry = _TARGET_REGISTRY.get(target, {})
    applied: dict = {}
    dropped: list[dict] = []

    if not isinstance(raw_filters, dict):
        return applied, dropped

    for field, value in raw_filters.items():
        if value is None or value == "":
            continue
        if isinstance(value, str) and not value.strip():
            continue  # whitespace-only — silently skip, not worth a warning
        spec = registry.get(field)
        if spec is None:
            dropped.append({"field": field, "value": value, "reason": f"'{field}' is not a supported filter"})
            continue
        normalized, err = spec["normalize"](value)
        if err is not None:
            dropped.append({"field": field, "value": value, "reason": err})
            continue
        if isinstance(normalized, tuple):  # _as_ip returns (output_key, value)
            out_key, out_val = normalized
        else:
            out_key, out_val = field, normalized
        if out_val is None or out_val == "":
            continue
        applied[out_key] = out_val

    return applied, dropped

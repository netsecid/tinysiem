"""Tests for app/ai/filters.py (registry + normalizer) and app/ai/countries.py.

Unit tests are DB-free; the store-level tests (exact IP / country filter)
use the session-scoped DuckDB like test_timestamp_utc.py.
"""

import uuid


# ── country resolution ───────────────────────────────────────────────────────


def test_country_iso2_passthrough_uppercased():
    from app.ai.countries import to_code
    assert to_code("id") == "ID"
    assert to_code("RU") == "RU"
    assert to_code("us") == "US"


def test_country_iso3_to_iso2():
    from app.ai.countries import to_code
    assert to_code("IDN") == "ID"
    assert to_code("rus") == "RU"


def test_country_names_en_and_id():
    from app.ai.countries import to_code
    assert to_code("Indonesia") == "ID"
    assert to_code("Rusia") == "RU"
    assert to_code("United States") == "US"
    assert to_code("Amerika Serikat") == "US"
    assert to_code("Jepang") == "JP"
    assert to_code("Belanda") == "NL"
    assert to_code("Inggris") == "GB"


def test_country_unknown_returns_none():
    from app.ai.countries import to_code
    assert to_code("Atlantis") is None
    assert to_code("") is None
    assert to_code(None) is None


# ── normalizer ───────────────────────────────────────────────────────────────


def test_normalize_country_name_to_code():
    from app.ai.filters import normalize_filters
    applied, dropped = normalize_filters("events", {"country_code": "Indonesia"})
    assert applied == {"country_code": "ID"}
    assert dropped == []


def test_normalize_int_and_enum():
    from app.ai.filters import normalize_filters
    applied, dropped = normalize_filters("events", {"status_code": "404"})
    assert applied == {"status_code": 404}
    applied, dropped = normalize_filters("alerts", {"severity": "Critical"})
    assert applied == {"severity": "critical"}
    applied, dropped = normalize_filters("alerts", {"severity": "urgent"})
    assert applied == {}
    assert dropped[0]["field"] == "severity"
    assert "not one of" in dropped[0]["reason"]


def test_normalize_ip_exact_cidr_and_x():
    from app.ai.filters import normalize_filters
    applied, _ = normalize_filters("events", {"source_ip": "45.148.10.151"})
    assert applied == {"source_ip_exact": "45.148.10.151"}
    applied, _ = normalize_filters("events", {"source_ip": "45.148.10.0/24"})
    assert applied == {"source_ip_prefix": "45.148.10."}
    applied, _ = normalize_filters("events", {"source_ip": "45.148.10.x"})
    assert applied == {"source_ip_prefix": "45.148.10."}
    applied, dropped = normalize_filters("events", {"source_ip": "not-an-ip"})
    assert applied == {}
    assert dropped[0]["field"] == "source_ip"


def test_normalize_unknown_field_dropped_with_reason():
    from app.ai.filters import normalize_filters
    applied, dropped = normalize_filters("events", {"port": 443})
    assert applied == {}
    assert dropped == [{"field": "port", "value": 443, "reason": "'port' is not a supported filter"}]


def test_normalize_invalid_datetime_dropped():
    from app.ai.filters import normalize_filters
    applied, dropped = normalize_filters("events", {"start": "yesterday"})
    assert applied == {}
    assert dropped[0]["field"] == "start"
    applied, dropped = normalize_filters("events", {"end": "2026-08-18T04:00:00+00:00"})
    assert applied == {"end": "2026-08-18T04:00:00+00:00"}
    assert dropped == []


def test_normalize_skips_empty_values():
    from app.ai.filters import normalize_filters
    applied, dropped = normalize_filters("events", {"method": "", "source": None, "q": "  "})
    assert applied == {}
    assert dropped == []


def test_normalize_alerts_mitre_passthrough():
    from app.ai.filters import normalize_filters
    applied, dropped = normalize_filters("alerts", {"mitre_tactic": "defense-evasion", "mitre_technique": "T1110"})
    assert applied == {"mitre_tactic": "defense-evasion", "mitre_technique": "T1110"}
    assert dropped == []


def test_normalize_cases_status_enum():
    from app.ai.filters import normalize_filters
    applied, _ = normalize_filters("cases", {"status": "Open"})
    assert applied == {"status": "open"}
    applied, dropped = normalize_filters("cases", {"status": "closed"})
    assert applied == {}
    assert dropped[0]["field"] == "status"


# ── store-level: exact IP + country filter ───────────────────────────────────


def _insert_event(source_ip: str, country_code: str | None = None) -> str:
    from app.storage import duckdb_store
    event_id = str(uuid.uuid4())
    duckdb_store.insert_event({
        "id": event_id,
        "source": "test_flt",
        "ingested_at": "2026-08-18T04:00:00",
        "event_time": "2026-08-18T04:00:00",
        "source_ip": source_ip, "method": "Ban", "uri": "/", "status_code": None,
        "response_size": None, "user_agent": "t", "referer": None,
        "raw": "flt-test", "extra": {},
        "country_code": country_code, "country_name": None, "city": None, "asn": None,
    })
    return event_id


def test_query_events_source_ip_exact_not_substring():
    from app.storage import duckdb_store
    _insert_event("1.2.3.4")
    _insert_event("11.2.3.45")  # LIKE %1.2.3.4% would match this too
    exact = duckdb_store.query_events(source="test_flt", source_ip_exact="1.2.3.4", limit=50)
    assert exact["total"] == 1
    assert exact["events"][0]["source_ip"] == "1.2.3.4"


def test_query_events_source_ip_prefix():
    from app.storage import duckdb_store
    _insert_event("45.148.10.151")
    _insert_event("45.148.10.152")
    _insert_event("45.148.11.1")
    prefixed = duckdb_store.query_events(source="test_flt", source_ip_prefix="45.148.10.", limit=50)
    assert prefixed["total"] == 2


def test_query_events_country_code_filter_case_insensitive():
    from app.storage import duckdb_store
    _insert_event("103.146.187.10", country_code="ID")
    _insert_event("45.153.34.161", country_code="NL")
    by_country = duckdb_store.query_events(source="test_flt", country_code="id", limit=50)
    assert by_country["total"] == 1
    assert by_country["events"][0]["source_ip"] == "103.146.187.10"


# ── alerts MITRE filter ──────────────────────────────────────────────────────


def test_apply_alert_filters_mitre():
    from app.alerts.router import apply_alert_filters
    alerts = [
        {"alert_id": "a1", "severity": "high", "rule_name": "r1", "mitre_tactic": "defense-evasion", "mitre_technique": "T1110", "triggered_at": "2026-08-18T00:00:00Z"},
        {"alert_id": "a2", "severity": "high", "rule_name": "r1", "mitre_tactic": "credential-access", "mitre_technique": "T1110", "triggered_at": "2026-08-18T00:00:00Z"},
        {"alert_id": "a3", "severity": "low", "rule_name": "r2", "mitre_tactic": "defense-evasion", "mitre_technique": "T1562", "triggered_at": "2026-08-18T00:00:00Z"},
    ]
    filtered = apply_alert_filters(alerts, None, None, None, None, None, None, None,
                                   mitre_tactic="defense-evasion")
    assert {a["alert_id"] for a in filtered} == {"a1", "a3"}
    filtered = apply_alert_filters(alerts, None, None, None, None, None, None, None,
                                   mitre_technique="T1110")
    assert {a["alert_id"] for a in filtered} == {"a1", "a2"}

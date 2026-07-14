import uuid
from datetime import datetime, timedelta

from app.rules import backtest as rule_backtest
from app.rules import engine as rule_engine
from app.rules import exceptions_store
from app.storage import duckdb_store


def _insert(source: str, status_code: int, ts: datetime, source_ip: str = "10.0.0.9") -> str:
    event_id = str(uuid.uuid4())
    duckdb_store.insert_event({
        "id": event_id, "source": source, "ingested_at": ts, "event_time": None,
        "source_ip": source_ip, "method": "GET", "uri": "/x", "status_code": status_code,
        "response_size": 100, "user_agent": "test", "referer": None,
        "raw": f"{source} {status_code}", "extra": {},
    })
    return event_id


async def test_backtest_inline_field_match(client, admin_headers):
    source = f"bt-inline-{uuid.uuid4().hex[:8]}"
    now = datetime.utcnow()
    _insert(source, 500, now - timedelta(hours=1))
    _insert(source, 500, now - timedelta(hours=2))
    _insert(source, 200, now - timedelta(hours=1))

    yaml_text = f"""\
name: bt-test-rule-{uuid.uuid4().hex[:8]}
severity: high
source: {source}
condition:
  type: field_match
  field: status_code
  value: 500
  operator: eq
mitre_tactic: "Impact"
mitre_technique: "T1499"
"""
    r = await client.post("/rules/backtest", json={"yaml_text": yaml_text, "days": 7}, headers=admin_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["supported"] is True
    assert data["would_fire_count"] == 2


async def test_backtest_named_rule_not_found(client, admin_headers):
    r = await client.post("/rules/nonexistent-rule-xyz/backtest", json={"days": 7}, headers=admin_headers)
    assert r.status_code == 404


async def test_backtest_correlation_unsupported(client, admin_headers):
    yaml_text = """\
name: bt-corr-test
severity: high
source: nginx
condition:
  type: correlation
  capture_field: source_ip
  window_seconds: 300
  steps:
    - field: status_code
      value: 401
      operator: eq
    - field: status_code
      value: 200
      operator: eq
mitre_tactic: "Credential Access"
mitre_technique: "T1110"
"""
    r = await client.post("/rules/backtest", json={"yaml_text": yaml_text, "days": 7}, headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["supported"] is False


async def test_backtest_analyst_forbidden(client, analyst_headers):
    r = await client.post("/rules/backtest", json={"yaml_text": "name: x\n", "days": 7}, headers=analyst_headers)
    assert r.status_code == 403


async def test_backtest_days_out_of_range_rejected(client, admin_headers):
    yaml_text = "name: bt-days-test\nseverity: low\nsource: nginx\ncondition:\n  type: field_match\n  field: status_code\n  value: 200\n"
    r = await client.post("/rules/backtest", json={"yaml_text": yaml_text, "days": 90}, headers=admin_headers)
    assert r.status_code == 422


async def test_backtest_invalid_numeric_operator_returns_422(client, admin_headers):
    """A field_match condition using a numeric-comparison operator (gt/gte/lt/lte)
    on a non-numeric field is fail-closed in the live rule engine, and
    duckdb_store raises ValueError for it. The backtest endpoint must turn
    that into a clean 422, not an unhandled 500."""
    yaml_text = """\
name: bt-bad-operator-test
severity: low
source: nginx
condition:
  type: field_match
  field: uri
  operator: gt
  value: "test"
"""
    r = await client.post("/rules/backtest", json={"yaml_text": yaml_text, "days": 7}, headers=admin_headers)
    assert r.status_code == 422
    assert "uri" in r.json()["detail"]


def test_backtest_field_match_excludes_rule_exceptions():
    """Whole-branch review Finding 1: backtest must apply the SAME per-rule
    exceptions the live engine applies, or its would_fire_count is inflated
    relative to what actually happens in production."""
    marker_source = f"bt-exc-fm-{uuid.uuid4().hex[:8]}"
    rule_name = f"bt-exc-fm-rule-{uuid.uuid4().hex[:8]}"
    rule = {
        "name": rule_name, "severity": "high", "source": marker_source,
        "condition": {"type": "field_match", "field": "status_code", "value": 500, "operator": "eq"},
    }
    now = datetime.utcnow()
    _insert(marker_source, 500, now - timedelta(hours=1), source_ip="9.9.9.9")  # excepted
    _insert(marker_source, 500, now - timedelta(hours=2), source_ip="9.9.9.9")  # excepted
    _insert(marker_source, 500, now - timedelta(hours=1), source_ip="1.1.1.1")  # real

    try:
        # Before adding the exception: backtest counts all 3 matching events.
        result_before = rule_backtest.run_backtest(rule, days=7)
        assert result_before["would_fire_count"] == 3

        exceptions_store.add_exception(rule_name, "source_ip", "9.9.9.9", "noisy scanner", "tester")
        rule_engine.load_exceptions()

        result_after = rule_backtest.run_backtest(rule, days=7)
        assert result_after["would_fire_count"] == 1, (
            "backtest must exclude events matching the rule's exception, "
            "same as the live engine would"
        )
    finally:
        rule_engine.load_exceptions()


def test_backtest_threshold_excludes_rule_exceptions():
    """Same as above but for the threshold condition path, which goes through
    query_events_windowed_counts() instead of query_events_matching()."""
    marker_source = f"bt-exc-th-{uuid.uuid4().hex[:8]}"
    rule_name = f"bt-exc-th-rule-{uuid.uuid4().hex[:8]}"
    rule = {
        "name": rule_name, "severity": "high", "source": marker_source,
        "condition": {
            "type": "threshold", "field": "status_code", "value": 401, "operator": "eq",
            "threshold_count": 3, "window_seconds": 3600,
        },
    }
    now = datetime.utcnow()
    base = (now - timedelta(hours=1)).replace(second=0, microsecond=0) + timedelta(seconds=5)
    # 2 excepted events + 1 real event land in the same 3600s bucket: without
    # exclusion this bucket would have count=3 and reach threshold_count=3.
    _insert(marker_source, 401, base, source_ip="9.9.9.9")
    _insert(marker_source, 401, base + timedelta(seconds=5), source_ip="9.9.9.9")
    _insert(marker_source, 401, base + timedelta(seconds=10), source_ip="1.1.1.1")

    try:
        result_before = rule_backtest.run_backtest(rule, days=7)
        assert result_before["would_fire_count"] >= 1

        exceptions_store.add_exception(rule_name, "source_ip", "9.9.9.9", "noisy scanner", "tester")
        rule_engine.load_exceptions()

        result_after = rule_backtest.run_backtest(rule, days=7)
        assert result_after["would_fire_count"] == 0, (
            "excluding the 2 excepted events should leave only 1 real event in the "
            "bucket, below threshold_count=3 — backtest must reflect that"
        )
    finally:
        rule_engine.load_exceptions()

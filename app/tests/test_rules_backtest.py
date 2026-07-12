import uuid
from datetime import datetime, timedelta

from app.storage import duckdb_store


def _insert(source: str, status_code: int, ts: datetime) -> str:
    event_id = str(uuid.uuid4())
    duckdb_store.insert_event({
        "id": event_id, "source": source, "ingested_at": ts, "event_time": None,
        "source_ip": "10.0.0.9", "method": "GET", "uri": "/x", "status_code": status_code,
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

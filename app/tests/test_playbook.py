import pytest


async def test_complete_step_creates_row(client, analyst_headers):
    from app.cases import store as case_store
    cr = await client.post("/cases", json={"title": "Playbook Test"}, headers=analyst_headers)
    case_id = cr.json()["case_id"]
    record, created = case_store.complete_step(case_id, "test-rule", "step1", "analyst1", "done")
    assert created is True
    assert record["step_id"] == "step1"
    assert record["rule_name"] == "test-rule"
    assert record["completed_by"] == "analyst1"
    assert record["note"] == "done"
    assert "completed_at" in record


async def test_complete_step_idempotent(client, analyst_headers):
    from app.cases import store as case_store
    cr = await client.post("/cases", json={"title": "Idempotent Test"}, headers=analyst_headers)
    case_id = cr.json()["case_id"]
    _, created1 = case_store.complete_step(case_id, "test-rule", "step1", "analyst1")
    record2, created2 = case_store.complete_step(case_id, "test-rule", "step1", "analyst2")
    assert created1 is True
    assert created2 is False
    assert record2["completed_by"] == "analyst1"  # original record unchanged


async def test_uncomplete_step(client, analyst_headers):
    from app.cases import store as case_store
    cr = await client.post("/cases", json={"title": "Uncheck Test"}, headers=analyst_headers)
    case_id = cr.json()["case_id"]
    case_store.complete_step(case_id, "test-rule", "step1", "analyst1")
    removed = case_store.uncomplete_step(case_id, "test-rule", "step1")
    assert removed is True
    assert case_store.get_step_completion(case_id, "test-rule", "step1") is None


async def test_uncomplete_step_not_found(client, analyst_headers):
    from app.cases import store as case_store
    cr = await client.post("/cases", json={"title": "No Step"}, headers=analyst_headers)
    case_id = cr.json()["case_id"]
    removed = case_store.uncomplete_step(case_id, "test-rule", "nonexistent")
    assert removed is False


async def test_get_completed_steps_scoped_by_case(client, analyst_headers):
    from app.cases import store as case_store
    cr1 = await client.post("/cases", json={"title": "Case A"}, headers=analyst_headers)
    cr2 = await client.post("/cases", json={"title": "Case B"}, headers=analyst_headers)
    case_a = cr1.json()["case_id"]
    case_b = cr2.json()["case_id"]
    case_store.complete_step(case_a, "rule-x", "step1", "analyst1")
    case_store.complete_step(case_b, "rule-x", "step1", "analyst1")
    steps_a = case_store.get_completed_steps(case_a)
    assert len(steps_a) == 1
    assert steps_a[0]["case_id"] == case_a


def test_get_event_full_returns_all_columns(client):
    from app.storage import duckdb_store
    # Insert a real event
    import uuid, datetime
    ev = {
        "id": str(uuid.uuid4()), "source": "nginx", "raw": "test raw",
        "ingested_at": datetime.datetime.utcnow(),
        "source_ip": "1.2.3.4", "method": "GET", "uri": "/test",
        "status_code": 200, "response_size": 100,
        "user_agent": "TestAgent/1.0", "referer": None,
        "event_time": None, "extra": {},
    }
    duckdb_store.insert_event(ev)
    result = duckdb_store.get_event_full(ev["id"])
    assert result is not None
    for col in ["id", "source", "ingested_at", "source_ip", "method", "uri",
                "status_code", "raw", "user_agent", "response_size",
                "event_time", "referer", "extra"]:
        assert col in result


def test_get_event_full_not_found():
    from app.storage import duckdb_store
    assert duckdb_store.get_event_full("nonexistent-id") is None


async def test_alert_snapshot_includes_playbook(client, analyst_headers):
    """write_alert snapshots playbook into the JSONL record."""
    import json, uuid
    from pathlib import Path
    from app.alerts.file_writer import write_alert
    from app.config import settings

    rule = {
        "name": "test-snap-rule",
        "severity": "medium",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1595",
        "playbook": {
            "summary": "Check the thing",
            "steps": [{"id": "s1", "name": "Step one"}],
        },
    }
    event = {"id": str(uuid.uuid4()), "source_ip": "1.2.3.4"}
    write_alert(rule, event)

    path = Path(settings.tinysiem_alerts_path)
    alerts = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    matching = [a for a in alerts if a.get("rule_name") == "test-snap-rule"]
    assert matching, "Alert not written"
    assert matching[-1]["playbook"]["summary"] == "Check the thing"
    assert matching[-1]["playbook"]["steps"][0]["id"] == "s1"


async def test_alert_snapshot_no_playbook(client, analyst_headers):
    """write_alert with a rule without playbook must not error and must omit the field."""
    import json, uuid
    from pathlib import Path
    from app.alerts.file_writer import write_alert
    from app.config import settings

    rule = {"name": "no-playbook-rule", "severity": "low"}
    event = {"id": str(uuid.uuid4()), "source_ip": "2.3.4.5"}
    write_alert(rule, event)

    path = Path(settings.tinysiem_alerts_path)
    alerts = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    matching = [a for a in alerts if a.get("rule_name") == "no-playbook-rule"]
    assert matching
    assert "playbook" not in matching[-1]


async def test_rule_playbook_validation_missing_id(client, admin_headers):
    """Steps missing id return 422."""
    yaml_text = """
name: val-test-rule
severity: medium
source: nginx
condition:
  type: field_match
  field: status_code
  value: 404
  operator: eq
playbook:
  summary: "Test"
  steps:
    - name: "Step without id"
"""
    resp = await client.post("/rules", json={"name": "val-test-rule", "yaml_text": yaml_text}, headers=admin_headers)
    assert resp.status_code == 422
    assert "id" in resp.json()["detail"].lower()


async def test_rule_playbook_validation_duplicate_ids(client, admin_headers):
    """Duplicate step ids return 422."""
    yaml_text = """
name: dup-id-rule
severity: medium
source: nginx
condition:
  type: field_match
  field: status_code
  value: 404
  operator: eq
playbook:
  summary: "Test"
  steps:
    - id: step1
      name: "First"
    - id: step1
      name: "Duplicate"
"""
    resp = await client.post("/rules", json={"name": "dup-id-rule", "yaml_text": yaml_text}, headers=admin_headers)
    assert resp.status_code == 422
    assert "duplicate" in resp.json()["detail"].lower()


async def test_rule_without_playbook_still_valid(client, admin_headers):
    """Rules with no playbook field are valid."""
    yaml_text = """
name: no-pb-rule
severity: low
source: nginx
condition:
  type: field_match
  field: status_code
  value: 200
  operator: eq
"""
    resp = await client.post("/rules", json={"name": "no-pb-rule", "yaml_text": yaml_text}, headers=admin_headers)
    # 201 created or 200 if already exists — either is fine, not 422
    assert resp.status_code in (200, 201)
    # Cleanup
    await client.delete("/rules/no-pb-rule", headers=admin_headers)

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


async def test_get_case_playbook_empty(client, analyst_headers):
    """Case with no linked alerts returns empty playbooks list."""
    cr = await client.post("/cases", json={"title": "PB Empty"}, headers=analyst_headers)
    case_id = cr.json()["case_id"]
    resp = await client.get(f"/cases/{case_id}/playbook", headers=analyst_headers)
    assert resp.status_code == 200
    assert resp.json() == {"playbooks": []}


async def test_get_case_playbook_with_alert_snapshot(client, analyst_headers):
    """Case linked to an alert that has a playbook returns that playbook with steps."""
    import json, uuid
    from pathlib import Path
    from app.alerts.file_writer import write_alert
    from app.config import settings

    # Write an alert with a playbook snapshot
    alert_id = str(uuid.uuid4())
    rule = {
        "name": "nginx-http-404-spike",
        "severity": "medium",
        "playbook": {
            "summary": "Investigate enumeration",
            "steps": [
                {"id": "check_ip", "name": "Check IP", "notes": "Look it up"},
                {"id": "escalate", "name": "Escalate if needed"},
            ],
        },
    }
    event = {"id": str(uuid.uuid4()), "source_ip": "9.9.9.9"}
    write_alert(rule, event)

    # Find the alert_id just written
    path = Path(settings.tinysiem_alerts_path)
    alerts = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    written = [a for a in alerts if a.get("rule_name") == "nginx-http-404-spike"]
    assert written
    alert_id = written[-1]["alert_id"]

    # Create case, link alert
    cr = await client.post("/cases", json={"title": "PB Case"}, headers=analyst_headers)
    case_id = cr.json()["case_id"]
    link = await client.post(f"/cases/{case_id}/alerts", json={"alert_ids": [alert_id]}, headers=analyst_headers)
    assert link.status_code == 200

    # Get playbook
    resp = await client.get(f"/cases/{case_id}/playbook", headers=analyst_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["playbooks"]) == 1
    pb = data["playbooks"][0]
    assert pb["rule_name"] == "nginx-http-404-spike"
    assert pb["summary"] == "Investigate enumeration"
    assert len(pb["steps"]) == 2
    assert pb["steps"][0]["id"] == "check_ip"
    assert pb["steps"][0]["completed"] is False


async def test_complete_and_uncheck_step_via_api(client, analyst_headers):
    """POST step marks complete; DELETE unchecks it; GET reflects state."""
    import json, uuid
    from pathlib import Path
    from app.alerts.file_writer import write_alert
    from app.config import settings

    rule = {
        "name": "brute-force-then-success",
        "severity": "high",
        "playbook": {"summary": "BF", "steps": [{"id": "s1", "name": "Step 1"}]},
    }
    event = {"id": str(uuid.uuid4()), "source_ip": "5.5.5.5"}
    write_alert(rule, event)
    path = Path(settings.tinysiem_alerts_path)
    alerts = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    alert_id = [a for a in alerts if a.get("rule_name") == "brute-force-then-success"][-1]["alert_id"]

    cr = await client.post("/cases", json={"title": "Step Case"}, headers=analyst_headers)
    case_id = cr.json()["case_id"]
    await client.post(f"/cases/{case_id}/alerts", json={"alert_ids": [alert_id]}, headers=analyst_headers)

    # Complete step
    resp = await client.post(f"/cases/{case_id}/playbook/steps",
        json={"rule_name": "brute-force-then-success", "step_id": "s1", "note": "done"},
        headers=analyst_headers)
    assert resp.status_code == 201
    assert resp.json()["step_id"] == "s1"

    # GET shows completed
    pb_resp = await client.get(f"/cases/{case_id}/playbook", headers=analyst_headers)
    step = pb_resp.json()["playbooks"][0]["steps"][0]
    assert step["completed"] is True
    assert step["completion_note"] == "done"

    # Idempotent POST → 200
    resp2 = await client.post(f"/cases/{case_id}/playbook/steps",
        json={"rule_name": "brute-force-then-success", "step_id": "s1"},
        headers=analyst_headers)
    assert resp2.status_code == 200

    # DELETE unchecks
    del_resp = await client.delete(
        f"/cases/{case_id}/playbook/steps/s1?rule_name=brute-force-then-success",
        headers=analyst_headers)
    assert del_resp.status_code == 204

    pb_resp2 = await client.get(f"/cases/{case_id}/playbook", headers=analyst_headers)
    step2 = pb_resp2.json()["playbooks"][0]["steps"][0]
    assert step2["completed"] is False

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

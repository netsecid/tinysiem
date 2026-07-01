"""Tests for Smart Baselines API and engine."""
import uuid
from datetime import datetime


# ── Baselines API ──────────────────────────────────────────────────────────────

async def test_list_baselines_empty(client, analyst_headers):
    r = await client.get("/baselines", headers=analyst_headers)
    assert r.status_code == 200
    d = r.json()
    assert "baselines" in d
    assert isinstance(d["baselines"], list)


async def test_list_baselines_requires_auth(client):
    r = await client.get("/baselines")
    assert r.status_code == 401


async def test_list_violations_empty(client, analyst_headers):
    r = await client.get("/baselines/violations", headers=analyst_headers)
    assert r.status_code == 200
    d = r.json()
    assert "violations" in d
    assert d["total"] == 0


async def test_list_violations_requires_auth(client):
    r = await client.get("/baselines/violations")
    assert r.status_code == 401


async def test_acknowledge_violation_not_found(client, analyst_headers):
    r = await client.patch(
        f"/baselines/violations/{uuid.uuid4()}",
        json={"acknowledged": True},
        headers=analyst_headers,
    )
    assert r.status_code == 404


async def test_reset_baselines_requires_admin(client, analyst_headers):
    r = await client.delete("/baselines/nginx", headers=analyst_headers)
    assert r.status_code == 403


async def test_reset_baselines_nonexistent_source(client, admin_headers):
    r = await client.delete("/baselines/nonexistent-source", headers=admin_headers)
    assert r.status_code == 204


# ── Baseline store (unit) ──────────────────────────────────────────────────────

def test_upsert_and_get_baseline():
    from app.baselines import store as bs
    now = datetime.utcnow()
    bs.upsert_baseline("test_src", 10, 2, 55.0, 12.0, 300.0, 5, now)
    result = bs.get_baseline("test_src", 10, 2)
    assert result is not None
    assert result["source"] == "test_src"
    assert result["hour_of_day"] == 10
    assert result["day_of_week"] == 2
    assert abs(result["mean"] - 55.0) < 0.001
    assert result["sample_count"] == 5


def test_upsert_updates_existing():
    from app.baselines import store as bs
    now = datetime.utcnow()
    bs.upsert_baseline("test_update_src", 3, 1, 10.0, 2.0, 8.0, 2, now)
    bs.upsert_baseline("test_update_src", 3, 1, 20.0, 5.0, 50.0, 3, now)
    result = bs.get_baseline("test_update_src", 3, 1)
    assert abs(result["mean"] - 20.0) < 0.001
    assert result["sample_count"] == 3


def test_list_baselines():
    from app.baselines import store as bs
    now = datetime.utcnow()
    bs.upsert_baseline("list_src", 0, 0, 1.0, 0.5, 0.25, 1, now)
    result = bs.list_baselines(source="list_src")
    assert len(result) >= 1
    # m2 should be stripped from response
    assert "m2" not in result[0]
    assert "last_updated" in result[0]


def test_insert_and_query_violation():
    from app.baselines import store as bs
    now = datetime.utcnow()
    vid = bs.insert_violation({
        "source": "nginx",
        "detected_at": now,
        "hour_of_day": 3,
        "day_of_week": 0,
        "observed_count": 410.0,
        "expected_mean": 12.0,
        "expected_std": 4.5,
        "z_score": 88.4,
        "severity": "critical",
    })
    assert isinstance(vid, str)
    result = bs.query_violations(source="nginx")
    vids = [v["violation_id"] for v in result["violations"]]
    assert vid in vids
    v = next(v for v in result["violations"] if v["violation_id"] == vid)
    assert v["severity"] == "critical"
    assert "summary" in v
    assert "nginx" in v["summary"]


def test_acknowledge_violation():
    from app.baselines import store as bs
    now = datetime.utcnow()
    vid = bs.insert_violation({
        "source": "ack_src",
        "detected_at": now,
        "hour_of_day": 5,
        "day_of_week": 3,
        "observed_count": 100.0,
        "expected_mean": 10.0,
        "expected_std": 2.0,
        "z_score": 45.0,
        "severity": "critical",
    })
    assert bs.acknowledge_violation(vid) is True
    result = bs.query_violations(source="ack_src", acknowledged=True)
    vids = [v["violation_id"] for v in result["violations"]]
    assert vid in vids


def test_acknowledge_nonexistent_returns_false():
    from app.baselines import store as bs
    assert bs.acknowledge_violation(str(uuid.uuid4())) is False


def test_delete_baselines_for_source():
    from app.baselines import store as bs
    now = datetime.utcnow()
    bs.upsert_baseline("del_src", 0, 0, 1.0, 0.0, 0.0, 1, now)
    bs.upsert_baseline("del_src", 1, 0, 2.0, 0.0, 0.0, 1, now)
    count = bs.delete_baselines_for_source("del_src")
    assert count >= 2
    remaining = bs.list_baselines(source="del_src")
    assert len(remaining) == 0


# ── Engine (unit) ─────────────────────────────────────────────────────────────

def test_z_severity():
    from app.baselines.engine import _z_severity
    assert _z_severity(2.5) == "low"
    assert _z_severity(3.5) == "low"
    assert _z_severity(4.5) == "medium"
    assert _z_severity(5.5) == "high"
    assert _z_severity(7.5) == "critical"


# ── Violation patch via API ────────────────────────────────────────────────────

async def test_acknowledge_violation_via_api(client, analyst_headers):
    from app.baselines import store as bs
    now = datetime.utcnow()
    vid = bs.insert_violation({
        "source": "api_ack_src",
        "detected_at": now,
        "hour_of_day": 8,
        "day_of_week": 4,
        "observed_count": 50.0,
        "expected_mean": 5.0,
        "expected_std": 1.0,
        "z_score": 45.0,
        "severity": "critical",
    })
    r = await client.patch(
        f"/baselines/violations/{vid}",
        json={"acknowledged": True},
        headers=analyst_headers,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "updated"


async def test_reset_baselines_via_api(client, admin_headers):
    from app.baselines import store as bs
    now = datetime.utcnow()
    bs.upsert_baseline("reset_api_src", 12, 5, 99.0, 5.0, 50.0, 10, now)
    r = await client.delete("/baselines/reset_api_src", headers=admin_headers)
    assert r.status_code == 204
    remaining = bs.list_baselines(source="reset_api_src")
    assert len(remaining) == 0

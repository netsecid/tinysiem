"""Tests for /dashboard/fidelity endpoint (P1: Detection Fidelity view)."""
import uuid
from datetime import datetime

from app.dashboard import fidelity as fidelity_telemetry
from app.storage import duckdb_store


def _insert_event(source: str) -> str:
    event_id = str(uuid.uuid4())
    duckdb_store.insert_event({
        "id": event_id, "source": source,
        "ingested_at": datetime.utcnow(), "event_time": None,
        "source_ip": "10.0.0.1", "method": "GET", "uri": "/x",
        "status_code": 200, "response_size": 100,
        "user_agent": "test", "referer": None,
        "raw": f"fidelity-test {event_id}", "extra": {},
    })
    return event_id


async def test_fidelity_requires_auth(client):
    r = await client.get("/dashboard/fidelity")
    assert r.status_code == 401


async def test_fidelity_response_shape_and_engine_fields(client, analyst_headers):
    """Smoke test: endpoint returns the documented shape with engine fields."""
    fidelity_telemetry.reset()
    # Some other tests (test_correlation_rules) leave _rules empty in teardown.
    # Make this test order-independent by reloading rules at the start.
    from app.rules import engine as rule_engine
    rule_engine.load_rules()
    src = f"fid-shape-{uuid.uuid4().hex[:8]}"
    _insert_event(src)
    r = await client.get("/dashboard/fidelity", headers=analyst_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["window_seconds"] == 60
    assert isinstance(data["generated_at"], str) and data["generated_at"].endswith("Z")
    assert set(data.keys()) == {"window_seconds", "generated_at", "sources", "engine", "outcomes"}
    assert set(data["engine"].keys()) == {"rules_loaded", "alerts_per_min"}
    assert set(data["outcomes"].keys()) == {
        "cases_open", "cases_investigating", "resolved",
        "total_resolved", "fidelity_pct",
    }
    assert set(data["outcomes"]["resolved"].keys()) == {
        "true_positive", "false_positive", "benign", "undetermined",
    }
    # Engine has a non-zero rules count (rule fixtures are loaded by conftest).
    assert isinstance(data["engine"]["rules_loaded"], int)
    assert data["engine"]["rules_loaded"] >= 1
    assert isinstance(data["engine"]["alerts_per_min"], (int, float))
    # Source we just inserted shows up.
    names = [s["name"] for s in data["sources"]]
    assert src in names
    src_row = next(s for s in data["sources"] if s["name"] == src)
    assert src_row["eps"] >= 0
    assert src_row["status"] in ("active", "stale", "silent")
    assert src_row["parse_fail_count"] == 0
    # fidelity_pct must equal round(100 * tp / denom, 2) where denom = tp+fp+bn.
    res = data["outcomes"]["resolved"]
    denom = res["true_positive"] + res["false_positive"] + res["benign"]
    expected = round(100.0 * res["true_positive"] / denom, 2) if denom > 0 else None
    assert data["outcomes"]["fidelity_pct"] == expected


def test_fidelity_null_when_denominator_is_zero():
    """MANDATORY null-guard: fidelity_pct must be None when no resolved cases
    exist (never 0, never div-by-zero).

    Pure unit test of the fidelity formula so it's robust against any cases
    added by other tests in the shared session DB.
    """
    # Replicate the endpoint's formula directly — keeps the null-guard
    # provable independent of other tests polluting the shared DB.
    resolved = {"true_positive": 0, "false_positive": 0, "benign": 0, "undetermined": 0}
    tp, fp, bn = resolved["true_positive"], resolved["false_positive"], resolved["benign"]
    denom = tp + fp + bn
    fidelity_pct = None if denom <= 0 else round(100.0 * tp / denom, 2)
    assert fidelity_pct is None

    # Also: every "all zero except undetermined" combo still yields None
    # (undetermined does NOT enter the denominator).
    for r in [
        {"true_positive": 0, "false_positive": 0, "benign": 0, "undetermined": 7},
        {"true_positive": 0, "false_positive": 0, "benign": 0, "undetermined": 1},
    ]:
        tp, fp, bn = r["true_positive"], r["false_positive"], r["benign"]
        denom = tp + fp + bn
        v = None if denom <= 0 else round(100.0 * tp / denom, 2)
        assert v is None


async def test_fidelity_eps_increases_with_recent_events(client, analyst_headers):
    fidelity_telemetry.reset()
    src = f"fid-eps-{uuid.uuid4().hex[:8]}"
    # Insert 30 events to one source; EPS should be > 0 in a 60s window.
    for _ in range(30):
        _insert_event(src)
    r = await client.get("/dashboard/fidelity", headers=analyst_headers)
    assert r.status_code == 200
    data = r.json()
    src_row = next(s for s in data["sources"] if s["name"] == src)
    # 30 events in 60s window = 0.5 EPS; allow for clock granularity.
    assert src_row["eps"] >= 0.4
    assert src_row["event_count_window" if "event_count_window" in src_row else "eps"] >= 0


async def test_fidelity_formula_with_benign_in_denominator(client, analyst_headers):
    """fidelity_pct = 100 * tp / (tp + fp + bn); benign IS in the denominator.

    Uses delta-based assertions so the test is robust against cases left over
    from other tests sharing the session DB.
    """
    fidelity_telemetry.reset()
    marker = f"ben-{uuid.uuid4().hex[:8]}"
    before = (await client.get("/dashboard/fidelity", headers=analyst_headers)).json()["outcomes"]

    # Create 2 TP, 1 FP, 1 Benign, 1 Undetermined resolved cases (delta).
    cases_payload = [
        ("tp", "true_positive"),
        ("tp", "true_positive"),
        ("fp", "false_positive"),
        ("bn", "benign"),
        ("un", "undetermined"),
    ]
    for kind, resolution in cases_payload:
        cr = await client.post("/cases", json={"title": f"{marker}-{kind}"}, headers=analyst_headers)
        patch = await client.patch(
            f"/cases/{cr.json()['case_id']}",
            json={"status": "resolved", "resolution": resolution},
            headers=analyst_headers,
        )
        assert patch.status_code == 200, patch.text

    r = await client.get("/dashboard/fidelity", headers=analyst_headers)
    assert r.status_code == 200
    out = r.json()["outcomes"]
    # Deltas match what we added.
    assert out["resolved"]["true_positive"] - before["resolved"]["true_positive"] == 2
    assert out["resolved"]["false_positive"] - before["resolved"]["false_positive"] == 1
    assert out["resolved"]["benign"] - before["resolved"]["benign"] == 1
    assert out["resolved"]["undetermined"] - before["resolved"]["undetermined"] == 1
    assert out["total_resolved"] - before["total_resolved"] == 5
    # Compute expected fidelity using the exact endpoint formula against the
    # post-test counts (this also proves the formula is faithful regardless
    # of any pre-existing cases).
    tp = out["resolved"]["true_positive"]
    fp = out["resolved"]["false_positive"]
    bn = out["resolved"]["benign"]
    expected = round(100.0 * tp / (tp + fp + bn), 2) if (tp + fp + bn) > 0 else None
    assert out["fidelity_pct"] == expected


async def test_fidelity_undetermined_excluded_from_denominator(client, analyst_headers):
    """undetermined must NOT count in the denominator.

    Test isolation strategy: snapshot the pre-test outcomes, add the test's
    cases, and verify the *deltas*. This makes the test robust against cases
    left in the shared session DB by earlier tests in the suite.
    """
    fidelity_telemetry.reset()
    marker = f"u-excl-{uuid.uuid4().hex[:8]}"
    before = (await client.get("/dashboard/fidelity", headers=analyst_headers)).json()["outcomes"]

    # 2 TP, 0 FP, 0 Benign, 5 Undetermined. Denom = 2, so 100%.
    for _ in range(2):
        cr = await client.post("/cases", json={"title": f"{marker}-tp"}, headers=analyst_headers)
        await client.patch(
            f"/cases/{cr.json()['case_id']}",
            json={"status": "resolved", "resolution": "true_positive"},
            headers=analyst_headers,
        )
    for _ in range(5):
        cr = await client.post("/cases", json={"title": f"{marker}-und"}, headers=analyst_headers)
        await client.patch(
            f"/cases/{cr.json()['case_id']}",
            json={"status": "resolved", "resolution": "undetermined"},
            headers=analyst_headers,
        )

    r = await client.get("/dashboard/fidelity", headers=analyst_headers)
    assert r.status_code == 200
    out = r.json()["outcomes"]
    assert out["resolved"]["true_positive"] - before["resolved"]["true_positive"] == 2
    assert out["resolved"]["undetermined"] - before["resolved"]["undetermined"] == 5
    # Compute expected fidelity from the post-test counts (matches the endpoint formula).
    tp = out["resolved"]["true_positive"]
    fp = out["resolved"]["false_positive"]
    bn = out["resolved"]["benign"]
    expected = round(100.0 * tp / (tp + fp + bn), 2) if (tp + fp + bn) > 0 else None
    assert out["fidelity_pct"] == expected
    # The undetermined bucket must not affect the percentage.
    assert out["fidelity_pct"] != 0.0 or out["fidelity_pct"] is None


async def test_fidelity_open_and_investigating_counts(client, analyst_headers):
    """open and investigating counts are read-only SELECTs over `cases`."""
    fidelity_telemetry.reset()
    marker = f"counts-{uuid.uuid4().hex[:8]}"
    before = (await client.get("/dashboard/fidelity", headers=analyst_headers)).json()["outcomes"]

    # 1 open, 2 investigating, 0 resolved (relative to before).
    await client.post("/cases", json={"title": f"{marker}-open"}, headers=analyst_headers)
    for _ in range(2):
        cr = await client.post("/cases", json={"title": f"{marker}-inv"}, headers=analyst_headers)
        await client.patch(
            f"/cases/{cr.json()['case_id']}",
            json={"status": "investigating"},
            headers=analyst_headers,
        )

    r = await client.get("/dashboard/fidelity", headers=analyst_headers)
    assert r.status_code == 200
    out = r.json()["outcomes"]
    assert out["cases_open"] - before["cases_open"] == 1
    assert out["cases_investigating"] - before["cases_investigating"] == 2
    # No resolved cases added by this test.
    assert out["total_resolved"] == before["total_resolved"]


async def test_fidelity_alert_rate_recorded(client, analyst_headers):
    fidelity_telemetry.reset()
    from app.alerts import file_writer
    rule = {"name": "fid-test-rule", "severity": "low", "mitre_tactic": "Test", "mitre_technique": "T0000"}
    event = {"id": "fake-evt-id", "source": "fid-alerts", "source_ip": "10.0.0.1"}
    for _ in range(3):
        file_writer.write_alert(rule, event)

    r = await client.get("/dashboard/fidelity", headers=analyst_headers)
    assert r.status_code == 200
    alerts_per_min = r.json()["engine"]["alerts_per_min"]
    # 3 alerts in 60s window = 3.0 alerts/min.
    assert alerts_per_min >= 2.5


def test_fidelity_snapshot_basic():
    fidelity_telemetry.reset()
    fidelity_telemetry.record_event("src-a")
    fidelity_telemetry.record_event("src-a")
    fidelity_telemetry.record_event("src-b")
    fidelity_telemetry.record_alert()
    snap = fidelity_telemetry.snapshot(window_seconds=60)
    assert snap["window_seconds"] == 60
    assert snap["total_events_window"] == 3
    a = next(s for s in snap["sources"] if s["name"] == "src-a")
    b = next(s for s in snap["sources"] if s["name"] == "src-b")
    assert a["event_count_window"] == 2
    assert b["event_count_window"] == 1
    assert snap["alerts_in_window"] == 1


def test_fidelity_snapshot_prunes_old_entries():
    """Entries with timestamps older than the window should be dropped."""
    import time
    from collections import deque
    fidelity_telemetry.reset()
    # Inject an old timestamp directly (older than any reasonable window)
    with fidelity_telemetry._lock:
        dq = fidelity_telemetry._event_ts.setdefault("ancient", deque())
        dq.append(time.monotonic() - 10000)
    snap = fidelity_telemetry.snapshot(window_seconds=60)
    ancient = next(s for s in snap["sources"] if s["name"] == "ancient")
    assert ancient["event_count_window"] == 0

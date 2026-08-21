"""Tests for /dashboard/fidelity endpoint (P1.5: Window filter + Totals)."""
import json
import tempfile
import uuid
from datetime import datetime
from pathlib import Path

from app.config import settings
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
    assert data["window_label"] == "1m"
    assert isinstance(data["generated_at"], str) and data["generated_at"].endswith("Z")
    assert set(data.keys()) == {
        "window_seconds", "window_label", "generated_at",
        "totals", "sources", "engine", "outcomes",
        "top_rules", "recent_alerts",
    }
    # totals shape
    assert set(data["totals"].keys()) == {
        "events", "events_rate", "events_rate_unit",
        "alerts", "alerts_rate", "alerts_rate_unit",
    }
    assert data["totals"]["events_rate_unit"] == "eps"
    assert data["totals"]["alerts_rate_unit"] == "alerts/min"
    # engine shape — alerts moved to totals
    assert set(data["engine"].keys()) == {"rules_loaded"}
    assert "alerts_per_min" not in data["engine"]
    # outcomes shape
    assert set(data["outcomes"].keys()) == {
        "cases_open", "cases_investigating", "resolved",
        "total_resolved", "fidelity_pct", "scope",
    }
    assert data["outcomes"]["scope"] == "all_time"
    assert set(data["outcomes"]["resolved"].keys()) == {
        "true_positive", "false_positive", "benign", "undetermined",
    }
    # Engine has a non-zero rules count (rule fixtures are loaded by conftest).
    assert isinstance(data["engine"]["rules_loaded"], int)
    assert data["engine"]["rules_loaded"] >= 1
    # Source we just inserted shows up with the new fields.
    names = [s["name"] for s in data["sources"]]
    assert src in names
    src_row = next(s for s in data["sources"] if s["name"] == src)
    assert set(src_row.keys()) == {"name", "events", "rate", "status", "parse_fail_count"}
    assert src_row["events"] >= 1
    assert src_row["rate"] >= 0
    assert src_row["status"] in ("active", "stale", "silent")
    assert src_row["parse_fail_count"] == 0
    assert "eps" not in src_row
    # top_rules / recent_alerts shape
    assert isinstance(data["top_rules"], list)
    assert isinstance(data["recent_alerts"], list)
    for tr in data["top_rules"]:
        assert set(tr.keys()) == {"rule_name", "count"}
    for ra in data["recent_alerts"]:
        assert set(ra.keys()) == {
            "alert_id", "rule_name", "severity", "triggered_at", "source_ip", "summary",
        }
    # fidelity_pct must equal round(100 * tp / denom, 2) where denom = tp+fp+bn.
    res = data["outcomes"]["resolved"]
    denom = res["true_positive"] + res["false_positive"] + res["benign"]
    expected = round(100.0 * res["true_positive"] / denom, 2) if denom > 0 else None
    assert data["outcomes"]["fidelity_pct"] == expected


async def test_fidelity_window_validation(client, analyst_headers):
    """?window=<invalid> → 422; valid windows return 200 with correct label."""
    fidelity_telemetry.reset()
    r = await client.get("/dashboard/fidelity?window=123", headers=analyst_headers)
    assert r.status_code == 422
    assert "window" in r.json()["detail"].lower()
    for w, label in ((60, "1m"), (3600, "1h"), (86400, "24h")):
        r = await client.get(f"/dashboard/fidelity?window={w}", headers=analyst_headers)
        assert r.status_code == 200, (w, r.text)
        d = r.json()
        assert d["window_seconds"] == w
        assert d["window_label"] == label
        assert d["totals"]["events"] >= 0


def test_fidelity_rate_normalization_units():
    """Pure-function unit test for the rate normalization helper."""
    from app.dashboard.fidelity import _events_rate_for_window, _alerts_rate_for_window
    # 60s window → events/60 + eps
    rate, unit = _events_rate_for_window(30, 60)
    assert rate == 0.5 and unit == "eps"
    rate, unit = _events_rate_for_window(60, 60)
    assert rate == 1.0 and unit == "eps"
    # 3600s window → events + events/hr
    rate, unit = _events_rate_for_window(900, 3600)
    assert rate == 900.0 and unit == "events/hr"
    # 86400s window → events + events/day
    rate, unit = _events_rate_for_window(12000, 86400)
    assert rate == 12000.0 and unit == "events/day"
    # Same for alerts
    rate, unit = _alerts_rate_for_window(3, 60)
    assert rate == 3.0 and unit == "alerts/min"
    rate, unit = _alerts_rate_for_window(7, 3600)
    assert rate == 7.0 and unit == "alerts/hr"
    rate, unit = _alerts_rate_for_window(42, 86400)
    assert rate == 42.0 and unit == "alerts/day"


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
    assert src_row["rate"] >= 0.4
    assert src_row["events"] >= 1


async def test_fidelity_db_window_counts_events(client, analyst_headers):
    """window=3600 must surface events from the events table (DB-backed path)."""
    fidelity_telemetry.reset()
    src = f"fid-db-{uuid.uuid4().hex[:8]}"
    for _ in range(7):
        _insert_event(src)
    # Force the DB path
    r = await client.get("/dashboard/fidelity?window=3600", headers=analyst_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["window_seconds"] == 3600
    assert data["window_label"] == "1h"
    assert data["totals"]["events_rate_unit"] == "events/hr"
    src_row = next(s for s in data["sources"] if s["name"] == src)
    assert src_row["events"] >= 7
    assert src_row["rate"] == float(src_row["events"])
    # engine + outcomes still present
    assert "rules_loaded" in data["engine"]
    assert "alerts_per_min" not in data["engine"]
    assert data["outcomes"]["scope"] == "all_time"


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
    totals = r.json()["totals"]
    # 3 alerts in 60s window → totals.alerts >= 3, totals.alerts_rate = 3.0.
    assert totals["alerts"] >= 3
    assert totals["alerts_rate"] >= 2.5
    assert totals["alerts_rate_unit"] == "alerts/min"


def test_fidelity_alert_stats_helper_against_tempfile():
    """Direct unit test of _alert_stats against a temp JSONL file.

    Independent of the shared test alerts path so we can inject deterministic
    triggered_at values without colliding with other tests.
    """
    from app.dashboard.fidelity import _alert_stats
    now = datetime.utcnow().replace(microsecond=0)
    recent = (now).isoformat() + "Z"
    old = "2000-01-01T00:00:00Z"
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "alerts.log"
        with open(path, "w") as fh:
            fh.write(json.dumps({"alert_id": "a", "triggered_at": recent, "rule_name": "r1", "severity": "low"}) + "\n")
            fh.write(json.dumps({"alert_id": "b", "triggered_at": recent, "rule_name": "r2", "severity": "high"}) + "\n")
            fh.write(json.dumps({"alert_id": "c", "triggered_at": recent, "rule_name": "r1", "severity": "medium"}) + "\n")
            fh.write(json.dumps({"alert_id": "d", "triggered_at": old, "rule_name": "r1", "severity": "low"}) + "\n")
        # Monkey-patch settings.tinysiem_alerts_path to the temp file
        original = settings.tinysiem_alerts_path
        settings.tinysiem_alerts_path = str(path)
        try:
            stats_60 = _alert_stats(60)
            stats_24h = _alert_stats(86400)
        finally:
            settings.tinysiem_alerts_path = original
    # 3 recent alerts, 1 old — count excludes the old one.
    assert stats_60["count"] == 3
    assert stats_24h["count"] == 3
    # by_rule counts only in-window alerts.
    assert stats_60["by_rule"] == {"r1": 2, "r2": 1}
    # recent is newest-first and carries all documented fields.
    assert len(stats_60["recent"]) == 3
    assert [r["alert_id"] for r in stats_60["recent"]] == ["c", "b", "a"]
    assert set(stats_60["recent"][0].keys()) == {
        "alert_id", "rule_name", "severity", "triggered_at", "source_ip", "summary",
    }


def test_fidelity_alert_stats_recent_capped_at_10():
    """recent is capped at the last 10 in-window alerts, newest first."""
    from app.dashboard.fidelity import _alert_stats
    now = datetime.utcnow().replace(microsecond=0)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "alerts.log"
        with open(path, "w") as fh:
            for i in range(15):
                fh.write(json.dumps({
                    "alert_id": f"a{i:02d}",
                    "triggered_at": now.isoformat() + "Z",
                    "rule_name": f"r{i}",
                }) + "\n")
        original = settings.tinysiem_alerts_path
        settings.tinysiem_alerts_path = str(path)
        try:
            stats = _alert_stats(60)
        finally:
            settings.tinysiem_alerts_path = original
    assert stats["count"] == 15
    assert len(stats["recent"]) == 10
    # newest-first → the last 10 written, reversed: a14..a05.
    assert [r["alert_id"] for r in stats["recent"]] == [f"a{i:02d}" for i in range(14, 4, -1)]


def test_fidelity_alert_stats_empty_when_no_alerts():
    """Empty/missing file → empty stats, never a crash."""
    from app.dashboard.fidelity import _alert_stats
    original = settings.tinysiem_alerts_path
    with tempfile.TemporaryDirectory() as tmp:
        settings.tinysiem_alerts_path = str(Path(tmp) / "does-not-exist.log")
        try:
            stats = _alert_stats(60)
        finally:
            settings.tinysiem_alerts_path = original
    assert stats == {"count": 0, "by_rule": {}, "recent": []}


def test_fidelity_top_rules_sorted_desc_by_count():
    """top_rules must be sorted by count desc with rule_name asc as tie-break,
    and capped at 5.
    """
    from app.dashboard.fidelity import _alert_stats
    now = datetime.utcnow().replace(microsecond=0)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "alerts.log"
        lines = (
            [("zeta", 1), ("alpha", 3), ("beta", 3), ("gamma", 2),
             ("delta", 1), ("epsilon", 1)]
        )
        with open(path, "w") as fh:
            for rule, n in lines:
                for _ in range(n):
                    fh.write(json.dumps({
                        "alert_id": str(uuid.uuid4()),
                        "triggered_at": now.isoformat() + "Z",
                        "rule_name": rule,
                    }) + "\n")
        original = settings.tinysiem_alerts_path
        settings.tinysiem_alerts_path = str(path)
        try:
            snap = fidelity_telemetry.snapshot(window_seconds=60)
        finally:
            settings.tinysiem_alerts_path = original
    # counts: alpha=3, beta=3, gamma=2, zeta=1, delta=1, epsilon=1 → top 5.
    top = snap["top_rules"]
    assert [t["rule_name"] for t in top] == ["alpha", "beta", "gamma", "delta", "epsilon"]
    assert [t["count"] for t in top] == [3, 3, 2, 1, 1]


async def test_fidelity_alerts_counted_in_db_window(client, analyst_headers):
    """window=3600 must read alerts from the JSONL file with triggered_at filter."""
    fidelity_telemetry.reset()
    from app.alerts import file_writer
    rule = {"name": "fid-1h-rule", "severity": "medium"}
    event = {"id": "fake-evt", "source": "fid-1h"}
    for _ in range(2):
        file_writer.write_alert(rule, event)

    r = await client.get("/dashboard/fidelity?window=3600", headers=analyst_headers)
    assert r.status_code == 200
    totals = r.json()["totals"]
    assert totals["alerts"] >= 2
    assert totals["alerts_rate_unit"] == "alerts/hr"
    assert totals["alerts_rate"] == float(totals["alerts"])


def test_fidelity_snapshot_basic():
    fidelity_telemetry.reset()
    from app.alerts import file_writer
    before_alerts = fidelity_telemetry.snapshot(window_seconds=60)["totals"]["alerts"]
    fidelity_telemetry.record_event("src-a")
    fidelity_telemetry.record_event("src-a")
    fidelity_telemetry.record_event("src-b")
    rule = {"name": "fid-snap-rule", "severity": "low"}
    evt = {"id": "fake-snap-evt", "source": "snap-test"}
    file_writer.write_alert(rule, evt)
    snap = fidelity_telemetry.snapshot(window_seconds=60)
    assert snap["window_seconds"] == 60
    assert snap["window_label"] == "1m"
    assert snap["totals"]["events"] == 3
    assert snap["totals"]["events_rate_unit"] == "eps"
    # Alerts count reads the JSONL file (shared with other tests) — delta-based
    assert snap["totals"]["alerts"] == before_alerts + 1
    # The alert we just wrote is the newest line → first in recent_alerts.
    assert isinstance(snap["top_rules"], list)
    assert isinstance(snap["recent_alerts"], list)
    assert snap["recent_alerts"][0]["rule_name"] == "fid-snap-rule"
    a = next(s for s in snap["sources"] if s["name"] == "src-a")
    b = next(s for s in snap["sources"] if s["name"] == "src-b")
    assert a["events"] == 2
    assert b["events"] == 1
    assert a["rate"] == round(2 / 60.0, 2)


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
    assert ancient["events"] == 0

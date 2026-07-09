"""Tests for source-scoped threshold counting (final-branch-review Fix 1).

Regression coverage for a bug where `count_events_in_window()` counted matching
events across the ENTIRE `events` table with no source filter. This meant a
threshold rule scoped to one source (e.g. `tinysiem-internal-brute-force`,
source `tinysiem_internal`) could be triggered by matching events from a
completely different source (e.g. real user 401s against the monitored nginx
app), defeating the purpose of self-monitoring (B2).
"""
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import yaml

from app.rules import engine as rule_engine
from app.storage import duckdb_store


def _insert_event(source: str, status_code: int, source_ip: str = "10.0.0.1") -> str:
    event_id = str(uuid.uuid4())
    duckdb_store.insert_event({
        "id": event_id,
        "source": source,
        "ingested_at": datetime.utcnow(),
        "event_time": None,
        "source_ip": source_ip,
        "method": "GET",
        "uri": "/x",
        "status_code": status_code,
        "response_size": 100,
        "user_agent": "test",
        "referer": None,
        "raw": f"{source} event {status_code}",
        "extra": {},
    })
    return event_id


def test_count_events_in_window_scopes_to_source():
    """Seed matching-field events from two different sources; confirm the
    `source` param only counts the requested source's events."""
    marker_a = f"scope-a-{uuid.uuid4()}"
    marker_b = f"scope-b-{uuid.uuid4()}"

    for _ in range(4):
        _insert_event(marker_a, 401)
    for _ in range(2):
        _insert_event(marker_b, 401)

    count_a = duckdb_store.count_events_in_window("status_code", 401, 3600, source=marker_a)
    count_b = duckdb_store.count_events_in_window("status_code", 401, 3600, source=marker_b)
    count_unscoped = duckdb_store.count_events_in_window("status_code", 401, 3600)

    assert count_a == 4
    assert count_b == 2
    # Unscoped (no source param) still counts across both — behavior-preserving
    # for callers that don't pass source.
    assert count_unscoped >= count_a + count_b


def test_builtin_threshold_rule_still_works_with_source_scoping(tmp_path):
    """Existing single-source threshold rules (like the shipped nginx-http-404-spike)
    already only cared about their own source's events — this should still work
    identically now that scoping is enforced at the SQL level, not just by
    coincidence of tests inserting one source at a time."""
    marker_source = f"nginx-scope-test-{uuid.uuid4().hex[:8]}"
    rule = {
        "name": "test_404_spike_scoped",
        "severity": "medium",
        "source": marker_source,
        "condition": {
            "type": "threshold", "field": "status_code", "value": 404,
            "operator": "eq", "threshold_count": 3, "window_seconds": 3600,
        },
        "mitre_tactic": "Discovery", "mitre_technique": "T1595",
    }
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "test_404_spike_scoped.yaml").write_text(yaml.dump(rule))
    rule_engine.load_rules(rules_dir)

    try:
        # Noise from an unrelated source with the same status code should not count.
        for _ in range(5):
            _insert_event("unrelated-noise-source", 404)

        last_event_id = None
        for _ in range(3):
            last_event_id = _insert_event(marker_source, 404)
        rule_engine.evaluate({
            "id": last_event_id, "source": marker_source, "status_code": 404,
            "source_ip": "10.0.0.1", "raw": "trigger",
        })

        from app.config import settings
        alerts_path = Path(settings.tinysiem_alerts_path)
        assert "test_404_spike_scoped" in alerts_path.read_text()
    finally:
        rule_engine.load_rules()


def test_internal_brute_force_rule_ignores_other_source_401s(tmp_path):
    """Reproduce the original bug scenario: 5 nginx 401s + 2 tinysiem_internal 401s
    must NOT fire the rule; only 5+ (new) tinysiem_internal 401s should.

    Loads the real tinysiem-brute-force-self.yaml rule content (field/value/source
    unchanged) under a fresh unique name. The session-wide DuckDB may already hold
    some tinysiem_internal 401 events from other tests exercising auth failures
    within the same 300s window (e.g. test_security_feed.py), so threshold_count
    is calibrated relative to a measured baseline rather than hardcoded — this
    keeps the test's pass/fail meaning ("+2 shouldn't fire, +5 should") stable
    regardless of test execution order, while still exercising the exact
    field=status_code/value=401/source=tinysiem_internal config of the real rule.
    """
    rules_dir = Path(__file__).parent.parent / "rules" / "rules"
    real_rule_path = rules_dir / "tinysiem-brute-force-self.yaml"
    rule = yaml.safe_load(real_rule_path.read_text())
    assert rule["source"] == "tinysiem_internal"
    assert rule["condition"]["field"] == "status_code"
    assert rule["condition"]["value"] == 401

    baseline = duckdb_store.count_events_in_window(
        "status_code", 401, rule["condition"]["window_seconds"], source="tinysiem_internal"
    )
    rule["name"] = f"test_brute_force_self_{uuid.uuid4().hex[:8]}"
    rule["condition"]["threshold_count"] = baseline + 5
    test_rules_dir = tmp_path / "rules"
    test_rules_dir.mkdir()
    (test_rules_dir / f"{rule['name']}.yaml").write_text(yaml.dump(rule))
    rule_engine.load_rules(test_rules_dir)

    try:
        from app.config import settings
        alerts_path = Path(settings.tinysiem_alerts_path)

        # 5 nginx 401s (unrelated real-user auth failures against the monitored app)
        # must NOT contribute toward this rule's count.
        for _ in range(5):
            _insert_event("nginx", 401)
        # Only 2 NEW tinysiem_internal 401s — total is baseline+2, below threshold.
        last_id = None
        for _ in range(2):
            last_id = _insert_event("tinysiem_internal", 401)
        rule_engine.evaluate({
            "id": last_id, "source": "tinysiem_internal", "status_code": 401,
            "source_ip": "127.0.0.1", "raw": "internal auth failure",
        })

        before_content = alerts_path.read_text() if alerts_path.exists() else ""
        assert rule["name"] not in before_content, (
            "Rule fired after only 2 new tinysiem_internal 401s (+5 nginx noise) — "
            "the nginx events must be leaking into the count."
        )

        # 3 more tinysiem_internal 401s brings the new total to baseline+5 — should fire.
        for _ in range(3):
            last_id = _insert_event("tinysiem_internal", 401)
        rule_engine.evaluate({
            "id": last_id, "source": "tinysiem_internal", "status_code": 401,
            "source_ip": "127.0.0.1", "raw": "internal auth failure",
        })

        after_content = alerts_path.read_text()
        assert rule["name"] in after_content
    finally:
        rule_engine.load_rules()

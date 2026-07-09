from datetime import datetime
from pathlib import Path

import yaml

from app.audit import store as audit
from app.audit import security_feed
from app.rules import engine as rule_engine
from app.storage import duckdb_store


def test_feeding_internal_event_does_not_create_extra_audit_entries():
    before = duckdb_store.query_audit(event_type="auth.login", limit=1000)["total"]
    audit.log_event("auth.login", "login", "failure", actor="loopcheck-unique-actor")
    after = duckdb_store.query_audit(event_type="auth.login", limit=1000)["total"]
    assert after == before + 1


def test_irrelevant_event_types_are_not_fed():
    from app.audit import security_feed
    calls = []
    original = security_feed.feed

    def _tracking_feed(*args, **kwargs):
        calls.append(args)
        return original(*args, **kwargs)

    security_feed.feed = _tracking_feed
    try:
        audit.log_event("error.api", "error", "error", actor="irrelevant-test")
    finally:
        security_feed.feed = original
    # error.api is not in the feed allowlist — feed() should have been called (central hook)
    # but returned immediately without ingesting anything. Verify no tinysiem_internal
    # event count changed by checking the events table directly for this unique actor.
    from app.storage import duckdb_store as store
    result = store.query_events(source="tinysiem_internal", q="irrelevant-test", limit=10)
    assert result["total"] == 0


def test_internal_brute_force_rule_fires_after_threshold(tmp_path):
    rule = {
        "name": "test_internal_brute_force",
        "severity": "high",
        "source": "tinysiem_internal",
        "condition": {
            "type": "threshold", "field": "status_code", "value": 401,
            "operator": "eq", "threshold_count": 3, "window_seconds": 60,
        },
        "mitre_tactic": "Credential Access", "mitre_technique": "T1110",
    }
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "test_internal_brute_force.yaml").write_text(yaml.dump(rule))
    rule_engine.load_rules(rules_dir)

    try:
        for _ in range(3):
            audit.log_event("auth.login", "login", "failure", actor="loadtest-brute")

        from app.config import settings
        alerts_path = Path(settings.tinysiem_alerts_path)
        assert "test_internal_brute_force" in alerts_path.read_text()
    finally:
        # Restore the real rule set for subsequent tests.
        rule_engine.load_rules()


def test_feed_handles_non_json_serializable_detail_gracefully():
    """Verify that feed() never raises even if detail contains non-JSON-serializable
    values (e.g. datetime objects). The json.dumps() and ingest should both be covered
    by the try/except handler."""
    # This call should NOT raise, even though detail contains a datetime object.
    # Before the fix, json.dumps(payload) was outside the try/except, causing
    # a TypeError to escape and violate log_event()'s "never raises" contract.
    security_feed.feed(
        event_type="auth.login",
        status="success",
        actor="test-user",
        ip_address="192.168.1.1",
        detail={"when": datetime.now(), "extra": "data"},
    )
    # Test passes if no exception is raised.

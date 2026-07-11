"""Regression test for a bug found via live browser testing: a threshold rule's
`_evaluate_rule` only checked the aggregate window count, never whether the
CURRENT event itself matched `field`/`value`. Since `evaluate()` re-runs a
threshold rule on every event from its source, once the count crossed the
threshold, the NEXT unrelated event from that source (e.g. a `user.delete`
audit action mirrored into `tinysiem_internal`) would also "fire" the rule,
stamping the alert with that unrelated event's id/source_ip — misattributing
routine activity as part of a brute-force alert.
"""
import uuid
from datetime import datetime
from pathlib import Path

import yaml

from app.rules import engine as rule_engine
from app.storage import duckdb_store


def _insert_event(source: str, status_code: int, source_ip: str) -> str:
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


def test_unrelated_event_does_not_trigger_stale_threshold(tmp_path):
    """Once a threshold is crossed by matching events, a later event that does
    NOT itself match field/value must not also fire the rule."""
    marker_source = f"match-gate-test-{uuid.uuid4().hex[:8]}"
    rule = {
        "name": f"test_match_gate_{uuid.uuid4().hex[:8]}",
        "severity": "high",
        "source": marker_source,
        "condition": {
            "type": "threshold", "field": "status_code", "value": 401,
            "operator": "eq", "threshold_count": 3, "window_seconds": 3600,
        },
        "mitre_tactic": "Credential Access", "mitre_technique": "T1110",
    }
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / f"{rule['name']}.yaml").write_text(yaml.dump(rule))
    rule_engine.load_rules(rules_dir)

    try:
        # Cross the threshold with 3 matching (401) events from source_ip A.
        last_id = None
        for _ in range(3):
            last_id = _insert_event(marker_source, 401, "10.0.0.1")
        rule_engine.evaluate({
            "id": last_id, "source": marker_source, "status_code": 401,
            "source_ip": "10.0.0.1", "raw": "trigger",
        })

        from app.config import settings
        alerts_path = Path(settings.tinysiem_alerts_path)
        assert rule["name"] in alerts_path.read_text(), "Rule should fire on the matching event"
        fired_count_after_match = alerts_path.read_text().count(rule["name"])

        # A later, UNRELATED event from the same source (e.g. a 200 response —
        # analogous to a "user.delete" audit action mirrored into the feed) must
        # NOT re-trigger the rule just because the aggregate count is still high.
        unrelated_id = _insert_event(marker_source, 200, "192.168.1.99")
        rule_engine.evaluate({
            "id": unrelated_id, "source": marker_source, "status_code": 200,
            "source_ip": "192.168.1.99", "raw": "unrelated event",
        })

        fired_count_final = alerts_path.read_text().count(rule["name"])
        assert fired_count_final == fired_count_after_match, (
            "An unrelated (non-matching) event re-fired the rule — "
            "the threshold branch is not gating on the current event's field/value"
        )
    finally:
        rule_engine.load_rules()


def test_matching_event_still_fires_normally(tmp_path):
    """Sanity check: the field-match gate must not break the normal case where
    the triggering event DOES match field/value."""
    marker_source = f"match-gate-normal-{uuid.uuid4().hex[:8]}"
    rule = {
        "name": f"test_match_gate_normal_{uuid.uuid4().hex[:8]}",
        "severity": "medium",
        "source": marker_source,
        "condition": {
            "type": "threshold", "field": "status_code", "value": 404,
            "operator": "eq", "threshold_count": 2, "window_seconds": 3600,
        },
        "mitre_tactic": "Discovery", "mitre_technique": "T1595",
    }
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / f"{rule['name']}.yaml").write_text(yaml.dump(rule))
    rule_engine.load_rules(rules_dir)

    try:
        last_id = None
        for _ in range(2):
            last_id = _insert_event(marker_source, 404, "10.0.0.5")
        rule_engine.evaluate({
            "id": last_id, "source": marker_source, "status_code": 404,
            "source_ip": "10.0.0.5", "raw": "trigger",
        })

        from app.config import settings
        alerts_path = Path(settings.tinysiem_alerts_path)
        assert rule["name"] in alerts_path.read_text()
    finally:
        rule_engine.load_rules()

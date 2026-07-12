import json
import uuid
from datetime import datetime
from pathlib import Path

import yaml

from app.rules import engine as rule_engine
from app.rules import exceptions_store
from app.storage import duckdb_store


def _insert_event(source: str, status_code: int, source_ip: str) -> str:
    event_id = str(uuid.uuid4())
    duckdb_store.insert_event({
        "id": event_id, "source": source, "ingested_at": datetime.utcnow(), "event_time": None,
        "source_ip": source_ip, "method": "GET", "uri": "/x", "status_code": status_code,
        "response_size": 100, "user_agent": "test", "referer": None,
        "raw": f"{source} {status_code}", "extra": {},
    })
    return event_id


def _alerts_text() -> str:
    from app.config import settings
    path = Path(settings.tinysiem_alerts_path)
    return path.read_text() if path.exists() else ""


def _fire_count(rule_name: str) -> int:
    """Count how many times `rule_name` actually fired an alert.

    Counting `.count(rule_name)` on the raw file text is unreliable: each
    alert's default summary is `f"Rule '{rule.get('name')}' triggered on
    event {event_id}"` (see app/alerts/file_writer.py), which embeds the
    rule name a SECOND time in the same JSON line as the `rule_name` field
    itself. A plain substring count therefore counts 2 per single fire, not
    1. Match the `"rule_name": "<name>"` JSON key/value pair instead, which
    appears exactly once per fired alert.
    """
    return _alerts_text().count(f'"rule_name": "{rule_name}"')


def test_excepted_event_skipped_for_field_match_rule():
    marker_source = f"exc-fm-{uuid.uuid4().hex[:8]}"
    rule = {
        "name": f"exc-fm-rule-{uuid.uuid4().hex[:8]}", "severity": "high", "source": marker_source,
        "condition": {"type": "field_match", "field": "status_code", "value": 500, "operator": "eq"},
        "mitre_tactic": "Impact", "mitre_technique": "T1499",
    }
    rules_dir_files = []
    import tempfile
    tmp_path = Path(tempfile.mkdtemp())
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / f"{rule['name']}.yaml").write_text(yaml.dump(rule))
    rule_engine.load_rules(rules_dir)
    try:
        exceptions_store.add_exception(rule["name"], "source_ip", "9.9.9.9", "known false positive", "tester")
        rule_engine.load_exceptions()

        before = _fire_count(rule["name"])
        event_id = _insert_event(marker_source, 500, "9.9.9.9")
        rule_engine.evaluate({"id": event_id, "source": marker_source, "status_code": 500, "source_ip": "9.9.9.9", "raw": "x"})
        after = _fire_count(rule["name"])
        assert after == before, "excepted event must not fire the rule"

        # sanity: a non-excepted IP still fires
        event_id2 = _insert_event(marker_source, 500, "1.1.1.1")
        rule_engine.evaluate({"id": event_id2, "source": marker_source, "status_code": 500, "source_ip": "1.1.1.1", "raw": "x"})
        after2 = _fire_count(rule["name"])
        assert after2 == before + 1
    finally:
        rule_engine.load_rules()
        rule_engine.load_exceptions()


def test_excepted_event_excluded_from_threshold_counting():
    marker_source = f"exc-th-{uuid.uuid4().hex[:8]}"
    rule = {
        "name": f"exc-th-rule-{uuid.uuid4().hex[:8]}", "severity": "high", "source": marker_source,
        "condition": {
            "type": "threshold", "field": "status_code", "value": 401, "operator": "eq",
            "threshold_count": 2, "window_seconds": 3600,
        },
        "mitre_tactic": "Credential Access", "mitre_technique": "T1110",
    }
    import tempfile
    tmp_path = Path(tempfile.mkdtemp())
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / f"{rule['name']}.yaml").write_text(yaml.dump(rule))
    rule_engine.load_rules(rules_dir)
    try:
        exceptions_store.add_exception(rule["name"], "source_ip", "9.9.9.9", "noisy known-good scanner", "tester")
        rule_engine.load_exceptions()

        before = _fire_count(rule["name"])
        # 2 events from the excepted IP — must not count toward the threshold at all
        for _ in range(2):
            eid = _insert_event(marker_source, 401, "9.9.9.9")
            rule_engine.evaluate({"id": eid, "source": marker_source, "status_code": 401, "source_ip": "9.9.9.9", "raw": "x"})
        after_excepted = _fire_count(rule["name"])
        assert after_excepted == before, "excepted events must not fire the rule themselves"

        # A single non-excepted event should NOT reach threshold_count=2 on its own,
        # proving the excepted events above were truly excluded from the aggregate.
        eid2 = _insert_event(marker_source, 401, "1.1.1.1")
        rule_engine.evaluate({"id": eid2, "source": marker_source, "status_code": 401, "source_ip": "1.1.1.1", "raw": "x"})
        after_one_real = _fire_count(rule["name"])
        assert after_one_real == before, "one real event must not reach threshold_count=2 alone"

        # A second non-excepted event crosses the threshold using only real events.
        eid3 = _insert_event(marker_source, 401, "1.1.1.1")
        rule_engine.evaluate({"id": eid3, "source": marker_source, "status_code": 401, "source_ip": "1.1.1.1", "raw": "x"})
        after_two_real = _fire_count(rule["name"])
        assert after_two_real == before + 1
    finally:
        rule_engine.load_rules()
        rule_engine.load_exceptions()


def _insert_event_full(source: str, status_code: int, method: str = "GET", referer=None) -> str:
    event_id = str(uuid.uuid4())
    duckdb_store.insert_event({
        "id": event_id, "source": source, "ingested_at": datetime.utcnow(), "event_time": None,
        "source_ip": "10.0.0.1", "method": method, "uri": "/x", "status_code": status_code,
        "response_size": 100, "user_agent": "test", "referer": referer,
        "raw": f"{source} {status_code}", "extra": {},
    })
    return event_id


def test_count_events_in_window_exclude_is_null_safe():
    """Whole-branch review Finding 2: `count_events_in_window`'s exclude clause
    used `AND NOT (exc_field = ?)`. Under SQL three-valued logic, a row where
    exc_field IS NULL makes `exc_field = ?` evaluate to NULL, and `NOT NULL` is
    ALSO NULL (not TRUE) — so that row was silently dropped from COUNT(*), even
    though it never matched the excepted value. This proves the `IS DISTINCT
    FROM` fix: NULL-field events must still count, only the genuinely-matching
    value must be excluded."""
    marker_source = f"nullsafe-{uuid.uuid4().hex[:8]}"

    # 2 events with referer matching the exception value -> must be excluded.
    _insert_event_full(marker_source, 200, referer="https://excepted.example")
    _insert_event_full(marker_source, 200, referer="https://excepted.example")
    # 2 events with referer NULL -> must NOT be excluded (still counted).
    _insert_event_full(marker_source, 200, referer=None)
    _insert_event_full(marker_source, 200, referer=None)
    # 2 events with a different, non-excepted, non-NULL referer -> still counted.
    _insert_event_full(marker_source, 200, referer="https://other.example")
    _insert_event_full(marker_source, 200, referer="https://other.example")

    count = duckdb_store.count_events_in_window(
        "status_code", 200, 3600, source=marker_source,
        exclude=[("referer", "https://excepted.example")],
    )
    assert count == 4, (
        "NULL-referer and other-referer events must still count; only the "
        "2 events with the excepted referer value should be dropped"
    )


def test_count_events_in_window_exclude_coerces_integer_column():
    """Additional coverage per whole-branch reviewer: exceptions on a genuinely
    INTEGER-typed column (status_code) must still exclude via DuckDB's implicit
    VARCHAR->INTEGER coercion, since rule_exceptions.value is always stored as
    VARCHAR regardless of the excepted field's underlying column type."""
    marker_source = f"intcoerce-{uuid.uuid4().hex[:8]}"

    _insert_event_full(marker_source, 404, method="GET")
    _insert_event_full(marker_source, 404, method="GET")
    _insert_event_full(marker_source, 500, method="GET")

    count = duckdb_store.count_events_in_window(
        "method", "GET", 3600, source=marker_source,
        exclude=[("status_code", "404")],
    )
    assert count == 1, "the 2 status_code=404 events must be excluded via VARCHAR->INTEGER coercion"

import json
from pathlib import Path

import yaml

from app.rules import engine as rule_engine


def _make_threshold_rule(tmp_path: Path, suppress_seconds=None):
    rule = {
        "name": "test_suppress_rule",
        "severity": "high",
        "source": "nginx",
        "condition": {"type": "field_match", "field": "status_code", "value": 500, "operator": "eq"},
        "mitre_tactic": "Impact",
        "mitre_technique": "T1499",
    }
    if suppress_seconds is not None:
        rule["suppress_seconds"] = suppress_seconds
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(exist_ok=True)
    (rules_dir / "test_suppress_rule.yaml").write_text(yaml.dump(rule))
    return rules_dir


def test_default_suppress_seconds_threshold_is_300():
    rule = {"name": "x", "condition": {"type": "threshold"}}
    assert rule_engine._default_suppress_seconds(rule) == 300


def test_default_suppress_seconds_field_match_is_0():
    rule = {"name": "x", "condition": {"type": "field_match"}}
    assert rule_engine._default_suppress_seconds(rule) == 0


def _alerts_for(rule_name: str, source_ip: str) -> list[dict]:
    """Parse the shared alerts.log and return only entries for this exact
    (rule_name, source_ip) pair. The alerts file is a single session-wide
    JSONL file (see conftest.py), so a plain substring count would double-count
    (rule_name appears both in "rule_name" and embedded in "summary") and
    would also pick up entries left behind by other tests in this module that
    reuse the same rule name against a different source_ip. Filtering on both
    fields keeps each test's assertions scoped to its own events."""
    from app.config import settings

    alerts_path = Path(settings.tinysiem_alerts_path)
    if not alerts_path.exists():
        return []
    entries = [json.loads(line) for line in alerts_path.read_text().splitlines() if line.strip()]
    return [
        e for e in entries
        if e.get("rule_name") == rule_name and e.get("source_ip") == source_ip
    ]


def test_repeated_firing_suppressed_within_window(tmp_path):
    rules_dir = _make_threshold_rule(tmp_path, suppress_seconds=60)
    rule_engine.load_rules(rules_dir)
    rule_engine.reset_suppression_state()

    event = {"id": "e1", "source": "nginx", "status_code": 500, "source_ip": "9.9.9.9", "raw": "x"}
    rule_engine.evaluate(event)
    rule_engine.evaluate({**event, "id": "e2"})
    rule_engine.evaluate({**event, "id": "e3"})

    assert len(_alerts_for("test_suppress_rule", "9.9.9.9")) == 1


def test_alert_fires_again_after_window_elapses_with_suppressed_count(tmp_path, monkeypatch):
    rules_dir = _make_threshold_rule(tmp_path, suppress_seconds=60)
    rule_engine.load_rules(rules_dir)
    rule_engine.reset_suppression_state()

    fake_time = [1000.0]
    monkeypatch.setattr(rule_engine.time, "monotonic", lambda: fake_time[0])

    event = {"id": "e1", "source": "nginx", "status_code": 500, "source_ip": "8.8.8.8", "raw": "x"}
    rule_engine.evaluate(event)
    rule_engine.evaluate({**event, "id": "e2"})
    rule_engine.evaluate({**event, "id": "e3"})

    fake_time[0] += 61

    rule_engine.evaluate({**event, "id": "e4"})

    alerts = _alerts_for("test_suppress_rule", "8.8.8.8")
    assert len(alerts) == 2
    assert alerts[0]["suppressed_count"] == 0
    assert alerts[1]["suppressed_count"] == 2


def test_suppress_seconds_zero_disables_suppression(tmp_path):
    rules_dir = _make_threshold_rule(tmp_path, suppress_seconds=0)
    rule_engine.load_rules(rules_dir)
    rule_engine.reset_suppression_state()

    event = {"id": "e1", "source": "nginx", "status_code": 500, "source_ip": "7.7.7.7", "raw": "x"}
    rule_engine.evaluate(event)
    rule_engine.evaluate({**event, "id": "e2"})

    assert len(_alerts_for("test_suppress_rule", "7.7.7.7")) == 2

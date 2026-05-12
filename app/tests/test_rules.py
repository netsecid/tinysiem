import json
from pathlib import Path

import pytest
import yaml

from app.rules import engine as rule_engine


def _make_rule(tmp_path: Path, condition: dict, **kwargs) -> Path:
    rule = {
        "name": kwargs.get("name", "test_rule"),
        "description": "test",
        "severity": kwargs.get("severity", "high"),
        "source": "nginx",
        "condition": condition,
        "mitre_tactic": "Impact",
        "mitre_technique": "T1499",
    }
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(exist_ok=True)
    rule_file = rules_dir / f"{rule['name']}.yaml"
    rule_file.write_text(yaml.dump(rule))
    return rules_dir


def test_field_match_rule_triggers_on_matching_event(tmp_path):
    rules_dir = _make_rule(
        tmp_path,
        name="test_500_match",
        condition={"type": "field_match", "field": "status_code", "value": 500, "operator": "eq"},
    )
    rule_engine.load_rules(rules_dir)

    event = {
        "id": "evt-test-001",
        "source": "nginx",
        "status_code": 500,
        "source_ip": "1.2.3.4",
        "raw": "fake log line",
    }

    rule_engine.evaluate(event)

    from app.config import settings
    alerts_path = Path(settings.tinysiem_alerts_path)
    assert alerts_path.exists(), "Alert file was not created"
    alerts = [json.loads(line) for line in alerts_path.read_text().splitlines() if line.strip()]
    assert any(a["rule_name"] == "test_500_match" for a in alerts)


def test_field_match_rule_does_not_trigger_on_mismatch(tmp_path):
    rules_dir = _make_rule(
        tmp_path,
        name="test_200_no_trigger",
        condition={"type": "field_match", "field": "status_code", "value": 500, "operator": "eq"},
    )
    rule_engine.load_rules(rules_dir)

    from app.config import settings
    alerts_path = Path(settings.tinysiem_alerts_path)
    initial_count = 0
    if alerts_path.exists():
        initial_count = alerts_path.read_text().count("test_200_no_trigger")

    event = {
        "id": "evt-test-002",
        "source": "nginx",
        "status_code": 200,
        "source_ip": "1.2.3.4",
        "raw": "fake log line",
    }
    rule_engine.evaluate(event)

    final_count = 0
    if alerts_path.exists():
        final_count = alerts_path.read_text().count("test_200_no_trigger")
    assert final_count == initial_count


def test_operator_contains(tmp_path):
    rules_dir = _make_rule(
        tmp_path,
        name="test_ua_contains",
        condition={"type": "field_match", "field": "user_agent", "value": "sqlmap", "operator": "contains"},
    )
    rule_engine.load_rules(rules_dir)

    event = {
        "id": "evt-test-003",
        "source": "nginx",
        "status_code": 200,
        "user_agent": "sqlmap/1.7",
        "source_ip": "5.5.5.5",
        "raw": "fake log line",
    }
    rule_engine.evaluate(event)

    from app.config import settings
    alerts_path = Path(settings.tinysiem_alerts_path)
    assert alerts_path.exists()
    content = alerts_path.read_text()
    assert "test_ua_contains" in content


def test_unknown_source_skips_rule(tmp_path):
    rules_dir = _make_rule(
        tmp_path,
        name="test_skip_source",
        condition={"type": "field_match", "field": "status_code", "value": 500, "operator": "eq"},
    )
    rule_engine.load_rules(rules_dir)

    from app.config import settings
    alerts_path = Path(settings.tinysiem_alerts_path)
    initial = alerts_path.read_text() if alerts_path.exists() else ""

    event = {
        "id": "evt-test-004",
        "source": "windows",  # doesn't match rule source 'nginx'
        "status_code": 500,
        "raw": "some windows log",
    }
    rule_engine.evaluate(event)

    after = alerts_path.read_text() if alerts_path.exists() else ""
    assert after.count("test_skip_source") == initial.count("test_skip_source")

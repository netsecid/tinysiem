"""Tests for correlation rule type in the rules engine."""
import pytest

from app.rules import engine as rule_engine
from app.rules.engine import reset_corr_state


CORR_RULE = {
    "name": "test-brute-force",
    "severity": "high",
    "source": "*",
    "condition": {
        "type": "correlation",
        "window_seconds": 300,
        "capture_field": "source_ip",
        "steps": [
            {"source": "nginx", "field": "status_code", "value": "401", "operator": "eq"},
            {"source": "nginx", "field": "status_code", "value": "200", "operator": "eq"},
        ],
    },
    "mitre_tactic": "Credential Access",
    "mitre_technique": "T1110",
}


@pytest.fixture(autouse=True)
def _clear_state():
    reset_corr_state()
    yield
    reset_corr_state()


@pytest.fixture
def loaded_rules(tmp_path):
    """Load only the correlation rule for tests."""
    import yaml
    rule_file = tmp_path / "test-corr.yaml"
    rule_file.write_text(yaml.dump(CORR_RULE))
    rule_engine.load_rules(tmp_path)
    yield
    rule_engine._rules.clear()


def _event(status_code, source_ip="1.2.3.4", source="nginx"):
    return {
        "id": "test-id",
        "source": source,
        "source_ip": source_ip,
        "status_code": status_code,
        "raw": f"test raw status={status_code}",
    }


def test_step1_alone_does_not_fire(loaded_rules, tmp_path):
    alerts = []
    with __import__("unittest.mock", fromlist=["patch"]).patch(
        "app.alerts.file_writer.write_alert", side_effect=lambda r, e: alerts.append(r)
    ):
        rule_engine.evaluate(_event(401))
    assert len(alerts) == 0


def test_sequence_fires_on_step2(loaded_rules):
    alerts = []
    with __import__("unittest.mock", fromlist=["patch"]).patch(
        "app.alerts.file_writer.write_alert", side_effect=lambda r, e: alerts.append(r)
    ):
        rule_engine.evaluate(_event(401))
        rule_engine.evaluate(_event(200))
    assert len(alerts) == 1
    assert alerts[0]["name"] == "test-brute-force"


def test_step2_before_step1_does_not_fire(loaded_rules):
    alerts = []
    with __import__("unittest.mock", fromlist=["patch"]).patch(
        "app.alerts.file_writer.write_alert", side_effect=lambda r, e: alerts.append(r)
    ):
        rule_engine.evaluate(_event(200))
        rule_engine.evaluate(_event(401))
    assert len(alerts) == 0


def test_different_ips_tracked_independently(loaded_rules):
    alerts = []
    with __import__("unittest.mock", fromlist=["patch"]).patch(
        "app.alerts.file_writer.write_alert", side_effect=lambda r, e: alerts.append(r)
    ):
        rule_engine.evaluate(_event(401, source_ip="1.1.1.1"))
        rule_engine.evaluate(_event(401, source_ip="2.2.2.2"))
        rule_engine.evaluate(_event(200, source_ip="1.1.1.1"))
    assert len(alerts) == 1


def test_wrong_source_in_step_does_not_advance(loaded_rules):
    alerts = []
    with __import__("unittest.mock", fromlist=["patch"]).patch(
        "app.alerts.file_writer.write_alert", side_effect=lambda r, e: alerts.append(r)
    ):
        rule_engine.evaluate(_event(401, source="nginx"))
        rule_engine.evaluate(_event(200, source="apache"))  # wrong source
    assert len(alerts) == 0


def test_correlation_resets_after_firing(loaded_rules):
    alerts = []
    with __import__("unittest.mock", fromlist=["patch"]).patch(
        "app.alerts.file_writer.write_alert", side_effect=lambda r, e: alerts.append(r)
    ):
        rule_engine.evaluate(_event(401))
        rule_engine.evaluate(_event(200))
        # First sequence fires
        assert len(alerts) == 1
        # Second sequence can fire independently
        rule_engine.evaluate(_event(401))
        rule_engine.evaluate(_event(200))
    assert len(alerts) == 2


def test_expired_step1_does_not_fire(loaded_rules):
    from datetime import datetime, timezone, timedelta

    alerts = []
    with __import__("unittest.mock", fromlist=["patch"]).patch(
        "app.alerts.file_writer.write_alert", side_effect=lambda r, e: alerts.append(r)
    ):
        rule_engine.evaluate(_event(401))
        # Manually expire the state entry
        rule_name = CORR_RULE["name"]
        if rule_name in rule_engine._corr_state:
            for k in rule_engine._corr_state[rule_name]:
                rule_engine._corr_state[rule_name][k]["triggered_at"] = (
                    datetime.now(timezone.utc) - timedelta(seconds=400)
                )
        # Step 2 arrives after window expires → should not fire
        rule_engine.evaluate(_event(200))
    assert len(alerts) == 0


async def test_correlation_via_ingest_api(client, admin_headers, loaded_rules):
    """Integration: correlation fires when using ingest API."""
    alerts = []
    with __import__("unittest.mock", fromlist=["patch"]).patch(
        "app.alerts.file_writer.write_alert", side_effect=lambda r, e: alerts.append(r)
    ):
        payload1 = {
            "source": "nginx",
            "raw": '10.0.0.1 - - [15/Jan/2024:10:00:00 +0000] "GET /login HTTP/1.1" 401 0 "-" "-"',
        }
        payload2 = {
            "source": "nginx",
            "raw": '10.0.0.1 - - [15/Jan/2024:10:00:01 +0000] "GET /dashboard HTTP/1.1" 200 512 "-" "-"',
        }
        resp1 = await client.post("/ingest/raw", json=payload1, headers=admin_headers)
        resp2 = await client.post("/ingest/raw", json=payload2, headers=admin_headers)
        assert resp1.status_code == 200
        assert resp2.status_code == 200
    assert len(alerts) == 1

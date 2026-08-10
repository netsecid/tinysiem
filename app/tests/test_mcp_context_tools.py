"""Tests for MCP context-assembly tools (app/mcp_server/server.py)."""
import uuid
from datetime import datetime, timezone

from app.alerts import file_writer
from app.mcp_server.server import build_alert_context, build_ip_context
from app.storage import duckdb_store


def _insert_event(source_ip=None, method=None, source="test_src", raw="raw line"):
    event = {
        "id": str(uuid.uuid4()),
        "source": source,
        "ingested_at": datetime.now(timezone.utc),
        "raw": raw,
        "extra": {},
    }
    if source_ip:
        event["source_ip"] = source_ip
    if method:
        event["method"] = method
    duckdb_store.insert_event(event)
    return event


async def test_build_ip_context_summary():
    ip = "203.0.113.99"
    _insert_event(source_ip=ip, method="Failed password")
    _insert_event(source_ip=ip, method="Failed password")
    _insert_event(source_ip=ip, method="Accepted password")

    ctx = build_ip_context(ip, days=7)
    assert ctx["ip"] == ip
    assert ctx["total_events"] == 3
    assert ctx["first_seen"] is not None
    assert ctx["last_seen"] is not None
    # no alerts/cases exist for this IP in the test env
    assert ctx["related_alerts"] == []
    assert ctx["related_cases"] == []


async def test_build_alert_context_full():
    from app.rules import engine as rule_engine
    # Other tests (test_alert_suppression, test_rule_exceptions_engine) reload
    # _rules from temp dirs without restoring — restore the repo's default set
    # so the playbook lookup below is deterministic.
    rule_engine.load_rules()

    event = _insert_event(source_ip="203.0.113.77", method="Failed password")
    rule = {
        "name": "ssh-bruteforce",  # real rule loaded by conftest (has playbook)
        "severity": "high",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110",
    }
    file_writer.write_alert(rule, event)

    from app.alerts.router import read_all_alerts
    alert = next(a for a in read_all_alerts() if a.get("event_id") == event["id"])

    ctx = build_alert_context(alert["alert_id"])
    assert ctx["alert"]["alert_id"] == alert["alert_id"]
    assert ctx["event"]["id"] == event["id"]
    assert ctx["event"]["source_ip"] == "203.0.113.77"
    assert ctx["cases"] == []
    # rule found in loaded rules → MITRE + playbook attached
    assert ctx["rule"]["name"] == "ssh-bruteforce"
    assert ctx["rule"]["mitre_technique"] == "T1110"
    assert "playbook" in ctx["rule"]
    # ip_summary assembled from events table
    assert ctx["ip_summary"]["total_events"] >= 1


async def test_build_alert_context_not_found():
    ctx = build_alert_context("does-not-exist")
    assert ctx["error"] == "alert not found"

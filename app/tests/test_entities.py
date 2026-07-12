import uuid
from datetime import datetime

from app.storage import duckdb_store


def _insert_event(ip: str, method="GET", uri="/", status=200) -> str:
    event_id = str(uuid.uuid4())
    duckdb_store.insert_event({
        "id": event_id,
        "source": "nginx",
        "ingested_at": datetime.utcnow(),
        "event_time": None,
        "source_ip": ip,
        "method": method,
        "uri": uri,
        "status_code": status,
        "response_size": 100,
        "user_agent": "test-agent",
        "referer": None,
        "raw": "test",
        "extra": {},
    })
    return event_id


async def test_entity_ip_summary(client, analyst_headers):
    ip = f"192.0.2.{uuid.uuid4().int % 200 + 1}"
    _insert_event(ip, method="GET", uri="/a", status=200)
    _insert_event(ip, method="POST", uri="/b", status=404)
    _insert_event(ip, method="GET", uri="/a", status=200)

    r = await client.get(f"/entities/ip/{ip}", headers=analyst_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["ip"] == ip
    assert data["total_events"] == 3
    assert data["first_seen"] is not None
    assert data["last_seen"] is not None
    methods = {m["value"]: m["count"] for m in data["top_methods"]}
    assert methods["GET"] == 2
    assert methods["POST"] == 1
    uris = {u["value"]: u["count"] for u in data["top_uris"]}
    assert uris["/a"] == 2
    assert "related_alerts" in data
    assert "related_cases" in data
    assert "histogram" in data


async def test_entity_ip_summary_unknown_ip_returns_zero_events(client, analyst_headers):
    r = await client.get("/entities/ip/203.0.113.250", headers=analyst_headers)
    assert r.status_code == 200
    assert r.json()["total_events"] == 0
    assert r.json()["first_seen"] is None


async def test_entity_ip_summary_requires_auth(client):
    r = await client.get("/entities/ip/192.0.2.1")
    assert r.status_code == 401


async def test_entity_ip_caps_case_lookups_to_50_alerts(client, analyst_headers, monkeypatch):
    """Regression test for N+1 case lookups: ensure case_store.get_cases_for_alert
    is called at most 50 times even when more than 50 alerts exist for the IP."""
    import json
    from pathlib import Path
    from datetime import datetime, timezone
    from app.config import settings
    from app.alerts.file_writer import write_alert

    ip = f"192.0.2.{uuid.uuid4().int % 200 + 1}"

    # Insert 60 alerts for the same IP
    alerts_path = Path(settings.tinysiem_alerts_path)
    for i in range(60):
        alert_data = {
            "alert_id": str(uuid.uuid4()),
            "triggered_at": datetime.now(timezone.utc).isoformat(),
            "rule_name": f"test_rule_{i % 5}",
            "severity": "medium",
            "mitre_tactic": "Discovery",
            "mitre_technique": "T1595",
            "event_id": str(uuid.uuid4()),
            "source_ip": ip,
            "suppressed_count": 0,
            "summary": f"Test alert {i}",
        }
        alerts_path.parent.mkdir(parents=True, exist_ok=True)
        with open(alerts_path, "a") as f:
            f.write(json.dumps(alert_data) + "\n")

    # Track calls to get_cases_for_alert
    from app.cases import store as case_store
    original_get_cases = case_store.get_cases_for_alert
    call_count = [0]

    def mock_get_cases(alert_id: str):
        call_count[0] += 1
        return original_get_cases(alert_id)

    monkeypatch.setattr(case_store, "get_cases_for_alert", mock_get_cases)

    # Call the endpoint
    r = await client.get(f"/entities/ip/{ip}", headers=analyst_headers)
    assert r.status_code == 200

    data = r.json()
    # Verify response contains at most 50 alerts
    assert len(data["related_alerts"]) <= 50
    # Verify we only called get_cases_for_alert up to 50 times (the response slice size)
    # Allow some tolerance for edge cases, but should be <= 50
    assert call_count[0] <= 50, f"Expected at most 50 case lookups, got {call_count[0]}"

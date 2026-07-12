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

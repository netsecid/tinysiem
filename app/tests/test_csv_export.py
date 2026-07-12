import csv
import io
import uuid
from datetime import datetime

from app.storage import duckdb_store


def _insert_event(source_ip: str, raw: str) -> str:
    event_id = str(uuid.uuid4())
    duckdb_store.insert_event({
        "id": event_id, "source": "nginx", "ingested_at": datetime.utcnow(), "event_time": None,
        "source_ip": source_ip, "method": "GET", "uri": "/x", "status_code": 200,
        "response_size": 100, "user_agent": "test", "referer": None, "raw": raw, "extra": {},
    })
    return event_id


async def test_events_csv_export_honors_filters(client, analyst_headers):
    ip = f"198.51.100.{uuid.uuid4().int % 200 + 1}"
    _insert_event(ip, "plain line")
    _insert_event("10.0.0.1", "different ip, should be excluded")

    r = await client.get(f"/events?source_ip={ip}&format=csv", headers=analyst_headers)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert len(rows) == 1
    assert rows[0]["source_ip"] == ip


async def test_events_csv_export_quotes_special_characters(client, analyst_headers):
    tricky_raw = 'contains, a comma and "a quote" and\na newline'
    ip = f"198.51.100.{uuid.uuid4().int % 200 + 1}"
    _insert_event(ip, tricky_raw)

    r = await client.get(f"/events?source_ip={ip}&format=csv", headers=analyst_headers)
    assert r.status_code == 200
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert rows[0]["raw"] == tricky_raw


async def test_alerts_csv_export(client, analyst_headers):
    r = await client.get("/alerts?format=csv", headers=analyst_headers)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    # header row must be present even with zero matching alerts
    reader = csv.reader(io.StringIO(r.text))
    header = next(reader)
    assert "alert_id" in header
    assert "rule_name" in header


async def test_events_csv_export_row_cap_enforced(client, analyst_headers, monkeypatch):
    from app.events import router as events_router
    monkeypatch.setattr(events_router, "_CSV_EXPORT_CAP", 2)
    marker_source = f"csv-cap-{uuid.uuid4().hex[:8]}"
    for _ in range(4):
        event_id = str(uuid.uuid4())
        duckdb_store.insert_event({
            "id": event_id, "source": marker_source, "ingested_at": datetime.utcnow(), "event_time": None,
            "source_ip": "10.0.0.1", "method": "GET", "uri": "/x", "status_code": 200,
            "response_size": 100, "user_agent": "test", "referer": None, "raw": "row", "extra": {},
        })
    r = await client.get(f"/events?source={marker_source}&format=csv", headers=analyst_headers)
    assert r.status_code == 200
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert len(rows) == 2

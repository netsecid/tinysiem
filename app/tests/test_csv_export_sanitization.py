import csv
import io
import uuid
from datetime import datetime

from app.storage import duckdb_store
from app.storage.csv_export import rows_to_csv


def _insert_event(source_ip: str, raw: str) -> str:
    event_id = str(uuid.uuid4())
    duckdb_store.insert_event({
        "id": event_id, "source": "nginx", "ingested_at": datetime.utcnow(), "event_time": None,
        "source_ip": source_ip, "method": "GET", "uri": "/x", "status_code": 200,
        "response_size": 100, "user_agent": "test", "referer": None, "raw": raw, "extra": {},
    })
    return event_id


# --- Unit tests for the shared helper ---

def test_rows_to_csv_prefixes_formula_like_values():
    rows = [{"a": "=1+1", "b": "plain"}]
    text = rows_to_csv(rows, ["a", "b"])
    reader = list(csv.DictReader(io.StringIO(text)))
    assert reader[0]["a"] == "'=1+1"
    assert reader[0]["b"] == "plain"


def test_rows_to_csv_leaves_normal_values_unchanged():
    rows = [{"a": "GET /index.html HTTP/1.1 200", "b": "10.0.0.1"}]
    text = rows_to_csv(rows, ["a", "b"])
    reader = list(csv.DictReader(io.StringIO(text)))
    assert reader[0]["a"] == "GET /index.html HTTP/1.1 200"
    assert reader[0]["b"] == "10.0.0.1"


def test_rows_to_csv_sanitizes_all_trigger_characters():
    rows = [{
        "plus": "+cmd|'/c calc'!A1",
        "minus": "-2+3",
        "at": "@SUM(1+1)",
        "tab": "\tdanger",
        "cr": "\rdanger",
        "eq": "=cmd|'/c calc'!A1",
    }]
    fieldnames = ["plus", "minus", "at", "tab", "cr", "eq"]
    text = rows_to_csv(rows, fieldnames)
    reader = list(csv.DictReader(io.StringIO(text)))
    row = reader[0]
    assert row["plus"] == "'+cmd|'/c calc'!A1"
    assert row["minus"] == "'-2+3"
    assert row["at"] == "'@SUM(1+1)"
    assert row["tab"] == "'\tdanger"
    assert row["cr"] == "'\rdanger"
    assert row["eq"] == "'=cmd|'/c calc'!A1"


def test_rows_to_csv_only_sanitizes_strings_not_other_types():
    rows = [{"n": 42, "none": None, "b": True}]
    text = rows_to_csv(rows, ["n", "none", "b"])
    reader = list(csv.DictReader(io.StringIO(text)))
    assert reader[0]["n"] == "42"
    assert reader[0]["none"] == ""
    assert reader[0]["b"] == "True"


# --- Integration tests through the /events export endpoint ---

async def test_events_csv_export_sanitizes_formula_injection(client, analyst_headers):
    ip = f"198.51.100.{uuid.uuid4().int % 200 + 1}"
    _insert_event(ip, "=1+1")

    r = await client.get(f"/events?source_ip={ip}&format=csv", headers=analyst_headers)
    assert r.status_code == 200
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert len(rows) == 1
    assert rows[0]["raw"] == "'=1+1"


async def test_events_csv_export_plain_value_unchanged(client, analyst_headers):
    ip = f"198.51.100.{uuid.uuid4().int % 200 + 1}"
    plain = 'GET /index.html HTTP/1.1" 200 512 "-" "curl/8.0"'
    _insert_event(ip, plain)

    r = await client.get(f"/events?source_ip={ip}&format=csv", headers=analyst_headers)
    assert r.status_code == 200
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert len(rows) == 1
    assert rows[0]["raw"] == plain


async def test_events_csv_export_sanitizes_other_trigger_characters(client, analyst_headers):
    # Fixed disjoint last octets OUTSIDE the 1-200 range other tests in this
    # file draw from (source_ip filtering is a LIKE substring match, so even
    # "198.51.100.3" can match "198.51.100.30" from another test).
    ip, ip2, ip3 = "198.51.100.250", "198.51.100.251", "198.51.100.252"
    _insert_event(ip, "+cmd exec")
    _insert_event(ip2, "-cmd exec")
    _insert_event(ip3, "@cmd exec")

    for ip_val, expected in ((ip, "'+cmd exec"), (ip2, "'-cmd exec"), (ip3, "'@cmd exec")):
        r = await client.get(f"/events?source_ip={ip_val}&format=csv", headers=analyst_headers)
        assert r.status_code == 200
        rows = list(csv.DictReader(io.StringIO(r.text)))
        assert len(rows) == 1
        assert rows[0]["raw"] == expected

"""Tests for the read-only SQL sandbox (app/query/router.py)."""
import json

import pytest

from app.query.router import validate_read_only, strip_comments


# ── validate_read_only unit tests ────────────────────────────────────────────

@pytest.mark.parametrize("sql", [
    "SELECT * FROM events",
    "select source, count(*) from events group by source",
    "WITH x AS (SELECT 1) SELECT * FROM x",
    "SHOW TABLES",
    "DESCRIBE events",
    "EXPLAIN SELECT 1",
    "VALUES (1, 2)",
    "/* comment */ SELECT 1",
    "-- line comment\nSELECT 1",
])
def test_valid_read_only(sql):
    validate_read_only(sql)  # must not raise


@pytest.mark.parametrize("sql", [
    "INSERT INTO events (id) VALUES ('x')",
    "UPDATE events SET method = 'GET'",
    "DELETE FROM events",
    "DROP TABLE events",
    "CREATE TABLE evil (x INT)",
    "ALTER TABLE events ADD COLUMN x INT",
    "COPY events TO '/tmp/x.csv'",
    "ATTACH '/tmp/evil.db'",
    "PRAGMA database_list",
    "SELECT 1; SELECT 2",
    "SELECT 'a'; DROP TABLE events",
    "  ",
    "",
])
def test_invalid_statements_rejected(sql):
    with pytest.raises(Exception):
        validate_read_only(sql)


def test_comment_strip_bypass_blocked():
    # Comment-stripping happens before the keyword check.
    validate_read_only("/* DROP */ SELECT 1")  # allowed: DROP is inside comment
    # A trailing -- comment neutralizes anything after it — safe, not a bypass.
    validate_read_only("SELECT 1 -- DROP TABLE events; SELECT 2")
    # Real bypass attempts: second statement on a new line (no ;) is caught by
    # the blocked-keyword scan; with ; it's caught by the multi-statement gate.
    with pytest.raises(Exception):
        validate_read_only("SELECT 1\nDROP TABLE events")
    with pytest.raises(Exception):
        validate_read_only("SELECT 1; SELECT 2 -- DROP")


def test_strip_comments():
    assert strip_comments("SELECT 1 -- hi").strip() == "SELECT 1"
    stripped = strip_comments("/* a */ SELECT /* b */ 1")
    assert "/*" not in stripped
    assert " ".join(stripped.split()) == "SELECT 1"


# ── Endpoint tests ───────────────────────────────────────────────────────────

async def test_sql_requires_auth(client):
    resp = await client.post("/query/sql", json={"query": "SELECT 1"})
    assert resp.status_code == 401


async def test_sql_select_ok(client, analyst_headers):
    resp = await client.post("/query/sql", json={"query": "SELECT 1 AS one"}, headers=analyst_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["columns"] == ["one"]
    assert body["rows"] == [[1]]
    assert body["total_rows"] == 1
    assert body["truncated"] is False
    assert "duration_ms" in body


async def test_sql_blocked_keyword(client, analyst_headers):
    resp = await client.post("/query/sql", json={"query": "DROP TABLE events"}, headers=analyst_headers)
    assert resp.status_code == 422


async def test_sql_multi_statement(client, analyst_headers):
    resp = await client.post("/query/sql", json={"query": "SELECT 1; SELECT 2"}, headers=analyst_headers)
    assert resp.status_code == 422


async def test_sql_row_cap(client, analyst_headers):
    from datetime import datetime, timezone
    import uuid
    from app.storage import duckdb_store

    src = f"test_rowcap_{uuid.uuid4().hex[:8]}"  # unique source: DB is shared across test files
    for i in range(5):
        duckdb_store.insert_event({
            "id": str(uuid.uuid4()),
            "source": src,
            "ingested_at": datetime.now(timezone.utc),
            "raw": f"line {i}",
            "extra": {},
        })

    resp = await client.post(
        "/query/sql",
        json={"query": f"SELECT raw FROM events WHERE source = '{src}' ORDER BY raw", "max_rows": 2},
        headers=analyst_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["rows"]) == 2
    assert body["total_rows"] == 5
    assert body["truncated"] is True


async def test_sql_cell_truncation(client, analyst_headers):
    resp = await client.post(
        "/query/sql",
        json={"query": "SELECT 'x' || repeat('y', 600) AS big"},
        headers=analyst_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["rows"][0][0]) == 500


async def test_sql_audited(client, analyst_headers):
    from app.audit import store as audit_store
    from app.storage import duckdb_store

    def _count():
        return duckdb_store.query_audit(event_type="query.sql").get("total", 0)

    before = _count()
    resp = await client.post("/query/sql", json={"query": "SELECT 42"}, headers=analyst_headers)
    assert resp.status_code == 200
    assert _count() == before + 1


async def test_sql_response_serializable(client, analyst_headers):
    resp = await client.post(
        "/query/sql",
        json={"query": "SELECT CAST('2026-08-01' AS DATE) AS d, x'deadbeef' AS b"},
        headers=analyst_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "columns" in body and "rows" in body
    json.dumps(body)  # must serialize

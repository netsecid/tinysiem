import json
import logging
import threading
from datetime import datetime, timezone
from typing import Optional

import duckdb

from app.config import settings

logger = logging.getLogger(__name__)

_conn: Optional[duckdb.DuckDBPyConnection] = None
_lock = threading.Lock()

_ALLOWED_FIELDS = {
    "source", "source_ip", "method", "uri",
    "status_code", "response_size", "user_agent", "referer",
}


def init_db(path: Optional[str] = None) -> None:
    global _conn
    db_path = path or settings.tinysiem_duckdb_path
    _conn = duckdb.connect(db_path)
    with _lock:
        _conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id              VARCHAR PRIMARY KEY,
                source          VARCHAR NOT NULL,
                ingested_at     TIMESTAMP NOT NULL,
                event_time      TIMESTAMP,
                source_ip       VARCHAR,
                method          VARCHAR,
                uri             VARCHAR,
                status_code     INTEGER,
                response_size   INTEGER,
                user_agent      VARCHAR,
                referer         VARCHAR,
                raw             VARCHAR NOT NULL,
                extra           JSON
            )
        """)
        _conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ingested_at ON events (ingested_at)"
        )
        _conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_source_ip ON events (source_ip)"
        )


def close_db() -> None:
    global _conn
    if _conn is not None:
        _conn.close()
        _conn = None


def _get_conn() -> duckdb.DuckDBPyConnection:
    if _conn is None:
        raise RuntimeError("Database not initialized — call init_db() first")
    return _conn


def insert_event(event: dict) -> None:
    conn = _get_conn()
    ingested_at = event.get("ingested_at", datetime.now(timezone.utc))
    # Strip tzinfo — DuckDB TIMESTAMP has no tz
    if hasattr(ingested_at, "tzinfo") and ingested_at.tzinfo is not None:
        ingested_at = ingested_at.replace(tzinfo=None)

    event_time = event.get("event_time")
    if event_time and hasattr(event_time, "tzinfo") and event_time.tzinfo is not None:
        event_time = event_time.replace(tzinfo=None)

    extra = event.get("extra") or {}
    extra_json = json.dumps(extra)

    with _lock:
        conn.execute(
            """
            INSERT INTO events
                (id, source, ingested_at, event_time, source_ip, method, uri,
                 status_code, response_size, user_agent, referer, raw, extra)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                event.get("id"),
                event.get("source"),
                ingested_at,
                event_time,
                event.get("source_ip"),
                event.get("method"),
                event.get("uri"),
                event.get("status_code"),
                event.get("response_size"),
                event.get("user_agent"),
                event.get("referer"),
                event.get("raw"),
                extra_json,
            ],
        )


def count_events_in_window(field: str, value, window_seconds: int) -> int:
    if field not in _ALLOWED_FIELDS:
        raise ValueError(f"Field '{field}' not permitted in threshold queries")

    conn = _get_conn()
    since_ts = datetime.utcnow().timestamp() - window_seconds

    with _lock:
        result = conn.execute(
            f"SELECT COUNT(*) FROM events WHERE {field} = ? AND epoch(ingested_at) >= ?",
            [value, since_ts],
        ).fetchone()

    return result[0] if result else 0

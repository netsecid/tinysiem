import json
import logging
import threading
from datetime import datetime, timedelta, timezone
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
        _conn.execute("CREATE INDEX IF NOT EXISTS idx_ingested_at ON events (ingested_at)")
        _conn.execute("CREATE INDEX IF NOT EXISTS idx_source_ip ON events (source_ip)")


def close_db() -> None:
    global _conn
    if _conn is not None:
        _conn.close()
        _conn = None


def _get_conn() -> duckdb.DuckDBPyConnection:
    if _conn is None:
        raise RuntimeError("Database not initialized — call init_db() first")
    return _conn


def _build_where(
    source: Optional[str] = None,
    source_ip: Optional[str] = None,
    status_code: Optional[int] = None,
    status_min: Optional[int] = None,
    status_max: Optional[int] = None,
    method: Optional[str] = None,
    uri: Optional[str] = None,
    q: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> tuple[str, list]:
    conditions: list[str] = []
    params: list = []

    if source:
        conditions.append("source = ?")
        params.append(source)
    if source_ip:
        conditions.append("source_ip LIKE ?")
        params.append(f"%{source_ip}%")
    if status_code is not None:
        conditions.append("status_code = ?")
        params.append(status_code)
    if status_min is not None:
        conditions.append("status_code >= ?")
        params.append(status_min)
    if status_max is not None:
        conditions.append("status_code <= ?")
        params.append(status_max)
    if method:
        conditions.append("UPPER(method) = UPPER(?)")
        params.append(method)
    if uri:
        conditions.append("uri ILIKE ?")
        params.append(f"%{uri}%")
    if q:
        conditions.append("raw ILIKE ?")
        params.append(f"%{q}%")
    if start:
        s = start.replace(tzinfo=None) if start.tzinfo else start
        conditions.append("ingested_at >= ?")
        params.append(s)
    if end:
        e = end.replace(tzinfo=None) if end.tzinfo else end
        conditions.append("ingested_at <= ?")
        params.append(e)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    return where, params


def insert_event(event: dict) -> None:
    conn = _get_conn()
    ingested_at = event.get("ingested_at", datetime.now(timezone.utc))
    if hasattr(ingested_at, "tzinfo") and ingested_at.tzinfo is not None:
        ingested_at = ingested_at.replace(tzinfo=None)

    event_time = event.get("event_time")
    if event_time and hasattr(event_time, "tzinfo") and event_time.tzinfo is not None:
        event_time = event_time.replace(tzinfo=None)

    extra_json = json.dumps(event.get("extra") or {})

    with _lock:
        conn.execute(
            """
            INSERT INTO events
                (id, source, ingested_at, event_time, source_ip, method, uri,
                 status_code, response_size, user_agent, referer, raw, extra)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                event.get("id"), event.get("source"), ingested_at, event_time,
                event.get("source_ip"), event.get("method"), event.get("uri"),
                event.get("status_code"), event.get("response_size"),
                event.get("user_agent"), event.get("referer"),
                event.get("raw"), extra_json,
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


def query_events(
    limit: int = 100,
    offset: int = 0,
    source: Optional[str] = None,
    source_ip: Optional[str] = None,
    status_code: Optional[int] = None,
    status_min: Optional[int] = None,
    status_max: Optional[int] = None,
    method: Optional[str] = None,
    uri: Optional[str] = None,
    q: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> dict:
    conn = _get_conn()
    where, params = _build_where(
        source=source, source_ip=source_ip,
        status_code=status_code, status_min=status_min, status_max=status_max,
        method=method, uri=uri, q=q, start=start, end=end,
    )

    with _lock:
        total = conn.execute(f"SELECT COUNT(*) FROM events {where}", params).fetchone()[0]
        rows = conn.execute(
            f"""SELECT id, source, ingested_at, event_time, source_ip, method, uri,
                       status_code, response_size, user_agent, referer, raw, extra
                FROM events {where}
                ORDER BY ingested_at DESC
                LIMIT ? OFFSET ?""",
            params + [limit, offset],
        ).fetchall()

    columns = [
        "id", "source", "ingested_at", "event_time", "source_ip", "method",
        "uri", "status_code", "response_size", "user_agent", "referer", "raw", "extra",
    ]
    events = []
    for row in rows:
        ev = dict(zip(columns, row))
        for f in ("ingested_at", "event_time"):
            if ev[f] is not None:
                ev[f] = ev[f].isoformat()
        events.append(ev)

    return {"total": total, "events": events}


def get_event_facets(
    source: Optional[str] = None,
    source_ip: Optional[str] = None,
    status_code: Optional[int] = None,
    status_min: Optional[int] = None,
    status_max: Optional[int] = None,
    method: Optional[str] = None,
    uri: Optional[str] = None,
    q: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> dict:
    conn = _get_conn()
    where, params = _build_where(
        source=source, source_ip=source_ip,
        status_code=status_code, status_min=status_min, status_max=status_max,
        method=method, uri=uri, q=q, start=start, end=end,
    )
    # Helpers for appending a NULL-check condition
    and_or_where = "AND" if where else "WHERE"

    with _lock:
        source_rows = conn.execute(
            f"SELECT source, COUNT(*) FROM events {where} {and_or_where} source IS NOT NULL "
            f"GROUP BY source ORDER BY COUNT(*) DESC LIMIT 20",
            params,
        ).fetchall()

        method_rows = conn.execute(
            f"SELECT method, COUNT(*) FROM events {where} {and_or_where} method IS NOT NULL "
            f"GROUP BY method ORDER BY COUNT(*) DESC LIMIT 10",
            params,
        ).fetchall()

        status_rows = conn.execute(
            f"""SELECT
                CASE WHEN status_code >= 500 THEN '5xx'
                     WHEN status_code >= 400 THEN '4xx'
                     WHEN status_code >= 300 THEN '3xx'
                     WHEN status_code >= 200 THEN '2xx'
                     WHEN status_code >= 100 THEN '1xx'
                     ELSE 'no status'
                END AS cls,
                COUNT(*) AS cnt
                FROM events {where}
                GROUP BY cls ORDER BY cnt DESC""",
            params,
        ).fetchall()

        ip_rows = conn.execute(
            f"SELECT source_ip, COUNT(*) FROM events {where} {and_or_where} source_ip IS NOT NULL "
            f"GROUP BY source_ip ORDER BY COUNT(*) DESC LIMIT 12",
            params,
        ).fetchall()

    return {
        "source":       [{"value": r[0], "count": r[1]} for r in source_rows],
        "method":       [{"value": r[0], "count": r[1]} for r in method_rows],
        "status_class": [{"value": r[0], "count": r[1]} for r in status_rows],
        "source_ip":    [{"value": r[0], "count": r[1]} for r in ip_rows],
    }


def get_event_histogram(start: datetime, end: datetime, buckets: int = 60) -> list:
    conn = _get_conn()
    duration = max(1, (end - start).total_seconds())
    bucket_size = max(1, int(duration / buckets))
    start_n = start.replace(tzinfo=None) if start.tzinfo else start
    end_n   = end.replace(tzinfo=None)   if end.tzinfo   else end

    with _lock:
        rows = conn.execute(
            """SELECT CAST(epoch(ingested_at) / ? AS BIGINT) * ? AS ts, COUNT(*) AS cnt
               FROM events WHERE ingested_at >= ? AND ingested_at <= ?
               GROUP BY ts ORDER BY ts""",
            [bucket_size, bucket_size, start_n, end_n],
        ).fetchall()

    return [{"ts": int(r[0]) * 1000, "count": r[1]} for r in rows]

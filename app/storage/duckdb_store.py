import json
import logging
import threading
import uuid
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
        _conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            VARCHAR PRIMARY KEY,
                username      VARCHAR UNIQUE NOT NULL,
                password_hash VARCHAR NOT NULL,
                role          VARCHAR NOT NULL,
                created_at    TIMESTAMP NOT NULL,
                must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
                token_epoch   INTEGER NOT NULL DEFAULT 0
            )
        """)
        # Migrate pre-v1.4 databases: CREATE TABLE IF NOT EXISTS above is a no-op when
        # the table already exists, so older deployments need these columns added explicitly.
        # Note: DuckDB 1.1.3 raises "Adding columns with constraints not yet supported" for
        # ALTER TABLE ... ADD COLUMN with a NOT NULL constraint (with or without DEFAULT), so
        # these ALTERs omit NOT NULL. DEFAULT alone still backfills existing rows (verified:
        # existing rows get FALSE / 0, not NULL), and every code path that writes these columns
        # (create_user, update_user, bump_token_epoch, change_own_password) always supplies an
        # explicit value, so the missing NOT NULL constraint has no practical effect.
        _existing_cols = {row[1] for row in _conn.execute("PRAGMA table_info('users')").fetchall()}
        if "must_change_password" not in _existing_cols:
            _conn.execute("ALTER TABLE users ADD COLUMN must_change_password BOOLEAN DEFAULT FALSE")
        if "token_epoch" not in _existing_cols:
            _conn.execute("ALTER TABLE users ADD COLUMN token_epoch INTEGER DEFAULT 0")


def close_db() -> None:
    global _conn
    if _conn is not None:
        _conn.close()
        _conn = None


def _get_conn() -> duckdb.DuckDBPyConnection:
    if _conn is None:
        raise RuntimeError("Database not initialized — call init_db() first")
    return _conn


def _escape_like(val: str) -> str:
    """Escape SQL LIKE/ILIKE metacharacters so user input is treated literally."""
    return val.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


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
        conditions.append("source_ip LIKE ? ESCAPE '\\'")
        params.append(f"%{_escape_like(source_ip)}%")
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
        conditions.append("uri ILIKE ? ESCAPE '\\'")
        params.append(f"%{_escape_like(uri)}%")
    if q:
        conditions.append("raw ILIKE ? ESCAPE '\\'")
        params.append(f"%{_escape_like(q)}%")
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
    start_n = start.replace(tzinfo=None) if start.tzinfo else start
    end_n   = end.replace(tzinfo=None)   if end.tzinfo   else end
    duration = max(1, (end_n - start_n).total_seconds())
    bucket_size = max(1, int(duration / buckets))

    with _lock:
        rows = conn.execute(
            """SELECT CAST(epoch(ingested_at) / ? AS BIGINT) * ? AS ts, COUNT(*) AS cnt
               FROM events WHERE ingested_at >= ? AND ingested_at <= ?
               GROUP BY ts ORDER BY ts""",
            [bucket_size, bucket_size, start_n, end_n],
        ).fetchall()

    return [{"ts": int(r[0]) * 1000, "count": r[1]} for r in rows]


# ── Alert triage store ────────────────────────────────────────────────────────

def init_alert_triage_table() -> None:
    with _lock:
        _conn.execute("""
            CREATE TABLE IF NOT EXISTS alert_triage (
                alert_id    VARCHAR PRIMARY KEY,
                status      VARCHAR NOT NULL DEFAULT 'open',
                notes       TEXT    NOT NULL DEFAULT '',
                assigned_to VARCHAR NOT NULL DEFAULT '',
                updated_at  TIMESTAMP,
                updated_by  VARCHAR NOT NULL DEFAULT ''
            )
        """)


def get_triage_map() -> dict:
    with _lock:
        rows = _conn.execute(
            "SELECT alert_id, status, notes, assigned_to, updated_at, updated_by FROM alert_triage"
        ).fetchall()
    return {
        row[0]: {
            "status": row[1],
            "notes": row[2],
            "assigned_to": row[3],
            "updated_at": row[4].isoformat() if row[4] else None,
            "updated_by": row[5],
        }
        for row in rows
    }


def upsert_triage(alert_id: str, status: str, notes: str, assigned_to: str, updated_by: str) -> None:
    with _lock:
        _conn.execute("""
            INSERT INTO alert_triage (alert_id, status, notes, assigned_to, updated_at, updated_by)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (alert_id) DO UPDATE SET
                status = excluded.status,
                notes = excluded.notes,
                assigned_to = excluded.assigned_to,
                updated_at = excluded.updated_at,
                updated_by = excluded.updated_by
        """, [alert_id, status, notes, assigned_to, datetime.utcnow(), updated_by])


def query_events_for_archive(cutoff: datetime, limit: int = 5000) -> list[dict]:
    with _lock:
        rows = _conn.execute(
            "SELECT id, source, ingested_at, event_time, source_ip, method, uri, "
            "status_code, response_size, user_agent, referer, raw, extra "
            "FROM events WHERE ingested_at < ? ORDER BY ingested_at LIMIT ?",
            [cutoff, limit]
        ).fetchall()
    cols = ["id", "source", "ingested_at", "event_time", "source_ip", "method",
            "uri", "status_code", "response_size", "user_agent", "referer", "raw", "extra"]
    result = []
    for row in rows:
        d = dict(zip(cols, row))
        for f in ("ingested_at", "event_time"):
            if d[f] is not None and hasattr(d[f], "isoformat"):
                d[f] = d[f].isoformat()
        result.append(d)
    return result


def delete_events_by_ids(ids: list[str]) -> int:
    if not ids:
        return 0
    placeholders = ",".join("?" * len(ids))
    with _lock:
        _conn.execute(f"DELETE FROM events WHERE id IN ({placeholders})", ids)
    return len(ids)


def count_all_events() -> int:
    with _lock:
        return _conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]


def count_events_in_window_range(start: datetime, end: datetime) -> int:
    s = start.replace(tzinfo=None) if start.tzinfo else start
    e = end.replace(tzinfo=None) if end.tzinfo else end
    with _lock:
        return _conn.execute(
            "SELECT COUNT(*) FROM events WHERE ingested_at >= ? AND ingested_at <= ?",
            [s, e]
        ).fetchone()[0]


# ── User store ────────────────────────────────────────────────────────────────

def _user_row_to_dict(row: tuple, include_hash: bool = False) -> dict:
    base = {
        "id": row[0],
        "username": row[1],
        "role": row[3],
        "created_at": row[4].isoformat() if hasattr(row[4], "isoformat") else str(row[4]),
        "must_change_password": bool(row[5]),
        "token_epoch": row[6],
    }
    if include_hash:
        base["password_hash"] = row[2]
    return base


def create_user(username: str, password_hash: str, role: str, must_change_password: bool = False) -> dict:
    user_id = str(uuid.uuid4())
    now = datetime.utcnow()
    with _lock:
        _get_conn().execute(
            "INSERT INTO users (id, username, password_hash, role, created_at, must_change_password, token_epoch) "
            "VALUES (?, ?, ?, ?, ?, ?, 0)",
            [user_id, username, password_hash, role, now, must_change_password],
        )
    return {
        "id": user_id, "username": username, "role": role, "created_at": now.isoformat(),
        "must_change_password": must_change_password, "token_epoch": 0,
    }


def get_user_by_username(username: str) -> dict | None:
    with _lock:
        row = _get_conn().execute(
            "SELECT id, username, password_hash, role, created_at, must_change_password, token_epoch "
            "FROM users WHERE username = ?",
            [username],
        ).fetchone()
    return _user_row_to_dict(row, include_hash=True) if row else None


def get_user_by_id(user_id: str) -> dict | None:
    with _lock:
        row = _get_conn().execute(
            "SELECT id, username, password_hash, role, created_at, must_change_password, token_epoch "
            "FROM users WHERE id = ?",
            [user_id],
        ).fetchone()
    return _user_row_to_dict(row, include_hash=True) if row else None


def list_users() -> list[dict]:
    with _lock:
        rows = _get_conn().execute(
            "SELECT id, username, password_hash, role, created_at, must_change_password, token_epoch "
            "FROM users ORDER BY created_at"
        ).fetchall()
    return [_user_row_to_dict(r) for r in rows]


def update_user(
    user_id: str,
    username: str = None,
    password_hash: str = None,
    role: str = None,
) -> dict | None:
    # Fetch full row first (includes password_hash and created_at raw value)
    with _lock:
        row = _get_conn().execute(
            "SELECT id, username, password_hash, role, created_at, must_change_password, token_epoch "
            "FROM users WHERE id = ?",
            [user_id],
        ).fetchone()
    if row is None:
        return None
    new_username = username if username is not None else row[1]
    new_role = role if role is not None else row[3]
    new_hash = password_hash if password_hash is not None else row[2]
    created_at = row[4]
    must_change_password = row[5]
    token_epoch = row[6] + 1  # any superadmin-driven update revokes the user's existing sessions
    # DuckDB 1.1.x has an ART index bug that raises spurious duplicate-key errors
    # on UPDATE for tables with primary keys; DELETE + INSERT is the safe workaround.
    with _lock:
        conn = _get_conn()
        conn.execute("DELETE FROM users WHERE id=?", [user_id])
        conn.execute(
            "INSERT INTO users (id, username, password_hash, role, created_at, must_change_password, token_epoch) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [user_id, new_username, new_hash, new_role, created_at, must_change_password, token_epoch],
        )
    return get_user_by_id(user_id)


def bump_token_epoch(user_id: str) -> dict | None:
    """Revoke a user's existing tokens by incrementing their epoch (DELETE+INSERT — see update_user)."""
    with _lock:
        row = _get_conn().execute(
            "SELECT id, username, password_hash, role, created_at, must_change_password, token_epoch "
            "FROM users WHERE id = ?",
            [user_id],
        ).fetchone()
    if row is None:
        return None
    with _lock:
        conn = _get_conn()
        conn.execute("DELETE FROM users WHERE id=?", [user_id])
        conn.execute(
            "INSERT INTO users (id, username, password_hash, role, created_at, must_change_password, token_epoch) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [row[0], row[1], row[2], row[3], row[4], row[5], row[6] + 1],
        )
    return get_user_by_id(user_id)


def change_own_password(user_id: str, new_password_hash: str) -> dict | None:
    """Self-service password change: clears must_change_password and bumps token_epoch."""
    with _lock:
        row = _get_conn().execute(
            "SELECT id, username, password_hash, role, created_at, must_change_password, token_epoch "
            "FROM users WHERE id = ?",
            [user_id],
        ).fetchone()
    if row is None:
        return None
    with _lock:
        conn = _get_conn()
        conn.execute("DELETE FROM users WHERE id=?", [user_id])
        conn.execute(
            "INSERT INTO users (id, username, password_hash, role, created_at, must_change_password, token_epoch) "
            "VALUES (?, ?, ?, ?, ?, FALSE, ?)",
            [row[0], row[1], new_password_hash, row[3], row[4], row[6] + 1],
        )
    return get_user_by_id(user_id)


def delete_user(user_id: str) -> bool:
    if get_user_by_id(user_id) is None:
        return False
    with _lock:
        _get_conn().execute("DELETE FROM users WHERE id=?", [user_id])
    return True


def count_superadmins() -> int:
    with _lock:
        result = _get_conn().execute(
            "SELECT COUNT(*) FROM users WHERE role='superadmin'"
        ).fetchone()
    return result[0] if result else 0


def ensure_superadmin(password_hash: str) -> None:
    """Create 'admin' superadmin if no users exist yet."""
    with _lock:
        count = _get_conn().execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count == 0:
        create_user("admin", password_hash, "superadmin")
        logger.info("Created initial superadmin user 'admin'")


# ── Audit log ─────────────────────────────────────────────────────────────────

def init_audit_table() -> None:
    with _lock:
        _conn.execute("""CREATE TABLE IF NOT EXISTS audit_log (
            id            VARCHAR PRIMARY KEY,
            ts            TIMESTAMP NOT NULL,
            event_type    VARCHAR NOT NULL,
            actor         VARCHAR NOT NULL DEFAULT 'system',
            actor_role    VARCHAR,
            resource_type VARCHAR,
            resource_id   VARCHAR,
            action        VARCHAR NOT NULL,
            status        VARCHAR NOT NULL,
            detail        JSON,
            ip_address    VARCHAR,
            duration_ms   INTEGER,
            error_msg     VARCHAR
        )""")
        _conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)")
        _conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor)")
        _conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_log(event_type)")


def insert_audit_event(row: dict) -> None:
    ts = row["ts"]
    if hasattr(ts, "tzinfo") and ts.tzinfo:
        ts = ts.replace(tzinfo=None)
    with _lock:
        _conn.execute(
            "INSERT INTO audit_log (id,ts,event_type,actor,actor_role,resource_type,"
            "resource_id,action,status,detail,ip_address,duration_ms,error_msg) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [row["id"], ts, row["event_type"], row["actor"],
             row.get("actor_role"), row.get("resource_type"), row.get("resource_id"),
             row["action"], row["status"], row.get("detail"),
             row.get("ip_address"), row.get("duration_ms"), row.get("error_msg")],
        )


def query_audit(
    event_type: Optional[str] = None,
    actor: Optional[str] = None,
    resource_type: Optional[str] = None,
    action: Optional[str] = None,
    status: Optional[str] = None,
    q: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    conditions: list[str] = []
    params: list = []
    if event_type:
        conditions.append("event_type = ?")
        params.append(event_type)
    if actor:
        conditions.append("actor = ?")
        params.append(actor)
    if resource_type:
        conditions.append("resource_type = ?")
        params.append(resource_type)
    if action:
        conditions.append("action = ?")
        params.append(action)
    if status:
        conditions.append("status = ?")
        params.append(status)
    if q:
        like = f"%{_escape_like(q)}%"
        conditions.append(
            "(actor ILIKE ? ESCAPE '\\' OR event_type ILIKE ? ESCAPE '\\' OR CAST(detail AS VARCHAR) ILIKE ? ESCAPE '\\')"
        )
        params += [like, like, like]
    if start:
        s = start.replace(tzinfo=None) if start.tzinfo else start
        conditions.append("ts >= ?")
        params.append(s)
    if end:
        e = end.replace(tzinfo=None) if end.tzinfo else end
        conditions.append("ts <= ?")
        params.append(e)
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    cols = ["id", "ts", "event_type", "actor", "actor_role", "resource_type",
            "resource_id", "action", "status", "detail", "ip_address", "duration_ms", "error_msg"]
    with _lock:
        total = _conn.execute(
            f"SELECT COUNT(*) FROM audit_log {where}", params
        ).fetchone()[0]
        rows = _conn.execute(
            f"SELECT {','.join(cols)} FROM audit_log {where} "
            "ORDER BY ts DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
    items = []
    for row in rows:
        d = dict(zip(cols, row))
        if d["ts"] and hasattr(d["ts"], "isoformat"):
            d["ts"] = d["ts"].isoformat() + "Z"
        if isinstance(d.get("detail"), str):
            try:
                d["detail"] = json.loads(d["detail"])
            except Exception:
                pass
        items.append(d)
    return {"total": total, "items": items}


# ── Cases ─────────────────────────────────────────────────────────────────────

def init_cases_tables() -> None:
    with _lock:
        _conn.execute("""CREATE TABLE IF NOT EXISTS cases (
            case_id         VARCHAR PRIMARY KEY,
            title           VARCHAR NOT NULL,
            description     VARCHAR,
            severity        VARCHAR NOT NULL DEFAULT 'medium',
            status          VARCHAR NOT NULL DEFAULT 'open',
            resolution      VARCHAR,
            assignee        VARCHAR,
            created_by      VARCHAR NOT NULL,
            created_at      TIMESTAMP NOT NULL,
            updated_at      TIMESTAMP NOT NULL,
            closed_at       TIMESTAMP,
            mitre_tactic    VARCHAR,
            mitre_technique VARCHAR,
            tags            JSON
        )""")
        # Note: no secondary indexes on cases — DuckDB 1.1.x UPDATE fails when a table
        # has a PRIMARY KEY + any secondary ART index (known bug). Filter queries use
        # table scans which are fast enough at this scale.
        _conn.execute("""CREATE TABLE IF NOT EXISTS case_alerts (
            case_id     VARCHAR NOT NULL,
            alert_id    VARCHAR NOT NULL,
            linked_at   TIMESTAMP NOT NULL,
            linked_by   VARCHAR NOT NULL,
            PRIMARY KEY (case_id, alert_id)
        )""")
        _conn.execute("""CREATE TABLE IF NOT EXISTS case_comments (
            comment_id  VARCHAR PRIMARY KEY,
            case_id     VARCHAR NOT NULL,
            author      VARCHAR NOT NULL,
            body        VARCHAR NOT NULL,
            created_at  TIMESTAMP NOT NULL,
            edited_at   TIMESTAMP,
            is_system   BOOLEAN NOT NULL DEFAULT FALSE
        )""")
        _conn.execute("CREATE INDEX IF NOT EXISTS idx_comments_case ON case_comments(case_id)")


# ── Log Sources ────────────────────────────────────────────────────────────────

_ACTIVE_MINUTES = 30
_STALE_HOURS = 24


def query_source_activity() -> list[dict]:
    with _lock:
        rows = _conn.execute("""
            SELECT
                source,
                COUNT(*) AS total,
                MAX(ingested_at) AS last_seen,
                MIN(ingested_at) AS first_seen,
                COUNT(*) FILTER (WHERE ingested_at > (CURRENT_TIMESTAMP - INTERVAL '24 hours')) AS cnt_24h,
                COUNT(*) FILTER (WHERE ingested_at > (CURRENT_TIMESTAMP - INTERVAL '1 hour'))  AS cnt_1h
            FROM events
            GROUP BY source
            ORDER BY last_seen DESC
        """).fetchall()
    now = datetime.utcnow()
    result = []
    for row in rows:
        source, total, last_seen, first_seen, cnt_24h, cnt_1h = row
        if last_seen:
            delta = (now - last_seen).total_seconds()
            if delta < _ACTIVE_MINUTES * 60:
                status = "active"
            elif delta < _STALE_HOURS * 3600:
                status = "stale"
            else:
                status = "silent"
        else:
            status = "silent"
        result.append({
            "source": source,
            "status": status,
            "last_seen": last_seen.isoformat() + "Z" if last_seen else None,
            "first_seen": first_seen.isoformat() + "Z" if first_seen else None,
            "event_count_total": total,
            "event_count_24h": cnt_24h or 0,
            "event_count_1h": cnt_1h or 0,
        })
    return result


def get_event_sources() -> list[str]:
    with _lock:
        rows = _get_conn().execute(
            "SELECT DISTINCT source FROM events WHERE source IS NOT NULL ORDER BY source"
        ).fetchall()
    return [r[0] for r in rows]


def get_event_by_id(event_id: str) -> Optional[dict]:
    with _lock:
        row = _get_conn().execute(
            "SELECT id, source, ingested_at, source_ip, method, uri, status_code, raw, extra "
            "FROM events WHERE id = ?",
            [event_id],
        ).fetchone()
    if not row:
        return None
    cols = ["id", "source", "ingested_at", "source_ip", "method", "uri", "status_code", "raw", "extra"]
    d = dict(zip(cols, row))
    if d.get("ingested_at") and hasattr(d["ingested_at"], "isoformat"):
        d["ingested_at"] = d["ingested_at"].isoformat()
    return d


def get_events_by_ids(event_ids: list[str]) -> list[dict]:
    if not event_ids:
        return []
    placeholders = ",".join("?" * len(event_ids))
    with _lock:
        rows = _get_conn().execute(
            f"SELECT id, source, ingested_at, source_ip, method, uri, status_code, raw, extra "
            f"FROM events WHERE id IN ({placeholders})",
            event_ids,
        ).fetchall()
    cols = ["id", "source", "ingested_at", "source_ip", "method", "uri", "status_code", "raw", "extra"]
    result = []
    for row in rows:
        d = dict(zip(cols, row))
        if d.get("ingested_at") and hasattr(d["ingested_at"], "isoformat"):
            d["ingested_at"] = d["ingested_at"].isoformat()
        result.append(d)
    return result


# ── Baselines ─────────────────────────────────────────────────────────────────

def init_baselines_tables() -> None:
    with _lock:
        # No secondary indexes — see CLAUDE.md re DuckDB 1.1.x UPDATE + ART index bug.
        _conn.execute("""CREATE TABLE IF NOT EXISTS baselines (
            source          VARCHAR NOT NULL,
            hour_of_day     INTEGER NOT NULL,
            day_of_week     INTEGER NOT NULL,
            mean            DOUBLE NOT NULL DEFAULT 0.0,
            std_dev         DOUBLE NOT NULL DEFAULT 0.0,
            m2              DOUBLE NOT NULL DEFAULT 0.0,
            sample_count    INTEGER NOT NULL DEFAULT 0,
            last_updated    TIMESTAMP NOT NULL,
            PRIMARY KEY (source, hour_of_day, day_of_week)
        )""")
        _conn.execute("""CREATE TABLE IF NOT EXISTS baseline_violations (
            violation_id    VARCHAR PRIMARY KEY,
            source          VARCHAR NOT NULL,
            detected_at     TIMESTAMP NOT NULL,
            hour_of_day     INTEGER NOT NULL,
            day_of_week     INTEGER NOT NULL,
            observed_count  DOUBLE NOT NULL,
            expected_mean   DOUBLE NOT NULL,
            expected_std    DOUBLE NOT NULL,
            z_score         DOUBLE NOT NULL,
            severity        VARCHAR NOT NULL,
            acknowledged    BOOLEAN NOT NULL DEFAULT FALSE
        )""")


def init_integrations_tables() -> None:
    with _lock:
        # No CREATE INDEX — DuckDB 1.1.x UPDATE fails with PRIMARY KEY + secondary ART index.
        _conn.execute("""CREATE TABLE IF NOT EXISTS integrations (
            integration_id   VARCHAR PRIMARY KEY,
            name             VARCHAR NOT NULL,
            integration_type VARCHAR NOT NULL,
            enabled          BOOLEAN NOT NULL DEFAULT TRUE,
            config           JSON NOT NULL,
            credentials      JSON NOT NULL,
            schedule_minutes INTEGER NOT NULL DEFAULT 15,
            created_by       VARCHAR NOT NULL,
            created_at       TIMESTAMP NOT NULL,
            updated_at       TIMESTAMP NOT NULL,
            last_run_at      TIMESTAMP,
            last_run_status  VARCHAR
        )""")
        _conn.execute("""CREATE TABLE IF NOT EXISTS integration_runs (
            run_id           VARCHAR PRIMARY KEY,
            integration_id   VARCHAR NOT NULL,
            started_at       TIMESTAMP NOT NULL,
            finished_at      TIMESTAMP,
            status           VARCHAR NOT NULL,
            events_pulled    INTEGER NOT NULL DEFAULT 0,
            events_ingested  INTEGER NOT NULL DEFAULT 0,
            error_message    VARCHAR,
            next_cursor      VARCHAR
        )""")


def init_dashboard_tables() -> None:
    with _lock:
        # No UNIQUE on owner — avoids DuckDB 1.1.x UPDATE bug; upsert uses DELETE+INSERT.
        _conn.execute("""CREATE TABLE IF NOT EXISTS dashboards (
            dashboard_id VARCHAR PRIMARY KEY,
            owner        VARCHAR NOT NULL,
            title        VARCHAR NOT NULL DEFAULT 'My Dashboard',
            widgets      JSON NOT NULL,
            created_at   TIMESTAMP NOT NULL,
            updated_at   TIMESTAMP NOT NULL
        )""")


def init_playbook_table() -> None:
    with _lock:
        # No CREATE INDEX — DuckDB 1.1.3 UPDATE + PRIMARY KEY + secondary index bug.
        _conn.execute("""
            CREATE TABLE IF NOT EXISTS case_playbook_steps (
                id           VARCHAR PRIMARY KEY,
                case_id      VARCHAR NOT NULL,
                rule_name    VARCHAR NOT NULL,
                step_id      VARCHAR NOT NULL,
                completed_by VARCHAR NOT NULL,
                completed_at TIMESTAMP NOT NULL,
                note         VARCHAR
            )
        """)


def get_event_full(event_id: str) -> Optional[dict]:
    with _lock:
        row = _get_conn().execute(
            """SELECT id, source, ingested_at, event_time, source_ip, method, uri,
                      status_code, response_size, user_agent, referer, raw, extra
               FROM events WHERE id = ?""",
            [event_id],
        ).fetchone()
    if not row:
        return None
    cols = ["id", "source", "ingested_at", "event_time", "source_ip", "method",
            "uri", "status_code", "response_size", "user_agent", "referer", "raw", "extra"]
    d = dict(zip(cols, row))
    for f in ("ingested_at", "event_time"):
        if d.get(f) and hasattr(d[f], "isoformat"):
            d[f] = d[f].isoformat() + "Z"
    return d


def get_audit_facets(
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> dict:
    conditions: list[str] = []
    params: list = []
    if start:
        s = start.replace(tzinfo=None) if start.tzinfo else start
        conditions.append("ts >= ?")
        params.append(s)
    if end:
        e = end.replace(tzinfo=None) if end.tzinfo else end
        conditions.append("ts <= ?")
        params.append(e)
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    def _counts(col: str) -> list[dict]:
        rows = _conn.execute(
            f"SELECT {col}, COUNT(*) FROM audit_log {where} "
            f"GROUP BY {col} ORDER BY COUNT(*) DESC LIMIT 20",
            params,
        ).fetchall()
        return [{"value": r[0], "count": r[1]} for r in rows if r[0] is not None]

    with _lock:
        return {
            "event_type": _counts("event_type"),
            "actor": _counts("actor"),
            "status": _counts("status"),
        }

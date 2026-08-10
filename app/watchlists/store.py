import uuid
from datetime import datetime, timezone
from typing import Optional

from app.storage.duckdb_store import _get_conn, _lock  # noqa: PLC2701 — intentional internal access

_VALID_TYPES = {"ip", "cidr", "user_agent_substring", "uri_substring"}
_VALID_SEVERITIES = {"low", "medium", "high", "critical"}
_MAX_ENTRIES = 50_000

_COLS = ["id", "list_name", "indicator_type", "value", "severity", "note", "added_by", "added_at", "active"]


def _row_to_dict(row: tuple) -> dict:
    d = dict(zip(_COLS, row))
    if hasattr(d["added_at"], "isoformat"):
        d["added_at"] = d["added_at"].isoformat() + "Z"  # explicit UTC marker
    d["active"] = bool(d["active"])
    return d


def count_entries() -> int:
    conn = _get_conn()
    with _lock:
        return conn.execute("SELECT COUNT(*) FROM watchlist_entries").fetchone()[0]


def list_entries(list_name: Optional[str] = None) -> list[dict]:
    conn = _get_conn()
    where = "WHERE list_name = ?" if list_name else ""
    params = [list_name] if list_name else []
    with _lock:
        rows = conn.execute(
            f"SELECT {','.join(_COLS)} FROM watchlist_entries {where} ORDER BY added_at DESC",
            params,
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def add_entry(
    list_name: str, indicator_type: str, value: str, severity: str,
    note: Optional[str], added_by: str,
) -> dict:
    if indicator_type not in _VALID_TYPES:
        raise ValueError(f"indicator_type must be one of {sorted(_VALID_TYPES)}")
    if severity not in _VALID_SEVERITIES:
        raise ValueError(f"severity must be one of {sorted(_VALID_SEVERITIES)}")
    if count_entries() >= _MAX_ENTRIES:
        raise ValueError(f"Watchlist entry cap ({_MAX_ENTRIES}) reached")
    conn = _get_conn()
    entry_id = str(uuid.uuid4())
    added_at = datetime.now(timezone.utc).replace(tzinfo=None)
    with _lock:
        conn.execute(
            "INSERT INTO watchlist_entries "
            "(id, list_name, indicator_type, value, severity, note, added_by, added_at, active) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, TRUE)",
            [entry_id, list_name, indicator_type, value, severity, note, added_by, added_at],
        )
    return _row_to_dict((entry_id, list_name, indicator_type, value, severity, note, added_by, added_at, True))


def set_active(entry_id: str, active: bool) -> bool:
    conn = _get_conn()
    with _lock:
        existing = conn.execute("SELECT id FROM watchlist_entries WHERE id = ?", [entry_id]).fetchone()
        if not existing:
            return False
        conn.execute("UPDATE watchlist_entries SET active = ? WHERE id = ?", [active, entry_id])
    return True


def delete_entry(entry_id: str) -> bool:
    conn = _get_conn()
    with _lock:
        existing = conn.execute("SELECT id FROM watchlist_entries WHERE id = ?", [entry_id]).fetchone()
        if not existing:
            return False
        conn.execute("DELETE FROM watchlist_entries WHERE id = ?", [entry_id])
    return True


def get_active_entries() -> list[dict]:
    """Used to rebuild the ingest-time matcher cache after any write."""
    conn = _get_conn()
    with _lock:
        rows = conn.execute(
            f"SELECT {','.join(_COLS)} FROM watchlist_entries WHERE active = TRUE"
        ).fetchall()
    return [_row_to_dict(r) for r in rows]

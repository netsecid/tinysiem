import uuid
from datetime import datetime, timezone

from app.storage.duckdb_store import _ALLOWED_FIELDS, _get_conn, _lock  # noqa: PLC2701 — intentional internal access

_COLS = ["id", "rule_name", "field", "value", "reason", "added_by", "added_at"]


def _row_to_dict(row: tuple) -> dict:
    d = dict(zip(_COLS, row))
    if hasattr(d["added_at"], "isoformat"):
        d["added_at"] = d["added_at"].isoformat()
    return d


def list_exceptions(rule_name: str) -> list[dict]:
    conn = _get_conn()
    with _lock:
        rows = conn.execute(
            f"SELECT {','.join(_COLS)} FROM rule_exceptions WHERE rule_name = ? ORDER BY added_at DESC",
            [rule_name],
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def add_exception(rule_name: str, field: str, value: str, reason: str, added_by: str) -> dict:
    if field not in _ALLOWED_FIELDS:
        raise ValueError(f"field must be one of {sorted(_ALLOWED_FIELDS)}")
    conn = _get_conn()
    exc_id = str(uuid.uuid4())
    added_at = datetime.now(timezone.utc).replace(tzinfo=None)
    with _lock:
        conn.execute(
            "INSERT INTO rule_exceptions (id, rule_name, field, value, reason, added_by, added_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [exc_id, rule_name, field, value, reason, added_by, added_at],
        )
    return _row_to_dict((exc_id, rule_name, field, value, reason, added_by, added_at))


def delete_exception(rule_name: str, exception_id: str) -> bool:
    conn = _get_conn()
    with _lock:
        existing = conn.execute(
            "SELECT id FROM rule_exceptions WHERE id = ? AND rule_name = ?",
            [exception_id, rule_name],
        ).fetchone()
        if not existing:
            return False
        conn.execute("DELETE FROM rule_exceptions WHERE id = ?", [exception_id])
    return True


def get_all_exceptions() -> list[dict]:
    """Used by the rule engine to build its in-memory exception cache."""
    conn = _get_conn()
    with _lock:
        rows = conn.execute(f"SELECT {','.join(_COLS)} FROM rule_exceptions").fetchall()
    return [_row_to_dict(r) for r in rows]

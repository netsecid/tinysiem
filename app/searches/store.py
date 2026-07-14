import uuid
from datetime import datetime, timezone
from typing import Optional

from app.storage.duckdb_store import _get_conn, _lock  # noqa: PLC2701 — intentional internal access

_COLS = ["id", "owner", "name", "page", "query_string", "created_at"]


def _row_to_dict(row: tuple) -> dict:
    d = dict(zip(_COLS, row))
    if hasattr(d["created_at"], "isoformat"):
        d["created_at"] = d["created_at"].isoformat()
    return d


def list_searches(owner: str, page: Optional[str] = None) -> list[dict]:
    conn = _get_conn()
    conditions = ["owner = ?"]
    params: list = [owner]
    if page:
        conditions.append("page = ?")
        params.append(page)
    where = "WHERE " + " AND ".join(conditions)
    with _lock:
        rows = conn.execute(
            f"SELECT {','.join(_COLS)} FROM saved_searches {where} ORDER BY created_at DESC",
            params,
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def create_search(owner: str, name: str, page: str, query_string: str) -> dict:
    conn = _get_conn()
    search_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).replace(tzinfo=None)
    with _lock:
        conn.execute(
            "INSERT INTO saved_searches (id, owner, name, page, query_string, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [search_id, owner, name, page, query_string, created_at],
        )
    return _row_to_dict((search_id, owner, name, page, query_string, created_at))


def delete_search(search_id: str, owner: str) -> bool:
    conn = _get_conn()
    with _lock:
        result = conn.execute(
            "DELETE FROM saved_searches WHERE id = ? AND owner = ? RETURNING id",
            [search_id, owner],
        ).fetchall()
    return len(result) > 0

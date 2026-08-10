"""Read-only SQL sandbox for AI agents and analysts.

POST /query/sql executes a single read-only DuckDB statement against the
events database and returns rows as JSON. Safe by construction:

- Statement allowlist: only SELECT / WITH / SHOW / DESCRIBE / EXPLAIN / VALUES
- Comments are stripped *before* the keyword check (blocks ``/* DROP */``
  and ``--`` tricks)
- A bare ``;`` rejects the query (no multi-statement — conservative, also
  rejects string literals containing ``;``, which is the safe trade-off)
- Row cap (default 1000) + hard query timeout (threaded, DuckDB 1.1.3 has
  no statement_timeout)
- Every execution is written to the audit log with actor + duration

The sandbox uses a *second, in-process* DuckDB connection to the same
database file — DuckDB allows multiple connections to one database within a
process, so this never contends with the app's write connection.
"""
import concurrent.futures
import json
import logging
import re
import threading
import time
from typing import Optional

import duckdb
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.auth import AuthUser, require_analyst
from app.config import settings
from app.storage import duckdb_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/query", tags=["query"])

_SAFE_KEYWORDS = {"select", "with", "show", "describe", "explain", "values"}
_BLOCKED_KEYWORDS = {
    "insert", "update", "delete", "merge", "drop", "alter", "create",
    "copy", "attach", "detach", "install", "load", "vacuum", "export",
    "import", "secret", "call", "pragma", "set", "reset",
}

_BLOCKED_RE = re.compile(r"\b(" + "|".join(sorted(_BLOCKED_KEYWORDS)) + r")\b", re.IGNORECASE)

_sandbox_conn: Optional[duckdb.DuckDBPyConnection] = None
_sandbox_lock = threading.Lock()
_exec_lock = threading.Lock()  # one sandbox query at a time


class SqlQueryRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=20_000)
    params: Optional[list] = None
    max_rows: Optional[int] = Field(default=None, ge=1, le=10_000)


def strip_comments(sql: str) -> str:
    """Remove -- line comments and /* */ block comments (non-greedy)."""
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.DOTALL)
    sql = re.sub(r"--[^\n]*", " ", sql)
    return sql


def validate_read_only(sql: str) -> None:
    """Raise HTTPException(422) if the statement is not single read-only."""
    stripped = strip_comments(sql).strip()
    if not stripped:
        raise HTTPException(status_code=422, detail="Empty query")
    if ";" in stripped:
        raise HTTPException(status_code=422, detail="Multi-statement queries are not allowed")
    first = stripped.split(None, 1)[0].rstrip(";").lower()
    if first not in _SAFE_KEYWORDS:
        raise HTTPException(status_code=422, detail=f"Only read-only statements are allowed (got '{first}')")
    if _BLOCKED_RE.search(stripped):
        raise HTTPException(status_code=422, detail="Query contains a blocked keyword")


def get_sandbox_conn() -> duckdb.DuckDBPyConnection:
    global _sandbox_conn
    with _sandbox_lock:
        if _sandbox_conn is None:
            _sandbox_conn = duckdb.connect(settings.tinysiem_duckdb_path)
        return _sandbox_conn


def _execute(sql: str, params: Optional[list]) -> tuple[list[str], list[list]]:
    conn = get_sandbox_conn()
    if params:
        result = conn.execute(sql, params)
    else:
        result = conn.execute(sql)
    columns = [d[0] for d in result.description]
    rows = [list(r) for r in result.fetchall()]
    return columns, rows


def _truncate_row_cells(rows: list[list], max_cell_chars: int = 500) -> list[list]:
    """Cap individual cell size so one giant raw log can't blow the payload."""
    out = []
    for row in rows:
        out.append([str(c)[:max_cell_chars] if c is not None and len(str(c)) > max_cell_chars else c for c in row])
    return out


@router.post("/sql")
def run_query(
    req: SqlQueryRequest,
    request: Request,
    actor: AuthUser = Depends(require_analyst),
):
    if not settings.tinysiem_sql_enabled:
        raise HTTPException(status_code=503, detail="SQL sandbox disabled")

    validate_read_only(req.query)

    max_rows = min(req.max_rows or settings.tinysiem_sql_max_rows, settings.tinysiem_sql_max_rows)
    timeout_s = settings.tinysiem_sql_timeout_ms / 1000.0
    started = time.monotonic()

    if not _exec_lock.acquire(timeout=timeout_s):
        raise HTTPException(status_code=429, detail="SQL sandbox busy — another query is running")
    try:
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                fut = pool.submit(_execute, req.query, req.params)
                columns, rows = fut.result(timeout=timeout_s)
        except concurrent.futures.TimeoutError:
            duration_ms = int((time.monotonic() - started) * 1000)
            _audit(actor, request, req.query, error="timeout", duration_ms=duration_ms)
            raise HTTPException(status_code=408, detail=f"Query timed out after {timeout_s:.1f}s")
    finally:
        _exec_lock.release()

    total = len(rows)
    truncated = total > max_rows
    rows = rows[:max_rows]
    rows = _truncate_row_cells(rows)
    duration_ms = int((time.monotonic() - started) * 1000)

    _audit(actor, request, req.query, rows_returned=len(rows), truncated=truncated, duration_ms=duration_ms)
    return {
        "columns": columns,
        "rows": rows,
        "total_rows": total,
        "truncated": truncated,
        "duration_ms": duration_ms,
    }


def _audit(actor: AuthUser, request: Request, query: str, **extra) -> None:
    try:
        from app.audit import store as audit
        audit.log_event(
            "query.sql",
            "execute",
            actor=actor.username,
            actor_role=actor.role,
            resource_type="sql",
            detail={"query": query[:300], **extra},
            ip_address=request.client.host if request.client else None,
        )
    except Exception as exc:  # audit must never break the query path
        logger.warning(f"Audit log error: {exc}")

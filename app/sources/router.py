from fastapi import APIRouter, Depends

from app.auth import AuthUser, require_analyst
from app.storage import duckdb_store

router = APIRouter(prefix="/sources", tags=["sources"])


@router.get("")
def list_sources(_: AuthUser = Depends(require_analyst)):
    sources = duckdb_store.query_source_activity()
    active = sum(1 for s in sources if s["status"] == "active")
    stale = sum(1 for s in sources if s["status"] == "stale")
    silent = sum(1 for s in sources if s["status"] == "silent")
    return {
        "sources": sources,
        "summary": {"total": len(sources), "active": active, "stale": stale, "silent": silent},
    }

import csv
import io
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, Response, UploadFile
from pydantic import BaseModel

from app.audit import store as audit
from app.auth import AuthUser, require_admin, require_analyst
from app.watchlists import store as watchlist_store

router = APIRouter(prefix="/watchlists", tags=["watchlists"])


def _reload_matcher_cache() -> None:
    try:
        from app.watchlists import matcher as watchlist_matcher
    except ImportError:
        return
    watchlist_matcher.reload_cache()


class WatchlistEntryRequest(BaseModel):
    list_name: str
    indicator_type: str
    value: str
    severity: str
    note: Optional[str] = None


class BulkEntryItem(BaseModel):
    indicator_type: str
    value: str
    severity: str
    note: Optional[str] = None


class BulkAddRequest(BaseModel):
    list_name: str
    entries: list[BulkEntryItem]


@router.get("")
def list_watchlist_entries(list_name: Optional[str] = None, _: AuthUser = Depends(require_analyst)):
    return {"entries": watchlist_store.list_entries(list_name)}


@router.post("", status_code=201)
def create_watchlist_entry(req: WatchlistEntryRequest, actor: AuthUser = Depends(require_admin)):
    try:
        entry = watchlist_store.add_entry(
            req.list_name, req.indicator_type, req.value, req.severity, req.note, actor.username,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    _reload_matcher_cache()
    audit.log_event(
        "watchlist.add", "created", "success",
        actor=actor.username, actor_role=actor.role,
        resource_type="watchlist_entry", resource_id=entry["id"],
        detail={"list_name": req.list_name, "indicator_type": req.indicator_type, "value": req.value},
    )
    return entry


@router.patch("/{entry_id}")
def toggle_watchlist_entry(entry_id: str, active: bool, actor: AuthUser = Depends(require_admin)):
    ok = watchlist_store.set_active(entry_id, active)
    if not ok:
        raise HTTPException(status_code=404, detail="Watchlist entry not found")
    _reload_matcher_cache()
    audit.log_event(
        "watchlist.toggle", "updated", "success",
        actor=actor.username, actor_role=actor.role,
        resource_type="watchlist_entry", resource_id=entry_id,
        detail={"active": active},
    )
    return {"id": entry_id, "active": active}


@router.delete("/{entry_id}", status_code=204)
def delete_watchlist_entry(entry_id: str, actor: AuthUser = Depends(require_admin)):
    ok = watchlist_store.delete_entry(entry_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Watchlist entry not found")
    _reload_matcher_cache()
    audit.log_event(
        "watchlist.delete", "deleted", "success",
        actor=actor.username, actor_role=actor.role,
        resource_type="watchlist_entry", resource_id=entry_id,
    )
    return Response(status_code=204)


@router.post("/bulk", status_code=201)
def bulk_add_watchlist_entries(req: BulkAddRequest, actor: AuthUser = Depends(require_admin)):
    created = []
    errors = []
    for i, item in enumerate(req.entries):
        try:
            entry = watchlist_store.add_entry(
                req.list_name, item.indicator_type, item.value, item.severity, item.note, actor.username,
            )
            created.append(entry)
        except ValueError as exc:
            errors.append({"index": i, "value": item.value, "error": str(exc)})
    _reload_matcher_cache()
    audit.log_event(
        "watchlist.bulk_add", "created", "success" if not errors else "partial",
        actor=actor.username, actor_role=actor.role,
        resource_type="watchlist_entry",
        detail={"list_name": req.list_name, "created": len(created), "errors": len(errors)},
    )
    return {"created": created, "errors": errors}


@router.post("/import", status_code=201)
async def import_watchlist_csv(
    list_name: str,
    file: UploadFile = File(...),
    actor: AuthUser = Depends(require_admin),
):
    raw = (await file.read()).decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(raw))
    required = {"type", "value", "severity", "note"}
    if reader.fieldnames is None or not required.issubset(set(reader.fieldnames)):
        raise HTTPException(
            status_code=422,
            detail=f"CSV must have columns: {', '.join(sorted(required))}",
        )
    created = []
    errors = []
    for i, row in enumerate(reader):
        try:
            entry = watchlist_store.add_entry(
                list_name, row["type"].strip(), row["value"].strip(),
                row["severity"].strip(), (row.get("note") or "").strip() or None, actor.username,
            )
            created.append(entry)
        except ValueError as exc:
            errors.append({"row": i, "value": row.get("value"), "error": str(exc)})
    _reload_matcher_cache()
    audit.log_event(
        "watchlist.import", "created", "success" if not errors else "partial",
        actor=actor.username, actor_role=actor.role,
        resource_type="watchlist_entry",
        detail={"list_name": list_name, "created": len(created), "errors": len(errors)},
    )
    return {"created": created, "errors": errors}

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel

from app.auth import AuthUser, require_analyst
from app.searches import store as search_store

router = APIRouter(prefix="/searches", tags=["searches"])

_VALID_PAGES = {"events", "alerts"}


class SavedSearchRequest(BaseModel):
    name: str
    page: str
    query_string: str


@router.get("")
def list_saved_searches(page: Optional[str] = None, actor: AuthUser = Depends(require_analyst)):
    return {"searches": search_store.list_searches(actor.username, page)}


@router.post("", status_code=201)
def create_saved_search(req: SavedSearchRequest, actor: AuthUser = Depends(require_analyst)):
    if req.page not in _VALID_PAGES:
        raise HTTPException(status_code=422, detail=f"page must be one of {sorted(_VALID_PAGES)}")
    return search_store.create_search(actor.username, req.name, req.page, req.query_string)


@router.delete("/{search_id}", status_code=204)
def delete_saved_search(search_id: str, actor: AuthUser = Depends(require_analyst)):
    ok = search_store.delete_search(search_id, actor.username)
    if not ok:
        raise HTTPException(status_code=404, detail="Saved search not found")
    return Response(status_code=204)

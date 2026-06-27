from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel

from app.auth import AuthUser, require_superadmin
from app.password import hash_password
from app.storage import duckdb_store

router = APIRouter(prefix="/users", tags=["users"])

_VALID_ROLES = {"superadmin", "admin", "analyst"}


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str


class UpdateUserRequest(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    role: Optional[str] = None


@router.get("")
def list_users(_: AuthUser = Depends(require_superadmin)):
    return {"users": duckdb_store.list_users()}


@router.post("", status_code=201)
def create_user(req: CreateUserRequest, _: AuthUser = Depends(require_superadmin)):
    if req.role not in _VALID_ROLES:
        raise HTTPException(status_code=422, detail=f"Role must be one of: {', '.join(sorted(_VALID_ROLES))}")
    if duckdb_store.get_user_by_username(req.username):
        raise HTTPException(status_code=409, detail="Username already exists")
    return duckdb_store.create_user(req.username, hash_password(req.password), req.role)


@router.put("/{user_id}")
def update_user(
    user_id: str,
    req: UpdateUserRequest,
    _: AuthUser = Depends(require_superadmin),
):
    if req.role is not None and req.role not in _VALID_ROLES:
        raise HTTPException(status_code=422, detail=f"Role must be one of: {', '.join(sorted(_VALID_ROLES))}")
    target = duckdb_store.get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target["role"] == "superadmin" and req.role and req.role != "superadmin":
        if duckdb_store.count_superadmins() <= 1:
            raise HTTPException(status_code=409, detail="Cannot demote the last superadmin")
    updated = duckdb_store.update_user(
        user_id,
        username=req.username,
        password_hash=hash_password(req.password) if req.password else None,
        role=req.role,
    )
    return updated


@router.delete("/{user_id}", status_code=204)
def delete_user(user_id: str, _: AuthUser = Depends(require_superadmin)):
    target = duckdb_store.get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target["role"] == "superadmin" and duckdb_store.count_superadmins() <= 1:
        raise HTTPException(status_code=409, detail="Cannot delete the last superadmin")
    duckdb_store.delete_user(user_id)
    return Response(status_code=204)

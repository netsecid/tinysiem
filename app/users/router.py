from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field

from app.audit import store as audit
from app.auth import AuthUser, require_superadmin
from app.password import MIN_PASSWORD_LENGTH, hash_password
from app.storage import duckdb_store

router = APIRouter(prefix="/users", tags=["users"])

_VALID_ROLES = {"superadmin", "admin", "analyst"}


class CreateUserRequest(BaseModel):
    username: str
    password: str = Field(min_length=MIN_PASSWORD_LENGTH)
    role: str


class UpdateUserRequest(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = Field(default=None, min_length=MIN_PASSWORD_LENGTH)
    role: Optional[str] = None


@router.get("")
def list_users(_: AuthUser = Depends(require_superadmin)):
    return {"users": duckdb_store.list_users()}


@router.post("", status_code=201)
def create_user(req: CreateUserRequest, actor: AuthUser = Depends(require_superadmin)):
    if req.role not in _VALID_ROLES:
        raise HTTPException(status_code=422, detail=f"Role must be one of: {', '.join(sorted(_VALID_ROLES))}")
    if duckdb_store.get_user_by_username(req.username):
        raise HTTPException(status_code=409, detail="Username already exists")
    result = duckdb_store.create_user(req.username, hash_password(req.password), req.role)
    audit.log_event(
        "user.create", "created", "success",
        actor=actor.username, actor_role=actor.role,
        resource_type="user", resource_id=req.username,
        detail={"target_username": req.username, "target_role": req.role},
    )
    return result


@router.put("/{user_id}")
def update_user(
    user_id: str,
    req: UpdateUserRequest,
    actor: AuthUser = Depends(require_superadmin),
):
    if req.role is not None and req.role not in _VALID_ROLES:
        raise HTTPException(status_code=422, detail=f"Role must be one of: {', '.join(sorted(_VALID_ROLES))}")
    target = duckdb_store.get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target["role"] == "superadmin" and req.role and req.role != "superadmin":
        if duckdb_store.count_superadmins() <= 1:
            raise HTTPException(status_code=409, detail="Cannot demote the last superadmin")
    if req.username is not None and req.username != target["username"]:
        if duckdb_store.get_user_by_username(req.username):
            raise HTTPException(status_code=409, detail="Username already exists")
    changes = [f for f, v in [("username", req.username), ("password", req.password), ("role", req.role)] if v is not None]
    updated = duckdb_store.update_user(
        user_id,
        username=req.username,
        password_hash=hash_password(req.password) if req.password else None,
        role=req.role,
    )
    if updated is None:
        raise HTTPException(status_code=404, detail="User not found after update")
    audit.log_event(
        "user.update", "updated", "success",
        actor=actor.username, actor_role=actor.role,
        resource_type="user", resource_id=target["username"],
        detail={"target_username": target["username"], "changes": changes},
    )
    updated.pop("password_hash", None)
    return updated


@router.delete("/{user_id}", status_code=204)
def delete_user(user_id: str, actor: AuthUser = Depends(require_superadmin)):
    target = duckdb_store.get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target["role"] == "superadmin" and duckdb_store.count_superadmins() <= 1:
        raise HTTPException(status_code=409, detail="Cannot delete the last superadmin")
    duckdb_store.delete_user(user_id)
    audit.log_event(
        "user.delete", "deleted", "success",
        actor=actor.username, actor_role=actor.role,
        resource_type="user", resource_id=target["username"],
        detail={"target_username": target["username"], "target_role": target["role"]},
    )
    return Response(status_code=204)

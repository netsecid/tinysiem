from fastapi import APIRouter, HTTPException, Request
from fastapi.params import Depends
from pydantic import BaseModel

from app.auth import AuthUser, create_token, require_analyst
from app.audit import store as audit
from app.config import settings
from app.password import hash_password, verify_password
from app.storage import duckdb_store

# Pre-computed dummy hash so bcrypt always runs regardless of whether username exists,
# preventing timing-based username enumeration.
_DUMMY_HASH = hash_password("tinysiem-dummy-no-match-placeholder")

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login")
def login(req: LoginRequest, request: Request):
    ip = request.client.host if request.client else None
    user = duckdb_store.get_user_by_username(req.username)
    password_hash = user["password_hash"] if user else _DUMMY_HASH
    password_valid = verify_password(req.password, password_hash)
    if not user or not password_valid:
        audit.log_event(
            "auth.login", "login", "failure",
            actor=req.username,
            detail={"attempted_username": req.username},
            ip_address=ip,
            error_msg="Invalid credentials",
        )
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = create_token(user["id"], user["username"], user["role"])
    audit.log_event(
        "auth.login", "login", "success",
        actor=user["username"],
        actor_role=user["role"],
        detail={"username": user["username"]},
        ip_address=ip,
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user["username"],
        "role": user["role"],
        "expires_in": settings.tinysiem_jwt_expiry_hours * 3600,
    }


@router.get("/me")
def me(user: AuthUser = Depends(require_analyst)):
    return {"user_id": user.user_id, "username": user.username, "role": user.role}

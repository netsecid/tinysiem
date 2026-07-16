from fastapi import APIRouter, HTTPException, Request
from fastapi.params import Depends
from pydantic import BaseModel

from app.auth import AuthUser, create_token, require_analyst
from app.audit import store as audit
from app.auth_lockout import check_and_note_attempt, record_success
from app.config import settings
from app.password import MIN_PASSWORD_LENGTH, hash_password, verify_password
from app.storage import duckdb_store

# Pre-computed dummy hash so bcrypt always runs regardless of whether username exists,
# preventing timing-based username enumeration.
_DUMMY_HASH = hash_password("tinysiem-dummy-no-match-placeholder")

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@router.post("/login")
def login(req: LoginRequest, request: Request):
    ip = request.client.host if request.client else "unknown"
    lock_key = (req.username, ip)

    remaining = check_and_note_attempt(lock_key)
    if remaining > 0:
        audit.log_event(
            "auth.lockout", "login", "failure",
            actor=req.username,
            detail={"attempted_username": req.username, "retry_after_seconds": round(remaining)},
            ip_address=ip,
            error_msg="Account temporarily locked after repeated failed attempts",
        )
        raise HTTPException(status_code=429, detail="Too many failed attempts. Try again later.")

    user = duckdb_store.get_user_by_username(req.username)
    password_hash = user["password_hash"] if user else _DUMMY_HASH
    password_valid = verify_password(req.password, password_hash)
    if not user or not password_valid:
        # Failure already recorded by check_and_note_attempt() above — do not record
        # it again here, that would double-count this attempt.
        audit.log_event(
            "auth.login", "login", "failure",
            actor=req.username,
            detail={"attempted_username": req.username},
            ip_address=ip,
            error_msg="Invalid credentials",
        )
        raise HTTPException(status_code=401, detail="Invalid username or password")

    record_success(lock_key)
    token = create_token(user["id"], user["username"], user["role"], epoch=user.get("token_epoch", 0))
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
        "must_change_password": user.get("must_change_password", False),
    }


@router.get("/me")
def me(user: AuthUser = Depends(require_analyst)):
    return {"user_id": user.user_id, "username": user.username, "role": user.role}


@router.post("/logout")
def logout(user: AuthUser = Depends(require_analyst)):
    duckdb_store.bump_token_epoch(user.user_id)
    audit.log_event(
        "auth.logout", "logout", "success",
        actor=user.username, actor_role=user.role,
    )
    return {"status": "ok"}


@router.post("/change-password")
def change_password(req: ChangePasswordRequest, request: Request, user: AuthUser = Depends(require_analyst)):
    ip = request.client.host if request.client else "unknown"
    lock_key = (f"pwchange:{user.username}", ip)

    remaining = check_and_note_attempt(lock_key)
    if remaining > 0:
        raise HTTPException(status_code=429, detail="Too many failed attempts. Try again later.")

    row = duckdb_store.get_user_by_id(user.user_id)
    if row is None:
        raise HTTPException(status_code=401, detail="User no longer exists")
    if not verify_password(req.current_password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    record_success(lock_key)
    if len(req.new_password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(status_code=422, detail=f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    updated = duckdb_store.change_own_password(user.user_id, hash_password(req.new_password))
    token = create_token(updated["id"], updated["username"], updated["role"], epoch=updated["token_epoch"])
    audit.log_event(
        "auth.password_change", "updated", "success",
        actor=user.username, actor_role=user.role,
    )
    return {"status": "ok", "access_token": token, "token_type": "bearer"}

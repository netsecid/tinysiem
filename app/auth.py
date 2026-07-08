import app.password  # noqa: F401 — ensures bcrypt monkey-patch is applied before passlib/jwt

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import settings

_ROLE_HIERARCHY = ["analyst", "admin", "superadmin"]

_bearer = HTTPBearer(auto_error=False)

_PASSWORD_CHANGE_EXEMPT_PATHS = {"/auth/me", "/auth/logout", "/auth/change-password"}


@dataclass
class AuthUser:
    user_id: str
    username: str
    role: str


def create_token(user_id: str, username: str, role: str, epoch: int = 0) -> str:
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "epoch": epoch,
        "exp": datetime.utcnow() + timedelta(hours=settings.tinysiem_jwt_expiry_hours),
    }
    return jwt.encode(payload, settings.tinysiem_jwt_secret, algorithm="HS256")


def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, settings.tinysiem_jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None


def _role_ok(user_role: str, min_role: str) -> bool:
    if min_role == "ingest":
        return _role_ok(user_role, "admin")  # admin+ JWTs can still hit ingest endpoints
    try:
        return _ROLE_HIERARCHY.index(user_role) >= _ROLE_HIERARCHY.index(min_role)
    except ValueError:
        return False


def require_auth(min_role: str = "analyst"):
    def _dep(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    ) -> AuthUser:
        if credentials is None:
            raise HTTPException(status_code=401, detail="Missing authentication")

        token = credentials.credentials

        # 1. Try JWT
        payload = decode_token(token)
        if payload:
            role = payload.get("role", "")
            if not _role_ok(role, min_role):
                raise HTTPException(status_code=403, detail="Insufficient permissions")

            from app.storage import duckdb_store
            user_row = duckdb_store.get_user_by_id(payload.get("sub", ""))
            if user_row is None:
                raise HTTPException(status_code=401, detail="User no longer exists")
            if payload.get("epoch", 0) != user_row.get("token_epoch", 0):
                raise HTTPException(status_code=401, detail="Token has been revoked")
            if user_row.get("must_change_password") and request.url.path not in _PASSWORD_CHANGE_EXEMPT_PATHS:
                raise HTTPException(status_code=403, detail="password_change_required")

            return AuthUser(user_id=user_row["id"], username=user_row["username"], role=role)

        # 2. Global API key — ingest-only scope
        if min_role == "ingest" and secrets.compare_digest(token, settings.tinysiem_api_key):
            return AuthUser(user_id="system", username="system", role="ingest")

        raise HTTPException(status_code=401, detail="Invalid authentication")

    return _dep


require_analyst = require_auth("analyst")
require_admin = require_auth("admin")
require_superadmin = require_auth("superadmin")
require_ingest = require_auth("ingest")

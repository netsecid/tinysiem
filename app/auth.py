import app.password  # noqa: F401 — ensures bcrypt monkey-patch is applied before passlib/jwt

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import settings

_ROLE_HIERARCHY = ["analyst", "admin", "superadmin"]

_bearer = HTTPBearer(auto_error=False)


@dataclass
class AuthUser:
    user_id: str
    username: str
    role: str


def create_token(user_id: str, username: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=settings.tinysiem_jwt_expiry_hours),
    }
    return jwt.encode(payload, settings.tinysiem_jwt_secret, algorithm="HS256")


def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, settings.tinysiem_jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None


def _role_ok(user_role: str, min_role: str) -> bool:
    try:
        return _ROLE_HIERARCHY.index(user_role) >= _ROLE_HIERARCHY.index(min_role)
    except ValueError:
        return False


def require_auth(min_role: str = "analyst"):
    def _dep(
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
            return AuthUser(
                user_id=payload["sub"],
                username=payload.get("username", ""),
                role=role,
            )

        # 2. Backward compat: global API key → admin
        if token == settings.tinysiem_api_key:
            if not _role_ok("admin", min_role):
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            return AuthUser(user_id="system", username="system", role="admin")

        raise HTTPException(status_code=401, detail="Invalid authentication")

    return _dep


require_analyst = require_auth("analyst")
require_admin = require_auth("admin")
require_superadmin = require_auth("superadmin")

# Backward-compat shim — existing routers import this until Task 3 migrates them
def verify_api_key(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> str:
    if credentials is None or credentials.credentials != settings.tinysiem_api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return credentials.credentials

from fastapi import APIRouter, HTTPException
from fastapi.params import Depends
from pydantic import BaseModel

from app.auth import AuthUser, create_token, require_analyst
from app.config import settings
from app.password import verify_password
from app.storage import duckdb_store

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login")
def login(req: LoginRequest):
    user = duckdb_store.get_user_by_username(req.username)
    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = create_token(user["id"], user["username"], user["role"])
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

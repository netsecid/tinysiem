import json
from pathlib import Path

from fastapi import APIRouter, Depends

from app.auth import AuthUser, require_admin

router = APIRouter(tags=["system"])

_SBOM_PATH = Path("/app/sbom.json")


@router.get("/sbom")
def get_sbom(_: AuthUser = Depends(require_admin)):
    if _SBOM_PATH.exists():
        return json.loads(_SBOM_PATH.read_text())
    return []

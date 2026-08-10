"""GeoIP lookup endpoint — analyst+.

GET /geoip/{ip} → {"ip": ..., "geo": {...}|null, "enabled": bool, "provider": ..., "db_path": ...}

Used by the entity page and by agents (read-only). Validation is strict: a
malformed IP returns 422, so callers can't use this as a free-form probe.
"""

from __future__ import annotations

import ipaddress

from fastapi import APIRouter, Depends, HTTPException

from app.auth import AuthUser, require_analyst
from app.geoip import lookup, status

router = APIRouter(prefix="/geoip", tags=["geoip"])


@router.get("/{ip}")
def geoip_lookup(ip: str, _: AuthUser = Depends(require_analyst)):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=422, detail=f"Invalid IP address: {ip}")
    return {"ip": ip, "geo": lookup(ip), **status()}

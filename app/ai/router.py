from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.auth import AuthUser, require_admin, require_analyst
from app.crypto import MasterKeyNotConfigured

router = APIRouter(prefix="/ai", tags=["ai"])


def _enforce_ai_rate_limit(actor: AuthUser) -> None:
    from app.ai.rate_limit import check_and_record
    from app.config import settings
    if not check_and_record(actor.username, settings.tinysiem_ai_daily_call_limit):
        raise HTTPException(
            status_code=429,
            detail=f"Daily AI call limit reached ({settings.tinysiem_ai_daily_call_limit}/day). Contact an admin to increase TINYSIEM_AI_DAILY_CALL_LIMIT.",
        )


def _validate_base_url(url: str) -> None:
    import ipaddress
    import socket
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=422, detail="base_url must use http:// or https://")
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=422, detail="base_url must include a hostname")
    try:
        addrs = {info[4][0] for info in socket.getaddrinfo(hostname, None)}
    except socket.gaierror:
        raise HTTPException(status_code=422, detail=f"Could not resolve base_url hostname: {hostname}")
    for addr in addrs:
        ip = ipaddress.ip_address(addr)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise HTTPException(
                status_code=422,
                detail="base_url resolves to a private, loopback, link-local, or reserved address, which is not allowed",
            )


class HomeSearchRequest(BaseModel):
    question: Annotated[str, Field(min_length=1, max_length=1000)]


class ExplainAlertRequest(BaseModel):
    alert_id: str


class AnalyzeEventsRequest(BaseModel):
    event_ids: Annotated[list[str], Field(min_length=1, max_length=50)]
    question: Annotated[str, Field(max_length=2000)]


@router.post("/explain-alert")
def explain_alert_endpoint(req: ExplainAlertRequest, actor: AuthUser = Depends(require_analyst)):
    _enforce_ai_rate_limit(actor)
    from app.ai import enrichment
    try:
        return enrichment.explain_alert(req.alert_id, actor=actor.username)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"AI provider error: {exc}")


@router.post("/analyze-events")
def analyze_events_endpoint(req: AnalyzeEventsRequest, actor: AuthUser = Depends(require_analyst)):
    _enforce_ai_rate_limit(actor)
    from app.ai import enrichment
    try:
        return enrichment.analyze_events(req.event_ids, req.question, actor=actor.username)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"AI provider error: {exc}")


@router.post("/search")
def home_search_endpoint(req: HomeSearchRequest, actor: AuthUser = Depends(require_analyst)):
    _enforce_ai_rate_limit(actor)
    from app.ai import home_search
    try:
        return home_search.run_search(req.question, actor=actor.username)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"AI provider error: {exc}")


class SaveAIConfigRequest(BaseModel):
    provider: str
    model: str
    base_url: Optional[str] = None
    api_key: Optional[str] = None


@router.get("/config")
def get_ai_config_endpoint(_: AuthUser = Depends(require_admin)):
    from app.ai import config_store
    cfg = config_store.get_ai_config()
    if not cfg:
        return {"configured": False}
    return {"configured": True, **cfg}


@router.put("/config")
def save_ai_config_endpoint(req: SaveAIConfigRequest, actor: AuthUser = Depends(require_admin)):
    from app.ai import config_store
    from app.ai.provider_factory import PROVIDER_PRESETS
    from app.audit import store as audit

    if req.provider not in PROVIDER_PRESETS:
        raise HTTPException(status_code=422, detail=f"Unknown provider: {req.provider}")

    if not req.model:
        raise HTTPException(status_code=422, detail="model is required")

    if req.provider == "custom":
        if not req.base_url:
            raise HTTPException(status_code=422, detail="base_url is required for the custom provider")
        _validate_base_url(req.base_url)
    elif req.provider == "opencode":
        # Local `opencode serve` — loopback session protocol, subscription auth
        # handled by the serve process itself. No api_key, no base_url.
        pass
    else:
        if not req.api_key:
            # A stored key only counts as "already there" for THIS save if it belongs to the
            # same provider — config_store.save_ai_config() only carries a key forward across
            # saves of the same provider, so this check must mirror that exactly or a
            # provider switch could pass validation here and still end up keyless.
            existing = config_store.get_ai_config()
            has_matching_key = bool(existing and existing["provider"] == req.provider and existing["has_api_key"])
            if not has_matching_key:
                raise HTTPException(status_code=422, detail=f"api_key is required for {req.provider}")

    try:
        cfg = config_store.save_ai_config(
            provider=req.provider,
            model=req.model,
            base_url=req.base_url if req.provider == "custom" else None,
            api_key=req.api_key,
            updated_by=actor.username,
        )
    except MasterKeyNotConfigured as e:
        raise HTTPException(status_code=503, detail=str(e))
    audit.log_event(
        "ai_config.update", "updated", "success",
        actor=actor.username, actor_role=actor.role,
        resource_type="ai_config",
        detail={"provider": req.provider, "model": req.model},
    )
    return {"configured": True, **cfg}


@router.post("/config/test")
def test_ai_config_endpoint(_: AuthUser = Depends(require_admin)):
    from app.ai.provider_factory import get_active_provider
    try:
        provider = get_active_provider()
    except RuntimeError as exc:
        return {"success": False, "detail": str(exc)}
    try:
        result = provider.chat(system="You are a test.", user="Reply with exactly: OK", max_tokens=512)
        return {"success": True, "detail": result.text}
    except Exception as exc:
        return {"success": False, "detail": str(exc)}

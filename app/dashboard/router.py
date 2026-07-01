"""API endpoints for /dashboard."""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.auth import AuthUser, require_analyst
from app.audit import store as audit
from app.dashboard import store as dstore

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

_MAX_WIDGETS = 20


class Widget(BaseModel):
    widget_id: str
    type: str
    title: str = ""
    grid_position: dict = Field(default_factory=dict)
    config: dict = Field(default_factory=dict)


class SaveDashboardRequest(BaseModel):
    title: str = Field("Dashboard", max_length=100)
    widgets: list[Widget] = Field(default_factory=list)


@router.get("")
def get_dashboard(actor: AuthUser = Depends(require_analyst)):
    return dstore.get_dashboard(actor.username)


@router.put("")
def save_dashboard(req: SaveDashboardRequest, actor: AuthUser = Depends(require_analyst)):
    if len(req.widgets) > _MAX_WIDGETS:
        raise HTTPException(status_code=400, detail=f"Maximum {_MAX_WIDGETS} widgets allowed")
    widgets = [w.model_dump() for w in req.widgets]
    result = dstore.upsert_dashboard(actor.username, req.title, widgets)
    audit.log_event(
        "dashboard.save", "saved", actor.username,
        detail={"owner": actor.username, "widget_count": len(widgets)},
    )
    return result


@router.delete("", status_code=204)
def reset_dashboard(actor: AuthUser = Depends(require_analyst)):
    dstore.delete_dashboard(actor.username)
    audit.log_event(
        "dashboard.reset", "reset", actor.username,
        detail={"owner": actor.username},
    )


@router.post("/export/html")
def export_html(actor: AuthUser = Depends(require_analyst)):
    from app.dashboard.renderer import build_html_export
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    html = build_html_export(actor.username)
    audit.log_event(
        "dashboard.export", "html_export", actor.username,
        detail={"owner": actor.username},
    )
    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": f'attachment; filename="dashboard-{ts}.html"'},
    )

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.auth import AuthUser, require_analyst

router = APIRouter(prefix="/ai", tags=["ai"])


class ExplainAlertRequest(BaseModel):
    alert_id: str


class AnalyzeEventsRequest(BaseModel):
    event_ids: Annotated[list[str], Field(min_length=1, max_length=50)]
    question: Annotated[str, Field(max_length=2000)]


@router.post("/explain-alert")
def explain_alert_endpoint(req: ExplainAlertRequest, actor: AuthUser = Depends(require_analyst)):
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
    from app.ai import enrichment
    try:
        return enrichment.analyze_events(req.event_ids, req.question, actor=actor.username)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"AI provider error: {exc}")

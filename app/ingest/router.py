import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile

from app.auth import AuthUser, require_ingest
from app.config import settings
from app.ingest.models import RawIngestRequest
from app.ingest.pipeline import process_line

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ingest", tags=["ingest"])


@router.post("/raw")
def ingest_raw(
    payload: RawIngestRequest,
    _: AuthUser = Depends(require_ingest),
):
    event_id = process_line(payload.source, payload.raw, strict=True)
    return {"status": "ok", "event_id": event_id}


@router.post("/file")
def ingest_file(
    source: str,
    file: UploadFile,
    _: AuthUser = Depends(require_ingest),
):
    content = file.file.read().decode("utf-8", errors="replace")
    lines = [line for line in content.splitlines() if line.strip()]

    processed = 0
    failed = 0
    for line in lines:
        try:
            process_line(source, line, strict=True)
            processed += 1
        except HTTPException:
            failed += 1
        except Exception as exc:
            logger.warning(f"Failed to process line: {exc}")
            failed += 1

    return {"status": "ok", "processed": processed, "failed": failed}


@router.post("/beats")
async def ingest_beats(
    request: Request,
    _: AuthUser = Depends(require_ingest),
):
    if not settings.tinysiem_beats_enabled:
        raise HTTPException(status_code=503, detail="Beats endpoint disabled")

    body = await request.body()
    lines = body.decode("utf-8", errors="replace").splitlines()

    items: list = []
    errors = False
    i = 0
    while i < len(lines):
        action_line = lines[i].strip()
        i += 1
        if not action_line or i >= len(lines):
            continue
        doc_line = lines[i].strip()
        i += 1
        if not doc_line:
            continue

        try:
            doc = json.loads(doc_line)
            source = (
                (doc.get("fields") or {}).get("source")
                or (doc.get("agent") or {}).get("type")
                or "beats"
            )
            raw = doc.get("message") or doc_line
            event_id = process_line(source, raw, strict=False)
            items.append({"index": {"_id": event_id, "result": "created"}})
        except Exception as exc:
            logger.warning(f"Beats ingest error: {exc}")
            items.append({"index": {"error": str(exc)}})
            errors = True

    return {"items": items, "errors": errors, "took": len(items)}

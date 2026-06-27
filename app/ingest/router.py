import logging

from fastapi import APIRouter, Depends, HTTPException, UploadFile

from app.auth import AuthUser, require_admin
from app.decoder import engine as decoder_engine
from app.ingest.models import RawIngestRequest
from app.rules import engine as rule_engine
from app.storage import chroma_store, duckdb_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ingest", tags=["ingest"])


def _process_line(source: str, raw: str) -> str:
    event = decoder_engine.decode(source, raw)
    if event is None:
        raise HTTPException(status_code=422, detail="Log line could not be decoded")

    duckdb_store.insert_event(event)

    try:
        chroma_store.upsert_event(event)
    except Exception as exc:
        logger.warning(f"ChromaDB upsert failed (non-fatal): {exc}")

    rule_engine.evaluate(event)
    return event["id"]


@router.post("/raw")
def ingest_raw(
    payload: RawIngestRequest,
    _: AuthUser = Depends(require_admin),
):
    event_id = _process_line(payload.source, payload.raw)
    return {"status": "ok", "event_id": event_id}


@router.post("/file")
def ingest_file(
    source: str,
    file: UploadFile,
    _: AuthUser = Depends(require_admin),
):
    content = file.file.read().decode("utf-8", errors="replace")
    lines = [line for line in content.splitlines() if line.strip()]

    processed = 0
    failed = 0
    for line in lines:
        try:
            _process_line(source, line)
            processed += 1
        except HTTPException:
            failed += 1
        except Exception as exc:
            logger.warning(f"Failed to process line: {exc}")
            failed += 1

    return {"status": "ok", "processed": processed, "failed": failed}

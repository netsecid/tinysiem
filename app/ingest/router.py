import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile

from app.auth import AuthUser, require_ingest
from app.config import settings
from app.decoder import engine as decoder_engine
from app.ingest.models import RawIngestRequest
from app.ingest.pipeline import process_line, store_and_evaluate

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ingest", tags=["ingest"])

_MAX_INGEST_ERRORS = 5000


@router.post("/raw")
def ingest_raw(
    payload: RawIngestRequest,
    _: AuthUser = Depends(require_ingest),
):
    event_id = process_line(payload.source, payload.raw, strict=True)
    return {"status": "ok", "event_id": event_id}


def _record_error(errors: list, errors_truncated: bool, line_num: int, message: str) -> bool:
    if len(errors) < _MAX_INGEST_ERRORS:
        errors.append({"line": line_num, "error": message})
        return errors_truncated
    return True


def _ingest_generic_lines(source: str, lines: list) -> dict:
    processed = 0
    errors: list = []
    errors_truncated = False
    for i, line in enumerate(lines, start=1):
        try:
            process_line(source, line, strict=True)
            processed += 1
        except HTTPException as exc:
            errors_truncated = _record_error(errors, errors_truncated, i, str(exc.detail))
        except Exception as exc:
            logger.warning(f"Failed to process line: {exc}")
            errors_truncated = _record_error(errors, errors_truncated, i, str(exc))

    return {
        "status": "ok",
        "processed": processed,
        "failed": len(lines) - processed,
        "errors": errors,
        "errors_truncated": errors_truncated,
    }


def _ingest_csv_lines(source: str, decoder: dict, lines: list) -> dict:
    if not lines:
        return {"status": "ok", "processed": 0, "failed": 0, "errors": [], "errors_truncated": False}

    try:
        header = decoder_engine.parse_csv_header(lines[0])
    except Exception:
        raise HTTPException(status_code=422, detail="CSV header row could not be parsed")

    data_lines = lines[1:]
    processed = 0
    errors: list = []
    errors_truncated = False

    for offset, line in enumerate(data_lines, start=2):
        event = decoder_engine.decode_csv_row(decoder, source, header, line)
        if event is None:
            errors_truncated = _record_error(errors, errors_truncated, offset, "CSV row could not be decoded")
            continue
        try:
            store_and_evaluate(event)
            processed += 1
        except Exception as exc:
            logger.warning(f"Failed to process CSV row: {exc}")
            errors_truncated = _record_error(errors, errors_truncated, offset, str(exc))

    return {
        "status": "ok",
        "processed": processed,
        "failed": len(data_lines) - processed,
        "errors": errors,
        "errors_truncated": errors_truncated,
    }


@router.post("/file")
def ingest_file(
    source: str,
    file: UploadFile,
    _: AuthUser = Depends(require_ingest),
):
    content = file.file.read().decode("utf-8", errors="replace")
    lines = [line for line in content.splitlines() if line.strip()]

    decoder = decoder_engine.get_decoder(source)
    if decoder and decoder.get("type") == "csv":
        return _ingest_csv_lines(source, decoder, lines)
    return _ingest_generic_lines(source, lines)


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

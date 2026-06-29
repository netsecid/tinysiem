import logging
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException

from app.decoder import engine as decoder_engine
from app.rules import engine as rule_engine
from app.storage import chroma_store, duckdb_store

logger = logging.getLogger(__name__)


def process_line(source: str, raw: str, strict: bool = True) -> str:
    """Decode, store, and evaluate rules for a single log line.

    strict=True raises HTTPException(422) if no decoder matches.
    strict=False stores a minimal event when decoding fails (used by beats/syslog).
    """
    event = decoder_engine.decode(source, raw)
    if event is None:
        if strict:
            raise HTTPException(status_code=422, detail="Log line could not be decoded")
        event = {
            "id": str(uuid.uuid4()),
            "source": source,
            "ingested_at": datetime.now(timezone.utc),
            "raw": raw,
        }

    duckdb_store.insert_event(event)

    try:
        chroma_store.upsert_event(event)
    except Exception as exc:
        logger.warning(f"ChromaDB upsert failed (non-fatal): {exc}")

    rule_engine.evaluate(event)
    return event["id"]

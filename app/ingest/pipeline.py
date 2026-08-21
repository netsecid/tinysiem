import logging
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException

from app.decoder import engine as decoder_engine
from app.rules import engine as rule_engine
from app.storage import duckdb_store
from app.watchlists import matcher as watchlist_matcher

logger = logging.getLogger(__name__)


def store_and_evaluate(event: dict) -> str:
    """Insert a decoded event and run it through the rule engine and watchlist matcher."""
    duckdb_store.insert_event(event)
    rule_engine.evaluate(event)
    watchlist_matcher.check_event(event)
    return event["id"]


def process_line(source: str, raw: str, strict: bool = True) -> str:
    """Decode, store, and evaluate rules for a single log line.

    strict=True raises HTTPException(422) if no decoder matches.
    strict=False stores a minimal event when decoding fails (used by beats/syslog).
    """
    event = decoder_engine.decode(source, raw)
    if event is None:
        if strict:
            from app.dashboard.fidelity import record_parse_failure
            record_parse_failure(source)
            raise HTTPException(status_code=422, detail="Log line could not be decoded")
        from app.dashboard.fidelity import record_parse_failure
        record_parse_failure(source)
        event = {
            "id": str(uuid.uuid4()),
            "source": source,
            "ingested_at": datetime.now(timezone.utc),
            "raw": raw,
        }

    return store_and_evaluate(event)

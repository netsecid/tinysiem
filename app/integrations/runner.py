"""Integration scheduler — polls due integrations and ingests results."""
import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Optional

from app.integrations import store as istore
from app.integrations.drivers import DRIVERS
from app.ingest import router as ingest_mod  # reuse ingest logic
from app.storage import duckdb_store

logger = logging.getLogger(__name__)

_POLL_TIMEOUT_S = 30


async def _ingest_events(events: list[dict], actor: str) -> int:
    """Insert pulled events via the same path as POST /ingest/raw."""
    from app.decoder import engine as decoder_engine
    from app.rules import engine as rule_engine

    ingested = 0
    for ev in events:
        raw = ev.get("raw", "")
        source = ev.get("source", "unknown")
        decoded = decoder_engine.decode(source, raw)
        if decoded is None:
            decoded = {
                "id": __import__("uuid").uuid4().hex,
                "source": source,
                "ingested_at": datetime.utcnow(),
                "raw": raw,
            }
        duckdb_store.insert_event(decoded)
        rule_engine.evaluate(decoded)
        ingested += 1
    return ingested


async def run_integration(integration_id: str, triggered_by: str = "scheduler") -> str:
    """Execute one integration poll. Returns run_id."""
    from app.audit import store as audit
    integration = istore.get_integration(integration_id, masked=False)
    if not integration:
        raise ValueError(f"Integration {integration_id} not found")

    driver = DRIVERS.get(integration["integration_type"])
    if not driver:
        raise ValueError(f"Unknown driver: {integration['integration_type']}")

    run_id = istore.insert_run(integration_id)
    audit.log_event(
        "integration.run", "triggered", triggered_by,
        detail={"integration_id": integration_id, "run_id": run_id, "triggered_by": triggered_by},
    )

    try:
        cursor = istore.get_last_cursor(integration_id)
        config = integration.get("config") or {}
        if isinstance(config, str):
            config = json.loads(config)
        credentials = integration.get("credentials") or {}

        events, new_cursor = await asyncio.wait_for(
            driver.pull(config, credentials, cursor),
            timeout=_POLL_TIMEOUT_S,
        )
        ingested = await _ingest_events(events, triggered_by)
        istore.finish_run(
            run_id, "ok",
            events_pulled=len(events),
            events_ingested=ingested,
            next_cursor=new_cursor,
        )
        istore.update_run_status(integration_id, "ok", datetime.utcnow())
        logger.info("Integration %s: pulled %d, ingested %d", integration_id, len(events), ingested)
    except Exception as exc:
        err = str(exc)[:500]
        istore.finish_run(run_id, "error", error_message=err)
        istore.update_run_status(integration_id, "error", datetime.utcnow())
        logger.error("Integration %s failed: %s", integration_id, err)

    return run_id


async def run_due() -> None:
    """Check all enabled integrations and run those that are due."""
    integrations = istore.list_integrations()
    now = datetime.utcnow()
    for integ in integrations:
        if not integ.get("enabled"):
            continue
        last_run = integ.get("last_run_at")
        schedule_min = integ.get("schedule_minutes", 15)
        if last_run:
            last_dt = datetime.fromisoformat(last_run) if isinstance(last_run, str) else last_run
            if now - last_dt < timedelta(minutes=schedule_min):
                continue
        try:
            await run_integration(integ["integration_id"], triggered_by="scheduler")
        except Exception as exc:
            logger.error("Error in integration scheduler for %s: %s", integ["integration_id"], exc)

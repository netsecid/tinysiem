"""GeoIP enrichment — public API.

- ``configure()`` is called at startup (main.py lifespan) and picks the
  provider from settings. Without a configured database the system stays in
  a "disabled" state: enrichment no-ops and the API reports provider="disabled".
- ``enrich_event()`` is the ingest hook (called from duckdb_store.insert_event),
  so every ingest path — /ingest/raw, /ingest/file, beats, syslog, integrations —
  gets geo columns populated for free.
- ``lookup()`` is used by the REST endpoint, the entity page and MCP context
  builders for on-demand single-IP lookups.
"""

from __future__ import annotations

import logging
from typing import Optional, Protocol

from app.config import settings
from app.geoip.provider import (
    CsvGeoProvider,
    MaxMindGeoProvider,
    NullGeoProvider,
    _build_provider,
)


class _GeoProvider(Protocol):
    def lookup(self, ip: str) -> Optional[dict]: ...
    def name(self) -> str: ...
    def describe(self) -> dict: ...

__all__ = [
    "configure",
    "enrich_event",
    "get_provider",
    "lookup",
    "reset",
    "status",
]

logger = logging.getLogger(__name__)

_provider: Optional[_GeoProvider] = None


def configure(db_path: Optional[str] = None, asn_path: Optional[str] = None) -> None:
    """(Re)build the active provider from settings (or explicit overrides).

    Tests pass explicit paths to point at fixture databases.
    """
    global _provider
    db_path = settings.tinysiem_geoip_db_path if db_path is None else db_path
    asn_path = settings.tinysiem_geoip_asn_path if asn_path is None else asn_path
    _provider = _build_provider(db_path or "", asn_path or "")
    logger.info("GeoIP provider: %s", _provider.name())


def reset() -> None:
    """Drop the cached provider + factory cache (used by tests)."""
    global _provider
    _provider = None
    _build_provider.cache_clear()


def get_provider() -> _GeoProvider:
    global _provider
    if _provider is None:
        configure()
    if _provider is None:  # configure() always sets one (Null fallback) — defensive
        raise RuntimeError("GeoIP provider not configured")
    return _provider


def lookup(ip: str) -> Optional[dict]:
    """Single-IP geo lookup. Returns None when no database is configured."""
    try:
        return get_provider().lookup(ip)
    except Exception as exc:  # never let enrichment break the pipeline
        logger.warning("GeoIP lookup failed for %s: %s", ip, exc)
        return None


def enrich_event(event: dict) -> dict:
    """Populate geo columns on a decoded event in place (ingest-time hook).

    Keys written (only when the provider returns them non-null):
    country_code, country_name, city, asn. Events without a source_ip or
    without a configured database pass through untouched.
    """
    ip = event.get("source_ip")
    if not ip:
        return event
    try:
        geo = get_provider().lookup(ip)
    except Exception as exc:
        logger.warning("GeoIP enrichment failed for %s: %s", ip, exc)
        return event
    if geo:
        for key, value in geo.items():
            if value not in (None, ""):
                event[key] = value
    return event


def status() -> dict:
    """Describe the active provider for /health and the /geoip API."""
    provider = get_provider()
    return {
        "enabled": not isinstance(provider, NullGeoProvider),
        "provider": provider.name(),
        "db_path": provider.describe().get("db_path", ""),
    }

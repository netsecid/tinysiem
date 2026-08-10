"""Backfill GeoIP columns on existing events (offline, server must be stopped).

TinySIEM's DuckDB constraint ("no UPDATE on tables with PRIMARY KEY + any
secondary index") makes row-by-row backfill impossible, so this script REBUILDS
the events table: enrich every distinct source_ip once, join it back, and swap
the table. DuckDB's ALTER TABLE RENAME is atomic and fast even at ~1M rows.

Usage (stop the server first — DuckDB is single-writer):
    python scripts/backfill_geoip.py --geoip data/geoip/dbip-country-lite-2026-08-01.csv.gz
    python scripts/backfill_geoip.py --geoip .../GeoLite2-City.mmdb --asn .../GeoLite2-ASN.mmdb
    python scripts/backfill_geoip.py --db /path/to/tinysiem.duckdb --geoip <path>

Steps:
    1. ALTER TABLE events ADD COLUMN (country_code, country_name, city, asn) if missing
    2. SELECT DISTINCT source_ip → lookup each once (cached, batched)
    3. CREATE TABLE events_new AS ... LEFT JOIN geo_lookup
    4. DROP events, RENAME events_new → events, recreate indexes
    5. Verify row count + enrichment coverage
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Make `app.*` importable when run as `python scripts/backfill_geoip.py`.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import duckdb  # noqa: E402

from app.geoip import configure as geoip_configure  # noqa: E402
from app.geoip import reset as geoip_reset  # noqa: E402

_EVENT_COLS = [
    "id", "source", "ingested_at", "event_time", "source_ip", "method", "uri",
    "status_code", "response_size", "user_agent", "referer", "raw", "extra",
]
_GEO_COLS = ["country_code", "country_name", "city", "asn"]
_DESC = __doc__.strip().splitlines()[0] if __doc__ else "Backfill GeoIP columns on existing events."


def main() -> int:
    parser = argparse.ArgumentParser(description=_DESC)
    parser.add_argument("--db", default=None,
                        help="DuckDB path (default: TINYSIEM_DUCKDB_PATH env or "
                             "app/config.py settings)")
    parser.add_argument("--geoip", required=True,
                        help="GeoIP database: db-ip .csv(.gz) or MaxMind .mmdb")
    parser.add_argument("--asn", default=None,
                        help="optional MaxMind GeoLite2-ASN .mmdb")
    args = parser.parse_args()

    from app.config import settings
    db_path = args.db or settings.tinysiem_duckdb_path
    if not Path(db_path).exists():
        print(f"ERROR: database not found: {db_path}", file=sys.stderr)
        return 2

    geoip_configure(db_path=args.geoip, asn_path=args.asn)
    from app.geoip import get_provider
    provider = get_provider()
    if provider.name() == "disabled":
        print(f"ERROR: could not load GeoIP DB: {args.geoip}", file=sys.stderr)
        return 2

    conn = duckdb.connect(db_path)
    try:
        _ensure_geo_columns(conn)

        print("Collecting distinct source IPs ...")
        ips = [r[0] for r in conn.execute(
            "SELECT DISTINCT source_ip FROM events WHERE source_ip IS NOT NULL"
        ).fetchall()]
        print(f"  {len(ips)} unique IPs to look up")

        hits = 0
        rows = []
        for i, ip in enumerate(ips, 1):
            geo = provider.lookup(ip)
            if geo and any(geo.get(k) for k in _GEO_COLS):
                hits += 1
                rows.append((ip,) + tuple(geo.get(k) for k in _GEO_COLS))
            if i % 10_000 == 0:
                print(f"  ... {i}/{len(ips)} looked up ({hits} hits)", file=sys.stderr)
        print(f"  {hits}/{len(ips)} IPs resolved")

        conn.execute("CREATE OR REPLACE TABLE geo_lookup (ip VARCHAR PRIMARY KEY, "
                     "country_code VARCHAR, country_name VARCHAR, city VARCHAR, asn VARCHAR)")
        if rows:
            conn.executemany(
                "INSERT INTO geo_lookup VALUES (?, ?, ?, ?, ?)", rows
            )

        total_before = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        print(f"Rebuilding events table ({total_before} rows) ...")
        select_list = ", ".join([f"e.{c}" for c in _EVENT_COLS]
                                + [f"g.{c}" for c in _GEO_COLS])
        # identifiers come from the constant _EVENT_COLS/_GEO_COLS tuples,
        # never from user input; DDL column lists cannot be parameterized
        ddl = "".join([
            "CREATE TABLE events_new AS SELECT ",
            select_list,
            " FROM events e LEFT JOIN geo_lookup g ON e.source_ip = g.ip",
        ])  # nosec B608
        conn.execute(  # nosemgrep: sqlalchemy-execute-raw-query
            ddl
        )
        conn.execute("DROP TABLE events")
        conn.execute("ALTER TABLE events_new RENAME TO events")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ingested_at ON events (ingested_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_source_ip ON events (source_ip)")

        total_after = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        enriched = conn.execute(
            "SELECT COUNT(*) FROM events WHERE country_code IS NOT NULL"
        ).fetchone()[0]
        conn.execute("DROP TABLE IF EXISTS geo_lookup")

        print(f"Done. rows: {total_before} -> {total_after} "
              f"(enriched: {enriched}, {100.0 * enriched / total_after:.1f}%)")
        if total_before != total_after:
            print("WARNING: row count changed! Inspect before starting the server.",
                  file=sys.stderr)
            return 1
        return 0
    finally:
        conn.close()
        geoip_reset()


def _ensure_geo_columns(conn) -> None:
    existing = {row[1] for row in conn.execute("PRAGMA table_info('events')").fetchall()}
    for col in _GEO_COLS:
        if col not in existing:
            # col comes from the constant _GEO_COLS tuple; DDL identifiers
            # cannot be parameterized
            conn.execute(  # nosemgrep: sqlalchemy-execute-raw-query, formatted-sql-query
                f"ALTER TABLE events ADD COLUMN {col} VARCHAR"
            )
            print(f"Added column {col}")


if __name__ == "__main__":
    raise SystemExit(main())

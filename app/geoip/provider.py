"""Offline GeoIP providers for event enrichment.

Design goals:
- Zero network calls at query time (privacy + no rate limits on ingest paths).
- Zero required dependencies: the default provider parses db-ip.com "lite"
  CSV files (country or city format, plain or .gz) with the stdlib only.
- Optional MaxMind GeoLite2 support via the `geoip2` package (.mmdb files).
- Graceful degradation: no DB configured/missing/unreadable → NullGeoProvider,
  enrichment silently no-ops and the API reports the provider as disabled.

db-ip lite CSV formats (all rows sorted by start_ip ascending):
  country: start_ip,end_ip,country_code,country_name
  city:    start_ip,end_ip,country_code,state_prov,city,latitude,longitude
"""

from __future__ import annotations

import csv
import gzip
import ipaddress
import logging
from functools import lru_cache
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Cache size for the provider factory — keyed by (db_path, asn_path), so tests
# can swap databases by calling configure() + reset().
_PROVIDER_CACHE_SIZE = 2


class NullGeoProvider:
    """No GeoIP database available — every lookup returns None."""

    def lookup(self, ip: str) -> Optional[dict]:
        return None

    def name(self) -> str:
        return "disabled"

    def describe(self) -> dict:
        return {"provider": self.name(), "db_path": ""}


class CsvGeoProvider:
    """Binary-search over db-ip lite CSV ranges (IPv4 + IPv6, family-aware).

    Supports country lite (4 cols, header), city lite (7-8 cols, header) and
    asn lite (3 cols, NO header: start_ip,end_ip,asn_number[,org]).
    """

    def __init__(self, path: str | Path, asn_path: str | Path | None = None):
        self.path = str(path)
        self._v4: list[tuple] = []  # (start_int, end_int, code, name, city)
        self._v6: list[tuple] = []
        self._asn_v4: list[tuple] = []  # (start_int, end_int, "AS<num>")
        self._asn_v6: list[tuple] = []
        self._load()
        if asn_path:
            self._load_asn(asn_path)

    # ── loading ────────────────────────────────────────────────────────────
    def _load(self) -> None:
        open_fn = gzip.open if self.path.endswith(".gz") else open
        with open_fn(self.path, "rt", encoding="utf-8", errors="replace") as fh:
            for row in csv.reader(fh):
                self._add_row(row)
        self._v4.sort(key=lambda r: r[0])
        self._v6.sort(key=lambda r: r[0])
        logger.info(
            "GeoIP CSV loaded: %d IPv4 + %d IPv6 ranges from %s",
            len(self._v4), len(self._v6), self.path,
        )

    def _add_row(self, row: list) -> None:
        """Map a data row to (start, end, code, name, city) by column count.

        db-ip lite formats across releases (header rows fail the IP parse and
        are skipped automatically):
          3 cols  country (2026+):        start, end, country_code
          4 cols  country (legacy):       start, end, country_code, country_name
          7 cols  city (legacy):          start, end, cc, state, city, lat, lon
          8 cols  city (2026+):           start, end, continent, cc, state, city, lat, lon
        """
        n = len(row)
        if n < 3:
            return
        try:
            start = int(ipaddress.ip_address(row[0]))
            end = int(ipaddress.ip_address(row[1]))
        except ValueError:
            return
        if n == 3:
            rec = (start, end, row[2], "", None)
        elif n == 4:
            rec = (start, end, row[2], row[3], None)
        elif n == 7:
            rec = (start, end, row[2], "", row[4])
        elif n >= 8:
            rec = (start, end, row[3], "", row[5])
        else:
            return
        if ":" in row[0] or ":" in row[1]:
            self._v6.append(rec)
        else:
            self._v4.append(rec)

    def _load_asn(self, asn_path: str | Path) -> None:
        self._asn_path = str(asn_path)
        open_fn = gzip.open if self._asn_path.endswith(".gz") else open
        with open_fn(self._asn_path, "rt", encoding="utf-8", errors="replace") as fh:
            for row in csv.reader(fh):
                if len(row) < 3:
                    continue
                try:
                    start = int(ipaddress.ip_address(row[0]))
                    end = int(ipaddress.ip_address(row[1]))
                except ValueError:
                    continue
                rec = (start, end, f"AS{row[2]}")
                if ":" in row[0] or ":" in row[1]:
                    self._asn_v6.append(rec)
                else:
                    self._asn_v4.append(rec)
        self._asn_v4.sort(key=lambda r: r[0])
        self._asn_v6.sort(key=lambda r: r[0])
        logger.info(
            "GeoIP ASN CSV loaded: %d IPv4 + %d IPv6 ranges from %s",
            len(self._asn_v4), len(self._asn_v6), self._asn_path,
        )

    # ── lookups ────────────────────────────────────────────────────────────
    def _search(self, table: list, target: int):
        lo, hi = 0, len(table) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            start, end = table[mid][0], table[mid][1]
            if target < start:
                hi = mid - 1
            elif target > end:
                lo = mid + 1
            else:
                return table[mid]
        return None

    def lookup(self, ip: str) -> Optional[dict]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        target = int(addr)
        hit = self._search(self._v6 if addr.version == 6 else self._v4, target)
        if hit is None:
            return None
        result = {
            "country_code": hit[2],
            "country_name": hit[3] or None,
            "city": hit[4] or None,
            "asn": None,
        }
        if self._asn_v4 or self._asn_v6:
            asn_hit = self._search(
                self._asn_v6 if addr.version == 6 else self._asn_v4, target
            )
            if asn_hit is not None:
                result["asn"] = asn_hit[2]
        return result

    def name(self) -> str:
        return "dbip-csv"

    def describe(self) -> dict:
        return {"provider": self.name(), "db_path": self.path}


class MaxMindGeoProvider:
    """GeoLite2 .mmdb lookup via the optional `geoip2` package.

    Requires `pip install geoip2`. A separate GeoLite2-ASN .mmdb can be
    supplied via TINYSIEM_GEOIP_ASN_PATH to populate the `asn` field.
    """

    def __init__(self, path: str | Path, asn_path: str | Path | None = None):
        import geoip2.database  # optional dependency — ImportError propagates

        self.path = str(path)
        self._reader = geoip2.database.Reader(str(path))
        self._asn_reader = (
            geoip2.database.Reader(str(asn_path)) if asn_path else None
        )
        db_type = (self._reader.metadata().database_type or "").lower()
        self._is_city = "city" in db_type or "enterprise" in db_type
        logger.info(
            "GeoIP MaxMind loaded: %s (%s)%s",
            self.path, db_type,
            " + ASN" if self._asn_reader else "",
        )

    def lookup(self, ip: str) -> Optional[dict]:
        try:
            if self._is_city:
                resp = self._reader.city(ip)
                city = (resp.city or {}).name if hasattr(resp.city, "name") else None
            else:
                resp = self._reader.country(ip)
                city = None
        except Exception:
            return None  # AddressNotFoundError, ValueError, etc. → no match

        result = {
            "country_code": getattr(resp.country, "iso_code", None),
            "country_name": getattr(resp.country, "name", None),
            "city": city,
            "asn": None,
        }
        if self._asn_reader:
            try:
                asn = self._asn_reader.asn(ip)
                if asn.autonomous_system_number:
                    result["asn"] = f"AS{asn.autonomous_system_number}"
            except Exception as exc:  # missing ASN entry → leave asn unset
                logger.debug("ASN lookup failed for %s: %s", ip, exc)
        return result

    def name(self) -> str:
        return "maxmind-mmdb"

    def describe(self) -> dict:
        return {"provider": self.name(), "db_path": self.path}


@lru_cache(maxsize=_PROVIDER_CACHE_SIZE)
def _build_provider(db_path: str, asn_path: str):
    """Factory — cached by path so long-lived lookups reuse the loaded DB."""
    if not db_path:
        return NullGeoProvider()
    path = Path(db_path)
    if not path.exists():
        logger.warning("GeoIP DB not found at %s — geo enrichment disabled", db_path)
        return NullGeoProvider()
    suffix = str(path).lower()
    if suffix.endswith((".csv", ".csv.gz")):
        # asn_path is only meaningful for CSV when it's also a CSV (MaxMind
        # uses it as a separate .mmdb via the MaxMindGeoProvider constructor)
        csv_asn = None
        if asn_path and str(asn_path).lower().endswith((".csv", ".csv.gz")):
            csv_asn = asn_path
        return CsvGeoProvider(path, csv_asn)
    if suffix.endswith(".mmdb"):
        try:
            return MaxMindGeoProvider(path, asn_path or None)
        except ImportError:
            logger.warning(
                "geoip2 is not installed — `pip install geoip2` for MaxMind "
                ".mmdb support; geo enrichment disabled"
            )
            return NullGeoProvider()
    logger.warning("Unsupported GeoIP DB format: %s (use .csv, .csv.gz or .mmdb)", db_path)
    return NullGeoProvider()

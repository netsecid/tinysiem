"""Download the free db-ip.com "lite" GeoIP databases (CC BY 4.0).

No registration required. Produces the CSV files that TinySIEM's CSV GeoIP
provider reads (see app/geoip/provider.py):

    dbip-country-lite-YYYY-MM.csv.gz   (~600 KB)   country-level  (default)
    dbip-city-lite-YYYY-MM.csv.gz      (~30 MB)    city-level     (--city)
    dbip-asn-lite-YYYY-MM.csv.gz       (~20 MB)    ASN/org        (--asn)

Point TINYSIEM_GEOIP_DB_PATH at the country or city file and
TINYSIEM_GEOIP_ASN_PATH at the ASN file (optional, CSV or .mmdb).

Usage:
    python scripts/fetch_geoip_db.py                    # country lite, current month
    python scripts/fetch_geoip_db.py --city --asn       # country + city + ASN
    python scripts/fetch_geoip_db.py --date 2026-08     # specific release (YYYY-MM)
    python scripts/fetch_geoip_db.py --dir data/geoip   # custom output dir

License: db-ip lite is CC BY 4.0 — https://db-ip.com/db/lite.php
"""

from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

_BASE = "https://download.db-ip.com/free"
_UA = "TinySIEM-geoip-fetcher/1.0 (self-hosted SIEM; https://github.com/netsecid/tinysiem)"
_DESC = __doc__.strip().splitlines()[0] if __doc__ else "Fetch db-ip lite GeoIP databases."


def _release_arg(raw: str) -> str:
    """Normalize a --date argument to YYYY-MM (db-ip publishes monthly)."""
    raw = raw.strip()
    if len(raw) == 7 and raw[4] == "-":
        return raw
    if len(raw) == 10 and raw[4] == "-" and raw[7] == "-":
        return raw[:7]
    raise SystemExit(f"ERROR: --date must be YYYY-MM or YYYY-MM-DD, got: {raw!r}")


def fetch(kind: str, release: str, out_dir: Path) -> Path:
    """Download one db-ip lite database (kind = country | city | asn)."""
    filename = f"dbip-{kind}-lite-{release}.csv.gz"
    url = f"{_BASE}/{filename}"
    dest = out_dir / filename
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    print(f"Downloading {url} ...", file=sys.stderr)
    try:
        # URL is built from the constant _BASE (https) plus a fixed
        # `dbip-{kind}-lite-{release}` path; kind is hardcoded by callers and
        # release passes through _release_arg() (validated to YYYY-MM), so the
        # scheme cannot be influenced
        with urllib.request.urlopen(  # nosec B310  # nosemgrep: dynamic-urllib-use-detected
            req, timeout=120
        ) as resp:
            data = resp.read()
    except urllib.error.HTTPError as exc:
        raise SystemExit(
            f"ERROR: {url} -> HTTP {exc.code}. The {release} release may not "
            f"exist yet — try --date YYYY-MM of a previous month."
        )
    dest.write_bytes(data)
    print(f"  -> {dest} ({len(data) / 1024 / 1024:.1f} MB)", file=sys.stderr)
    return dest


def main() -> int:
    parser = argparse.ArgumentParser(description=_DESC)
    parser.add_argument("--date", default=date.today().strftime("%Y-%m"),
                        help="release month YYYY-MM (default: current month)")
    parser.add_argument("--dir", default="data/geoip", help="output directory")
    parser.add_argument("--city", action="store_true",
                        help="also download the city-level database (~30 MB)")
    parser.add_argument("--asn", action="store_true",
                        help="also download the ASN database (~20 MB)")
    args = parser.parse_args()

    release = _release_arg(args.date)
    out_dir = Path(args.dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    country = fetch("country", release, out_dir)
    print(f"\nSet in your .env:\nTINYSIEM_GEOIP_DB_PATH={country.resolve()}")
    if args.city:
        city = fetch("city", release, out_dir)
        print(f"TINYSIEM_GEOIP_DB_PATH={city.resolve()}  # for city-level data")
    if args.asn:
        asn = fetch("asn", release, out_dir)
        print(f"TINYSIEM_GEOIP_ASN_PATH={asn.resolve()}")
    print("\nLicense: CC BY 4.0 (db-ip.com lite)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""GeoIP enrichment tests — providers, ingest hook, API, schema migration.

Isolation notes (repo landmines):
- The session-scoped DuckDB is shared across all test files → every pipeline
  test uses a unique source name (uuid4 hex) and documentation-range IPs.
- The GeoIP provider is a module-level singleton. The `geoip_enabled`
  fixture configures a fixture CSV and resets afterwards, so tests that run
  without it keep the default disabled (Null) provider.
"""

import gzip
import os
import uuid
from datetime import datetime

import duckdb
import pytest

from app.geoip import provider as geoip_provider

# db-ip lite country format. 0.0.0.0/8 is deliberately present: its integer
# range [0, 16777215] contains ::1 — the family split must keep IPv6 lookups
# out of it (would otherwise be a false "Reserved" match).
_COUNTRY_CSV = """start_ip,end_ip,country_code,country_name
0.0.0.0,0.255.255.255,ZZ,Reserved
8.8.8.0,8.8.8.255,US,United States of America
45.153.34.0,45.153.34.255,RU,Russia
2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,JP,Japan
"""

_CITY_CSV = """start_ip,end_ip,country_code,state_prov,city,latitude,longitude
8.8.8.0,8.8.8.255,US,California,Mountain View,37.386,-122.0838
"""

# db-ip asn lite format: start_ip,end_ip,asn_number[,org] — NO header row
_ASN_CSV = """1.0.0.0,1.0.0.255,13335
8.8.8.0,8.8.8.255,15169
45.153.34.0,45.153.34.255,210083
"""


@pytest.fixture
def country_csv(tmp_path):
    p = tmp_path / "country.csv"
    p.write_text(_COUNTRY_CSV)
    return str(p)


@pytest.fixture
def city_csv(tmp_path):
    p = tmp_path / "city.csv"
    p.write_text(_CITY_CSV)
    return str(p)


@pytest.fixture
def gz_csv(tmp_path):
    p = tmp_path / "country.csv.gz"
    with gzip.open(p, "wt") as f:
        f.write(_COUNTRY_CSV)
    return str(p)


@pytest.fixture
def asn_csv(tmp_path):
    p = tmp_path / "asn.csv"
    p.write_text(_ASN_CSV)
    return str(p)


@pytest.fixture
def geoip_enabled(country_csv):
    """Configure the GeoIP provider with a fixture DB, reset on teardown."""
    from app.geoip import configure, reset
    configure(db_path=country_csv)
    yield
    reset()


# ── CSV provider ──────────────────────────────────────────────────────────


def test_csv_provider_country_lite(country_csv):
    p = geoip_provider.CsvGeoProvider(country_csv)
    assert p.lookup("8.8.8.8") == {
        "country_code": "US",
        "country_name": "United States of America",
        "city": None,
        "asn": None,
    }
    assert p.lookup("45.153.34.161")["country_code"] == "RU"
    assert p.lookup("1.1.1.1") is None
    assert p.lookup("not-an-ip") is None


def test_csv_provider_family_isolation(country_csv):
    """IPv6 addresses must never match IPv4 ranges (and vice versa).

    ::1 has integer value 1, which lies inside the 0.0.0.0/8 IPv4 range in
    the fixture — without the family split it would falsely resolve to
    "Reserved". IPv4-mapped IPv6 (::ffff:8.8.8.8) must likewise not resolve
    to the US range.
    """
    p = geoip_provider.CsvGeoProvider(country_csv)
    assert p.lookup("::1") is None
    assert p.lookup("::ffff:8.8.8.8") is None
    assert p.lookup("2001:db8::1")["country_code"] == "JP"


def test_csv_provider_city_lite(city_csv):
    p = geoip_provider.CsvGeoProvider(city_csv)
    g = p.lookup("8.8.8.8")
    assert g["country_code"] == "US"
    assert g["city"] == "Mountain View"


def test_csv_provider_modern_country_3col(tmp_path):
    """2026+ country lite: start,end,country_code — no name, no header."""
    p = tmp_path / "c3.csv"
    p.write_text("8.8.8.0,8.8.8.255,US\n45.153.34.0,45.153.34.255,NL\n")
    prov = geoip_provider.CsvGeoProvider(p)
    g = prov.lookup("8.8.8.8")
    assert g["country_code"] == "US"
    assert g["country_name"] is None


def test_csv_provider_modern_city_8col(tmp_path):
    """2026+ city lite: start,end,continent,cc,state,city,lat,lon."""
    p = tmp_path / "c8.csv"
    p.write_text("8.8.8.0,8.8.8.255,NA,US,California,Mountain View,37.386,-122.0838\n")
    prov = geoip_provider.CsvGeoProvider(p)
    g = prov.lookup("8.8.8.8")
    assert g["country_code"] == "US"
    assert g["city"] == "Mountain View"


def test_csv_provider_gzipped(gz_csv):
    p = geoip_provider.CsvGeoProvider(gz_csv)
    assert p.lookup("45.153.34.161")["country_code"] == "RU"


def test_csv_provider_malformed_rows_are_skipped(tmp_path):
    csv_path = tmp_path / "dirty.csv"
    csv_path.write_text(
        "start_ip,end_ip,country_code,country_name\n"
        "not-an-ip,8.8.8.255,US,Broken\n"       # unparseable → skipped
        "8.8.8.0,8.8.8.255,US,United States\n"  # valid
        "9.9.9.0,9.9.9.255\n"                    # too few columns → skipped
    )
    p = geoip_provider.CsvGeoProvider(csv_path)
    assert p.lookup("8.8.8.8")["country_code"] == "US"
    assert p.lookup("9.9.9.9") is None


def test_csv_provider_asn_lite_merge(country_csv, asn_csv):
    """ASN lite CSV (headerless) enriches lookups with the asn field."""
    p = geoip_provider.CsvGeoProvider(country_csv, asn_path=asn_csv)
    g = p.lookup("8.8.8.8")
    assert g["country_code"] == "US"
    assert g["asn"] == "AS15169"
    g2 = p.lookup("45.153.34.161")
    assert g2["country_code"] == "RU"
    assert g2["asn"] == "AS210083"


def test_csv_provider_headerless_country(tmp_path):
    """A country CSV without a header row still loads (first row is data)."""
    p = tmp_path / "h.csv"
    p.write_text("203.0.113.0,203.0.113.255,US,Example\n")
    prov = geoip_provider.CsvGeoProvider(p)
    assert prov.lookup("203.0.113.9")["country_code"] == "US"


def test_factory_wires_csv_asn(country_csv, asn_csv):
    """configure(db_path, asn_path) with two CSVs enables ASN enrichment."""
    from app.geoip import configure, lookup, reset
    configure(db_path=country_csv, asn_path=asn_csv)
    try:
        g = lookup("8.8.8.8")
        assert g["country_code"] == "US"
        assert g["asn"] == "AS15169"
    finally:
        reset()


# ── MaxMind provider (stubbed — geoip2 optional dependency) ───────────────


def test_maxmind_provider_city_mapping(monkeypatch):
    geoip2 = pytest.importorskip("geoip2")
    import geoip2.database  # submodule is not loaded by `import geoip2`
    import geoip2.errors

    class FakeCity:
        iso_code = "US"
        name = "United States"

    class FakeCountry:
        pass

    class FakeResp:
        country = FakeCity()
        city = type("City", (), {"name": "Mountain View"})()

    class FakeReader:
        def __init__(self, path):
            self._path = path

        def metadata(self):
            return type("Meta", (), {"database_type": "GeoLite2-City"})()

        def city(self, ip):
            if ip == "8.8.8.8":
                return FakeResp()
            raise geoip2.errors.AddressNotFoundError(ip)

    monkeypatch.setattr(geoip2.database, "Reader", FakeReader)
    p = geoip_provider.MaxMindGeoProvider("fake.mmdb")
    g = p.lookup("8.8.8.8")
    assert g["country_code"] == "US"
    assert g["city"] == "Mountain View"
    assert p.lookup("9.9.9.9") is None  # AddressNotFoundError → None


def test_maxmind_provider_country_db_and_asn(monkeypatch):
    geoip2 = pytest.importorskip("geoip2")
    import geoip2.database  # submodule is not loaded by `import geoip2`
    import geoip2.errors

    class FakeCountry:
        iso_code = "RU"
        name = "Russia"

    class FakeResp:
        country = FakeCountry()

    class FakeAsnResp:
        autonomous_system_number = 210083

    class FakeReader:
        def __init__(self, path):
            self._path = path

        def metadata(self):
            return type("Meta", (), {"database_type": "GeoLite2-Country"})()

        def country(self, ip):
            if ip == "45.153.34.161":
                return FakeResp()
            raise geoip2.errors.AddressNotFoundError(ip)

    class FakeAsnReader(FakeReader):
        def asn(self, ip):
            if ip == "45.153.34.161":
                return FakeAsnResp()
            raise geoip2.errors.AddressNotFoundError(ip)

    monkeypatch.setattr(geoip2.database, "Reader", FakeReader)
    p = geoip_provider.MaxMindGeoProvider("fake.mmdb", asn_path="fake-asn.mmdb")
    monkeypatch.setattr(p, "_asn_reader", FakeAsnReader("fake-asn.mmdb"))
    g = p.lookup("45.153.34.161")
    assert g["country_code"] == "RU"
    assert g["asn"] == "AS210083"
    assert g["city"] is None


# ── Enrichment hook ───────────────────────────────────────────────────────


def test_enrich_event_noop_when_disabled():
    from app.geoip import enrich_event, reset
    reset()
    ev = {"source_ip": "8.8.8.8", "raw": "x"}
    assert enrich_event(ev) is ev
    assert "country_code" not in ev


def test_enrich_event_populates_geo(geoip_enabled):
    from app.geoip import enrich_event
    ev = {"source_ip": "45.153.34.161", "raw": "x"}
    enrich_event(ev)
    assert ev["country_code"] == "RU"
    assert ev["country_name"] == "Russia"
    # unknown IP → untouched
    ev2 = {"source_ip": "198.51.100.7", "raw": "x"}
    enrich_event(ev2)
    assert "country_code" not in ev2
    # no source_ip → untouched
    ev3 = {"raw": "x"}
    enrich_event(ev3)
    assert "country_code" not in ev3
    # malformed IP → untouched (never raises)
    ev4 = {"source_ip": "not-an-ip", "raw": "x"}
    enrich_event(ev4)
    assert "country_code" not in ev4


# ── Schema migration ──────────────────────────────────────────────────────


def test_events_schema_migration_adds_geo_columns(tmp_path):
    from app.storage import duckdb_store

    db_path = str(tmp_path / "legacy.duckdb")
    legacy_conn = duckdb.connect(db_path)
    legacy_conn.execute(
        """
        CREATE TABLE events (
            id VARCHAR PRIMARY KEY, source VARCHAR NOT NULL,
            ingested_at TIMESTAMP NOT NULL, event_time TIMESTAMP,
            source_ip VARCHAR, method VARCHAR, uri VARCHAR,
            status_code INTEGER, response_size INTEGER,
            user_agent VARCHAR, referer VARCHAR,
            raw VARCHAR NOT NULL, extra JSON
        )
        """
    )
    legacy_conn.execute(
        "INSERT INTO events (id, source, ingested_at, raw) "
        "VALUES ('legacy-1', 'legacy', '2026-01-01 00:00:00', 'raw')"
    )
    legacy_conn.close()

    duckdb_store.init_db(db_path)
    try:
        cols = {row[1] for row in
                duckdb_store._get_conn().execute("PRAGMA table_info('events')").fetchall()}
        assert {"country_code", "country_name", "city", "asn"} <= cols

        # Explicit geo values pass through insert (enrichment is disabled here)
        event_id = str(uuid.uuid4())
        duckdb_store.insert_event({
            "id": event_id, "source": "legacy", "raw": "raw2",
            "ingested_at": datetime.utcnow(), "event_time": None,
            "source_ip": "8.8.8.8", "method": None, "uri": None,
            "status_code": None, "response_size": None,
            "user_agent": None, "referer": None, "extra": {},
            "country_code": "US", "country_name": "United States",
        })
        ev = duckdb_store.get_event_full(event_id)
        assert ev["country_code"] == "US"
        # pre-existing rows keep NULL geo columns
        old = duckdb_store.get_event_full("legacy-1")
        assert old["country_code"] is None
    finally:
        duckdb_store.close_db()
        duckdb_store.init_db(os.environ["TINYSIEM_DUCKDB_PATH"])


# ── REST API ──────────────────────────────────────────────────────────────


async def test_geoip_api_lookup(client, analyst_headers, geoip_enabled):
    r = await client.get("/geoip/8.8.8.8", headers=analyst_headers)
    assert r.status_code == 200
    d = r.json()
    assert d["ip"] == "8.8.8.8"
    assert d["geo"]["country_code"] == "US"
    assert d["enabled"] is True
    assert d["provider"] == "dbip-csv"


async def test_geoip_api_miss_returns_null_geo(client, analyst_headers, geoip_enabled):
    r = await client.get("/geoip/1.1.1.1", headers=analyst_headers)
    assert r.status_code == 200
    assert r.json()["geo"] is None


async def test_geoip_api_rejects_malformed_ip(client, analyst_headers, geoip_enabled):
    r = await client.get("/geoip/not-an-ip", headers=analyst_headers)
    assert r.status_code == 422


async def test_geoip_api_requires_auth(client):
    r = await client.get("/geoip/8.8.8.8")
    assert r.status_code in (401, 403)


async def test_geoip_api_disabled_when_no_db(client, analyst_headers):
    from app.geoip import reset
    reset()
    r = await client.get("/geoip/8.8.8.8", headers=analyst_headers)
    assert r.status_code == 200
    d = r.json()
    assert d["enabled"] is False
    assert d["geo"] is None


# ── End-to-end ingest pipeline ────────────────────────────────────────────


async def test_ingest_pipeline_enriches_events(client, auth_headers, geoip_enabled):
    """POST /ingest/raw → decoder → enrichment → stored with geo columns."""
    from app.storage import duckdb_store

    raw = (
        '{"event_time": "2026-08-10T10:00:00.000000", '
        '"action": "Failed password", "user": "root", '
        '"source_ip": "45.153.34.161", '
        '"message": "Failed password for root from 45.153.34.161"}'
    )
    r = await client.post(
        "/ingest/raw", json={"source": "sshd", "raw": raw}, headers=auth_headers
    )
    assert r.status_code == 200, r.text
    event_id = r.json()["event_id"]

    ev = duckdb_store.get_event_full(event_id)
    assert ev is not None
    assert ev["source_ip"] == "45.153.34.161"
    assert ev["country_code"] == "RU"
    assert ev["country_name"] == "Russia"

    # Facets expose the country dimension
    facets = duckdb_store.get_event_facets(source="sshd", source_ip="45.153.34.161")
    countries = {f["value"]: f["count"] for f in facets.get("country_code", [])}
    assert countries.get("RU", 0) >= 1

    # Events API serializes the new columns
    events_resp = duckdb_store.query_events(source="sshd", source_ip="45.153.34.161", limit=5)
    assert any(e["id"] == event_id and e["country_code"] == "RU" for e in events_resp["events"])


async def test_ingest_pipeline_skips_enrichment_when_disabled(client, auth_headers):
    from app.geoip import reset
    from app.storage import duckdb_store

    reset()
    raw = (
        '{"event_time": "2026-08-10T10:00:00.000000", '
        '"action": "Accepted password", "user": "ubuntu", '
        f'"source_ip": "198.51.100.{uuid.uuid4().int % 200 + 1}", '
        '"message": "ok"}'
    )
    r = await client.post("/ingest/raw", json={"source": "sshd", "raw": raw}, headers=auth_headers)
    assert r.status_code == 200
    ev = duckdb_store.get_event_full(r.json()["event_id"])
    assert ev["country_code"] is None

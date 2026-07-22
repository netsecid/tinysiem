# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Current State: v1.5

All v1.4 "Hardened Tiny" features shipped and tested (see git history for A1–A10, B1–B3, C1).

v1.5 "Analyst Experience" shipped and tested:
- **E1** entity pivot view — `GET /entities/ip/{value}` + `ui/entity.html`; every rendered IP in Events/Alerts/Cases links to it
- **E2** IOC watchlists — `watchlist_entries` table, CRUD + CSV import under `/watchlists`, ingest-time matching emits `watchlist:<list_name>` alerts
- **E3** rule backtesting — `POST /rules/{name}/backtest` and `POST /rules/backtest` (inline), UI in the rule detail panel
- **E4** saved searches + deep links — `saved_searches` table, owner-scoped `/searches` API, Events/Alerts serialize filter state to the URL and hydrate on load
- **E5** per-rule exceptions — `rule_exceptions` table, `/rules/{name}/exceptions` API, enforced in the rule engine (skips evaluation and excludes from threshold counting)
- **E6** CSV export — `format=csv` on `GET /events`/`GET /alerts`, honoring all filters, 10,000-row cap
- **E7** MITRE ATT&CK coverage matrix — `GET /rules/mitre-coverage` + UI section on the Rules page

**Next version: v1.6.** Deferred from v1.4/v1.5: TOTP/2FA, dependency extras split, audit-log hash chaining, GeoIP enrichment, username/actor entities.

**After v1.6 ships:** update this section to "Current State: v1.6" and set next to v1.7.

**Known DuckDB constraints:**
- DuckDB 1.1.3 fails `UPDATE` on tables with PRIMARY KEY + any secondary index. Do NOT add `CREATE INDEX` to tables that will be updated. Applies to `baselines`, `baseline_violations`, cases tables, `integrations`, `integration_runs`, `case_playbook_steps`, `users`, and `watchlist_entries` (v1.5 — the `active` toggle is a plain `UPDATE`, so this table never gets a secondary index either). Dashboard uses DELETE+INSERT pattern (no UNIQUE on `owner`) to avoid this. `saved_searches` and `rule_exceptions` (also v1.5) are insert/delete-only, so this constraint doesn't apply to them at all.
- DuckDB 1.1.3 also rejects `ALTER TABLE ... ADD COLUMN ... NOT NULL` ("Adding columns with constraints not yet supported"). Only plain `ADD COLUMN ... DEFAULT <value>` (no `NOT NULL`) works — discovered adding `token_epoch`/`must_change_password` to `users` in v1.4; future schema migrations must drop `NOT NULL` from `ALTER TABLE` statements (it's fine on `CREATE TABLE`).

**Environment variables added in v1.2:**
- `TINYSIEM_MASTER_KEY` — Fernet key for credential encryption. Optional (503 if integrations are used without it). Generate with: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`

---

## Build & Run

```bash
# Full rebuild (required after any Python/Dockerfile change)
docker-compose up --build

# Restart only (safe after ui/ HTML-only changes — ui/ is a volume mount)
docker-compose restart tinysiem

# Seed test data (Python stdlib, no pip install needed)
python scripts/ingest_test_logs.py 500

# Bulk-load a real log/CSV file for an investigation (generic, any decoder source)
python scripts/ingest_file.py --source my_custom_csv --file evidence.csv --csv

# Run all tests
pytest app/tests/

# Run a single test
pytest app/tests/test_ingest.py::test_ingest_raw_returns_200

# Health check
curl http://localhost:8000/health
```

**Key rule:** `docker-compose restart` does NOT rebake the image. Any change to `app/` Python files requires `docker-compose up --build`.

---

## Architecture

### Services
- **nginx** (`localhost:8080`) — generates access logs to `./logs/` shared volume
- **tinysiem** (`localhost:8000`) — FastAPI app + serves `ui/` as static files

### Volume mounts (docker-compose)
- `./logs:/app/logs:ro` — nginx logs (read-only in tinysiem)
- `./ui:/app/ui:ro` — UI HTML files (live-reloaded, no rebuild needed)
- `tinysiem_data:/app/data` — DuckDB + alerts (named volume, persists)

### URL layout
- `http://localhost:8000` → redirects to `/ui/events.html`
- `http://localhost:8000/ui/events.html` — Events UI
- `http://localhost:8000/ui/alerts.html` — Alerts UI
- `http://localhost:8000/events` — events API
- `http://localhost:8000/alerts` — alerts API
- `http://localhost:8000/ingest/raw` — log ingestion

---

## Backend Module Layout (`app/`)

```
main.py          → FastAPI entry; CORS middleware; StaticFiles /ui; root redirect; routers
config.py        → pydantic-settings for TINYSIEM_* env vars
auth.py          → Bearer token dependency (HTTPBearer)

ingest/          → POST /ingest/raw, POST /ingest/file
events/          → GET /events, GET /events/facets, GET /events/histogram
alerts/          → GET /alerts, GET /alerts/facets (router.py) + JSONL file writer (file_writer.py)
decoder/         → YAML decoder engine; decoders/nginx_access.yaml
storage/
  duckdb_store.py  → _build_where() helper; query_events(); get_event_facets();
                     get_event_histogram(); insert_event(); count_events_in_window()
rules/           → YAML rule loader + threshold/field_match evaluator
```

### Key duckdb_store details
- Single global `_conn` protected by `threading.Lock()` (`_lock`) — all queries must hold `_lock`
- `_build_where(**kwargs)` → shared parameterized WHERE clause builder used by all query functions
- `count_events_in_window(field, value, window_seconds)` enforces `_ALLOWED_FIELDS` allowlist before constructing the query — add new threshold-queryable fields there
- DuckDB TIMESTAMP stores no timezone. All datetimes are stripped of tzinfo before insert. `_build_where` handles tz-aware datetime params by converting to naive UTC

### Events API endpoints
| Endpoint | Notes |
|---|---|
| `GET /events` | source, source_ip, status_code, status_min, status_max, method, uri, q, start, end, limit, offset |
| `GET /events/facets` | Same filter params as /events; returns `{source, method, status_class, source_ip}` value/count lists |
| `GET /events/histogram` | start, end, buckets (10–200) |

### Alerts API endpoints
| Endpoint | Notes |
|---|---|
| `GET /alerts` | Reads JSONL from `TINYSIEM_ALERTS_PATH`; filters: severity, rule_name, source_ip, q, start, end, limit, offset; sorted newest-first |
| `GET /alerts/facets` | Reads full alerts file; returns `{severity: [...], rule_name: [...]}` counts |

Alert record fields (JSONL): `alert_id`, `triggered_at` (ISO), `rule_name`, `severity`, `mitre_tactic`, `mitre_technique`, `event_id`, `source_ip`, `summary`

---

## Data Flow (ingest)

```
POST /ingest/raw
  → auth check (Bearer token)
  → decoder engine (YAML regex → normalized dict + UUID)
  → DuckDB insert (events table)
  → rule engine (evaluate all YAML rules for this source)
  → alert writer (JSONL append if rule triggers)
```

Decoders and rules are loaded at startup into module-level lists (`_decoders`, `_rules`) via `decoder_engine.load_decoders()` and `rule_engine.load_rules()` in `main.py`'s lifespan.

---

## UI Pages

Both are single self-contained HTML files — no build step, no framework. Vanilla JS + CSS. IBM Plex Sans + IBM Plex Mono from Google Fonts.

All page state lives in a module-level `S` object. Theme (`dark`/`light`) is set as `data-theme` on `<html>` and persisted in `localStorage` (`ts_theme`). API endpoint and key are also persisted (`ts_ep`, `ts_key`).

Search is parsed client-side: `field:value` tokens (`ip:`, `source:`, `status:`, `method:`, `uri:`) are mapped to API params; everything else becomes `q` (full-text on `raw`).

---

## DuckDB Schema

```sql
CREATE TABLE events (
    id              VARCHAR PRIMARY KEY,
    source          VARCHAR NOT NULL,
    ingested_at     TIMESTAMP NOT NULL,   -- naive UTC (no tz stored)
    event_time      TIMESTAMP,
    source_ip       VARCHAR,
    method          VARCHAR,
    uri             VARCHAR,
    status_code     INTEGER,
    response_size   INTEGER,
    user_agent      VARCHAR,
    referer         VARCHAR,
    raw             VARCHAR NOT NULL,
    extra           JSON
)
-- Indexes: idx_ingested_at, idx_source_ip
```

---

## Decoder YAML format

```yaml
name: nginx_access
source: nginx
type: regex          # regex | json | kv
pattern: '^(?P<remote_addr>\S+)...'
fields:
  source_ip: remote_addr
  method: request_method
  # ... maps normalized field names to capture group names
timestamp_field: timestamp
timestamp_format: '%d/%b/%Y:%H:%M:%S %z'
```

A `csv` type is also supported — it reads column names from the file's own header
row (uploaded as line 1) rather than a fixed capture-group pattern, so custom
column names/order need no code changes, just a `fields:` mapping:

```yaml
name: my_custom_csv
source: my_custom_csv
type: csv
fields:
  source_ip: client_ip      # normalized field: your CSV's header name
  status_code: http_status
timestamp_field: event_time  # optional, must be a key in fields:
timestamp_format: '%Y-%m-%d %H:%M:%S'
```

`type: csv` decoders only work via `POST /ingest/file` (they need the header row
from the uploaded content) — not `POST /ingest/raw` or `POST /ingest/beats`.
Column values containing embedded newlines inside quotes are not supported: each
CSV row must be a single line, since files are split line-by-line before decoding.

## Rule YAML format

```yaml
name: http_404_spike
severity: medium     # low | medium | high | critical
source: nginx
condition:
  type: threshold    # threshold | field_match
  field: status_code
  value: 404
  operator: eq       # eq | neq | gt | gte | lt | lte | contains
  threshold_count: 10
  window_seconds: 60
mitre_tactic: "Discovery"
mitre_technique: "T1595"
```

---

## Testing

`pytest.ini` sets `asyncio_mode = auto` — all test functions can be `async` without extra decorators.

`conftest.py` must run before any app module is imported. It:
1. Sets `TINYSIEM_*` env vars pointing to temp dirs
2. Provides `client` (session-scoped `AsyncClient` via ASGI transport) and `auth_headers` fixtures

Do not import `app.*` at module level in test files — conftest order dependency.

---

## Security Constraints (Non-Negotiable)

- All endpoints except `GET /health` and `POST /auth/login` require a valid JWT (obtained via `POST /auth/login`, `Authorization: Bearer <jwt>`); `TINYSIEM_API_KEY` as of v1.4 only authenticates `/ingest/*` (admin+ JWTs also still work there)
- FastAPI `/docs` and `/redoc` disabled unless `TINYSIEM_DEBUG=true`
- Container runs as non-root `appuser`
- Decoder and rule YAML parsed with `yaml.safe_load()` — never `eval()`/`exec()`
- All ingest payloads validated via Pydantic v2 (422 on malformed)
- SQL queries use parameterized `?` placeholders throughout — `count_events_in_window` uses `_ALLOWED_FIELDS` allowlist since field name is interpolated
- CORS defaults to same-origin only as of v1.4; set `TINYSIEM_CORS_ORIGINS` (comma-separated) to allow specific additional origins

---

## Environment Variables

```
TINYSIEM_API_KEY              # required; long random string; scoped to /ingest/* only as of v1.4
TINYSIEM_DEBUG                # false | true (enables /docs)
TINYSIEM_DUCKDB_PATH          # /app/data/tinysiem.duckdb
TINYSIEM_ALERTS_PATH          # /app/data/alerts/alerts.log
TINYSIEM_ALERT_MAX_MB         # 50
TINYSIEM_JWT_SECRET           # required; use a 64-char random string (no default — container won't start without it)
TINYSIEM_JWT_EXPIRY_HOURS     # 24
TINYSIEM_SUPERADMIN_PASSWORD  # initial superadmin password (only used when users table is empty); default: admin
TINYSIEM_SYSLOG_ALLOW_CIDRS   # comma-separated CIDRs allowed to send syslog; empty = allow all sources
TINYSIEM_SYSLOG_MAX_BYTES     # 8192; oversized syslog messages are dropped and counted in /health
TINYSIEM_CORS_ORIGINS         # comma-separated allowed cross-origin URLs; empty = same-origin only
TINYSIEM_TLS_CERT             # path to PEM certificate; set with TINYSIEM_TLS_KEY to serve HTTPS instead of HTTP
TINYSIEM_TLS_KEY              # path to matching PEM private key
```

---

## Do NOT Add (out of scope for this project)

- Real-time SSE / WebSocket log tailing (polling is fine)
- Slack/PagerDuty alert destinations
- Multi-tenant / org isolation
- SBOM UI (a static `/sbom` endpoint is acceptable)
- Rate limiting
- Sigma rule format
- React/Vue/any build-step frontend framework
- ML models (sklearn, ARIMA, Isolation Forest) — z-score only for baselines
- Case SLA timers or automated escalation
- OAuth flow for integrations (service account/API key only)

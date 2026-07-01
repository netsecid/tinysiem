# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Current State: v1.0

All v1.0 features shipped and tested (164 tests passing):
- All v0.9 features +
- **Cases & Workflow**: `app/cases/` module, `ui/cases.html`, 3 new DuckDB tables (cases, case_comments, case_alerts), full CRUD API, sliding detail panel with comment thread
- **Log Sources**: `app/sources/` module, `GET /sources` API, Log Sources section in Configuration UI
- Cases nav link added to all pages

**Known DuckDB constraint:** DuckDB 1.1.3 fails `UPDATE` on tables with PRIMARY KEY + any secondary index. Do NOT add `CREATE INDEX` to tables that will be updated. See `app/storage/duckdb_store.py` comment in `init_cases_tables()`.

**Next version: v1.1** — see `docs/specs/roadmap.md` for the full roadmap and `docs/specs/` for individual specs.

### What to build next (v1.1)

Two independent features:

1. **Smart Baselines** (`app/baselines/`) — spec: `docs/specs/v1.1-smart-baselines.md`
   - 2 new DuckDB tables: `baselines`, `baseline_violations` (no secondary indexes per DuckDB constraint above)
   - Background `asyncio` job runs every 5 min, computes z-scores with Welford's online algorithm
   - New dependency: `numpy` (add to `requirements.txt` + Dockerfile)
   - API: `GET /baselines`, `GET /baselines/violations`, `PATCH /baselines/violations/{id}`, `DELETE /baselines/{source}`

2. **AI Context Enrichment** (`app/ai/enrichment.py`) — spec: `docs/specs/v1.1-ai-enrichment.md`
   - Inject active sources + existing parsers/rules context into existing `/parsers/generate` and `/rules/generate` endpoints (no schema change)
   - Two new endpoints: `POST /ai/explain-alert`, `POST /ai/analyze-events`
   - UI: "Explain with AI" button in alerts expanded row; multi-select + "Analyze with AI" in events

**After v1.1 ships:** update this section to "Current State: v1.1" and set next to v1.2 (Integrations + Dashboard).

---

## Build & Run

```bash
# Full rebuild (required after any Python/Dockerfile change)
docker-compose up --build

# Restart only (safe after ui/ HTML-only changes — ui/ is a volume mount)
docker-compose restart tinysiem

# Seed test data (Python stdlib, no pip install needed)
python scripts/ingest_test_logs.py 500

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
- `tinysiem_data:/app/data` — DuckDB + ChromaDB + alerts (named volume, persists)

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
  chroma_store.py  → ChromaDB upsert (non-fatal; plumbing for future AI triage)
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
  → ChromaDB upsert (non-fatal; embeddings for future AI)
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
2. Stubs `chromadb` in `sys.modules` before any import resolves it
3. Provides `client` (session-scoped `AsyncClient` via ASGI transport) and `auth_headers` fixtures

Do not import `app.*` at module level in test files — conftest order dependency.

---

## Security Constraints (Non-Negotiable)

- All endpoints except `GET /health` require `Authorization: Bearer <TINYSIEM_API_KEY>`
- FastAPI `/docs` and `/redoc` disabled unless `TINYSIEM_DEBUG=true`
- Container runs as non-root `appuser`
- Decoder and rule YAML parsed with `yaml.safe_load()` — never `eval()`/`exec()`
- All ingest payloads validated via Pydantic v2 (422 on malformed)
- SQL queries use parameterized `?` placeholders throughout — `count_events_in_window` uses `_ALLOWED_FIELDS` allowlist since field name is interpolated
- CORS allows `*` origins (local tool, acceptable for this version)

---

## Environment Variables

```
TINYSIEM_API_KEY              # required; long random string (used by log shippers)
TINYSIEM_DEBUG                # false | true (enables /docs)
TINYSIEM_DUCKDB_PATH          # /app/data/tinysiem.duckdb
TINYSIEM_CHROMA_PATH          # /app/data/chroma_store
TINYSIEM_ALERTS_PATH          # /app/data/alerts/alerts.log
TINYSIEM_ALERT_MAX_MB         # 50
TINYSIEM_JWT_SECRET           # required; use a 64-char random string (no default — container won't start without it)
TINYSIEM_JWT_EXPIRY_HOURS     # 24
TINYSIEM_SUPERADMIN_PASSWORD  # initial superadmin password (only used when users table is empty); default: admin
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

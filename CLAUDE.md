# CLAUDE.md

This file provides guidance to Claude Code when working in this repository.

## Current State: v0.3

Backend is fully implemented. Events UI (v0.2) and Alerts UI (v0.3) are both working in Docker. The stack has been tested end-to-end with ingested nginx logs.

---

## Build & Run

```bash
# Full rebuild (required after any Python/Dockerfile change)
docker-compose up --build

# Restart only (safe after UI-only changes — ui/ is a volume mount)
docker-compose restart tinysiem

# Seed test data (Python stdlib, no pip install needed)
python scripts/ingest_test_logs.py 500

# Run tests
pytest app/tests/

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

### Key duckdb_store functions
- `_build_where(**kwargs)` → shared WHERE clause builder used by all query functions
- `query_events(limit, offset, source, source_ip, status_code, status_min, status_max, method, uri, q, start, end)` → paginated events
- `get_event_facets(same kwargs as query_events)` → returns `{source, method, status_class, source_ip}` value/count lists for the sidebar
- `get_event_histogram(start, end, buckets)` → time-bucketed counts for Chart.js sparkline

### Events API endpoints
| Endpoint | Notes |
|---|---|
| `GET /events` | Supports: source, source_ip, status_code, status_min, status_max, method, uri, q, start, end, limit, offset |
| `GET /events/facets` | Same filter params as /events; returns dynamic sidebar data |
| `GET /events/histogram` | start, end, buckets (10–200) |

### Alerts API endpoints
| Endpoint | Notes |
|---|---|
| `GET /alerts` | Reads JSONL from `TINYSIEM_ALERTS_PATH`; filters: severity, rule_name, source_ip, q, start, end, limit, offset; sorted newest-first |
| `GET /alerts/facets` | Reads full alerts file; returns `{severity: [...], rule_name: [...]}` counts for sidebar |

Alert record fields (JSONL): `alert_id`, `triggered_at` (ISO), `rule_name`, `severity`, `mitre_tactic`, `mitre_technique`, `event_id`, `source_ip`, `summary`

---

## UI Pages

Both are single self-contained HTML files. No build step, no framework. Vanilla JS + CSS. IBM Plex Sans + IBM Plex Mono from Google Fonts.

### `ui/events.html` — Events / Live Log Stream
```
NAV (TinySIEM logo → events | Events (active) | Alerts | theme | settings)
TOP AREA
  search bar (field:value syntax + free text)
  active filter chips strip
  histogram (collapsible, Chart.js bar)
BODY (flex row)
  SIDEBAR (232px)
    dynamic facet groups: Source | Status | Method | Source IP
    each value: dot + label + count + proportion bar; click to filter
  MAIN PANEL
    controls bar (limit select | Refresh | Export CSV | result count | pagination)
    events table (sticky header, expandable rows, raw modal)
```

### `ui/alerts.html` — Alerts
```
NAV (TinySIEM logo → events | Events | Alerts (active) | theme | settings)
TOP AREA
  search bar (free text)
  active filter chips strip
BODY (flex row)
  SIDEBAR (232px)
    Severity facet (critical/high/medium/low) with colored dots + proportion bars
    Rule Name facet (top 20 rules by alert count)
  MAIN PANEL
    controls bar (limit select | Refresh | Export CSV | result count | pagination)
    alerts table (triggered time | rule name | severity badge | source IP | MITRE tactic | technique | summary)
    expandable rows with all fields
    full detail modal (all fields + Copy as JSON)
```

### JS state object `S`
```js
S = {
  ep, key,                    // API endpoint + key (localStorage)
  tv, cs, ce,                 // time value (e.g. '1h') + custom start/end ISO
  fq, q,                      // text-search parsed filters + free text
  af,                         // active facet filters {source, method, status_class, source_ip}
  limit, offset, total, page, // pagination
  live, liveT, latest,        // live mode toggle + interval + latest ingested_at seen
  events, hc, rawEv, histOpen // loaded events, Chart instance, raw modal event, histogram state
}
```

### Search syntax (parsed client-side)
- `ip:1.2.3.4` or `source_ip:` → source_ip filter
- `source:nginx` → source filter
- `status:404` or `status_code:` → status_code filter
- `method:GET` → method filter
- `uri:/api` → uri filter
- Everything else → `q` (full-text on raw line)

### Facet filter → API param mapping
- `af.source` → `source=`
- `af.method` → `method=`
- `af.source_ip` → `source_ip=`
- `af.status_class` (e.g. `'4xx'`) → `status_min=400&status_max=499`

### Theme
- `data-theme="dark"` / `data-theme="light"` on `<html>` element
- All colors via CSS custom properties in `:root` and `[data-theme="light"]`
- Persisted in `localStorage` key `ts_theme`

### Config persistence (localStorage)
- `ts_ep` — API endpoint URL
- `ts_key` — API key
- `ts_theme` — dark/light

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

**Important:** DuckDB TIMESTAMP stores no timezone. All datetimes are stripped of tzinfo before insert. API params that are tz-aware datetimes must be converted to naive UTC in `_build_where()`.

---

## Decoder YAML format

```yaml
name: nginx_access
source: nginx
type: regex          # regex | json | kv
pattern: '^(?P<remote_addr>\S+) \S+ \S+ \[(?P<time_local>[^\]]+)\] "(?P<request_method>\S+) (?P<request_uri>\S+) \S+" (?P<status>\d+) (?P<body_bytes_sent>\d+|-) "(?P<http_referer>[^"]*)" "(?P<http_user_agent>[^"]*)"'
fields:
  source_ip: remote_addr
  method: request_method
  uri: request_uri
  status_code: status
  response_size: body_bytes_sent
  user_agent: http_user_agent
  referer: http_referer
  timestamp: time_local
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
  operator: eq
  threshold_count: 10
  window_seconds: 60
mitre_tactic: "Discovery"
mitre_technique: "T1595"
```

---

## Security Constraints (Non-Negotiable)

- All endpoints except `GET /health` require `Authorization: Bearer <TINYSIEM_API_KEY>`
- FastAPI `/docs` and `/redoc` disabled unless `TINYSIEM_DEBUG=true`
- Container runs as non-root `appuser`
- nginx log volume mounted `:ro`
- Decoder and rule YAML parsed with `yaml.safe_load()` — never `eval()`/`exec()`
- All ingest payloads validated via Pydantic v2 (422 on malformed)
- SQL queries use parameterized `?` placeholders throughout — no string interpolation of user values
- CORS allows `*` origins (local tool, acceptable for v0.2)

---

## Environment Variables

```
TINYSIEM_API_KEY       # required; long random string
TINYSIEM_DEBUG         # false | true (enables /docs)
TINYSIEM_DUCKDB_PATH   # /app/data/tinysiem.duckdb
TINYSIEM_CHROMA_PATH   # /app/data/chroma_store
TINYSIEM_ALERTS_PATH   # /app/data/alerts/alerts.log
TINYSIEM_ALERT_MAX_MB  # 50
```

---

## What to Build Next (v0.4)

1. **Dashboard page** (`ui/dashboard.html`) — event volume chart (24h sparkline reusing `/events/histogram`), top source IPs and top rules fired (reusing `/events/facets`), alert severity breakdown (reusing `/alerts/facets`), total events + total alerts counters; no new backend endpoints needed
2. **Wire dashboard in nav** — add `href="/ui/dashboard.html"` to the Dashboard nav item in both `events.html` and `alerts.html`
3. **`test_events.py`** — tests for `query_events`, `get_event_facets`, `get_event_histogram` in `duckdb_store.py`

### Known polish items
- `scripts/ingest_test_logs.py` hardcodes the API key; could read it from `.env` dynamically
- The events table expand-row stopPropagation between expand toggle and raw modal could be tightened

---

## Do NOT Add (out of scope for this project)

- Real-time SSE log tailing (polling is fine)
- Slack/webhook alert destinations
- Multi-user auth or sessions
- AI triage (ChromaDB plumbing exists but no Claude API calls yet)
- Log retention/purge
- Rate limiting
- Sigma rule format
- React/Vue/any build-step frontend framework

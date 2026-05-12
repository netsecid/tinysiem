# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**TinySIEM** is a lightweight, AI-native SIEM built for small security teams. It ingests logs, decodes them, evaluates detection rules, and surfaces alerts — with a ChromaDB semantic layer for future AI triage.

This repo currently contains two specification documents:
- `phase1-infra.md` — backend v0.1 build spec (FastAPI + DuckDB + ChromaDB, Docker)
- `phase1-design.md` — UI mockup spec (single self-contained HTML file, vanilla JS)

## Build & Run Commands

```bash
# Start all services
docker-compose up --build

# Run tests (from inside the app/ directory or via docker exec)
pytest app/tests/

# Run a single test file
pytest app/tests/test_ingest.py -v

# Test a live endpoint (after stack is up)
curl -H "Authorization: Bearer <your-key>" http://localhost:8000/health
curl -X POST http://localhost:8000/ingest/raw \
  -H "Authorization: Bearer <your-key>" \
  -H "Content-Type: application/json" \
  -d '{"source": "nginx", "raw": "<log line>"}'
```

## Architecture

### Services (docker-compose)
- **nginx** (`localhost:8080`) — generates access logs to `./logs/` shared volume
- **tinysiem** (`localhost:8000`) — FastAPI app that reads logs read-only from the shared volume

### Backend Module Layout (`app/`)
```
main.py          → FastAPI entry point; mounts routers; controls /docs via TINYSIEM_DEBUG
config.py        → pydantic-settings loading all TINYSIEM_* env vars
auth.py          → Bearer token dependency injected into protected routes

ingest/          → POST /ingest/raw and POST /ingest/file endpoints
decoder/         → YAML-driven regex/json/kv field extractor; loaded on startup
storage/         → duckdb_store.py (raw SQL, parameterized) + chroma_store.py (embeddings)
rules/           → YAML rule loader + threshold/field_match evaluator; runs after each ingest
alerts/          → file_writer.py; appends JSONL to TINYSIEM_ALERTS_PATH with file lock
```

### Data Flow
```
POST /ingest/raw
  → auth check
  → decoder engine (match source → extract fields → normalized dict + UUID)
  → DuckDB insert (events table)
  → ChromaDB upsert (same UUID, raw line as document)
  → rule engine (evaluate all rules matching source)
  → alert writer (JSONL append if rule triggers)
```

### Storage Schemas
- **DuckDB** `events` table: `id, source, ingested_at, event_time, source_ip, method, uri, status_code, response_size, user_agent, referer, raw, extra (JSON)`
- **ChromaDB** `events` collection: document = decoded raw line, metadata = `{source, ingested_at, source_ip, status_code, uri}`

### Decoder YAML format
```yaml
name: nginx_access
source: nginx
type: regex          # regex | json | kv
pattern: '<named groups>'
fields:              # normalized_name: regex_group_name
  source_ip: remote_addr
  ...
timestamp_field: timestamp
timestamp_format: '%d/%b/%Y:%H:%M:%S %z'
```

### Rule YAML format
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

## Security Constraints (Non-Negotiable)

- All endpoints except `GET /health` require `Authorization: Bearer <TINYSIEM_API_KEY>`
- FastAPI `/docs` and `/redoc` disabled unless `TINYSIEM_DEBUG=true`
- Container runs as non-root user `appuser`
- nginx log volume mounted `:ro` into tinysiem container
- Decoder and rule YAML are parsed safely — never `eval()` or `exec()` external input
- All ingest payloads validated via Pydantic v2 models (422 on malformed)
- `.env`, `*.db`, `chroma_store/`, and `logs/` excluded from version control

## Environment Variables

Defined in `.env` (copy from `.env.example`):
```
TINYSIEM_API_KEY       # required; long random string
TINYSIEM_DEBUG         # false | true (enables /docs)
TINYSIEM_DUCKDB_PATH   # /app/data/tinysiem.duckdb
TINYSIEM_CHROMA_PATH   # /app/data/chroma_store
TINYSIEM_ALERTS_PATH   # /app/data/alerts/alerts.log
TINYSIEM_ALERT_MAX_MB  # 50
```

## UI Mockup (`phase1-design.md`)

The UI is a **single self-contained `.html` file** — no build step, no framework. Vanilla HTML + CSS + JS with Chart.js from CDN. Key constraints:
- All 7 pages (Dashboard, Alerts, Events, Rules, Decoders, Settings, Profile) rendered via JS view-switching — no page reloads
- CSS custom properties for theming; dark/light toggle via `class="light"` on `<html>`, persisted in `localStorage`
- Chart.js 4.4.0 from cdnjs; IBM Plex Sans + IBM Plex Mono from Google Fonts
- Design system: 4px grid, 8px card radius, IBM Plex Mono for all data values (IPs, timestamps, rule names, log lines)

## What Is NOT in v0.1

Do not add: real-time log tailing, Slack/webhook alerts, multi-user auth, AI triage (ChromaDB plumbing exists but no Claude API calls), log retention/purge, rate limiting, Sigma rule format.

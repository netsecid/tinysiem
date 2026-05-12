# TinySIEM v0.1 — Claude Code Build Prompt

## Project Overview

Build **TinySIEM**, a lightweight, AI-native Security Information and Event Management
system. The philosophy: simple by design, flexible by architecture, AI-augmented from
day one. This is not a Wazuh replacement — it is a minimal, composable SIEM that grows
with its operator.

This prompt covers **v0.1 only**: ingest pipeline, dual storage (DuckDB + ChromaDB),
nginx decoder, basic rule engine, and file-based alerting. No UI. No agent. No
complexity that isn't needed yet.

---

## Environment

- **Host OS:** Windows 11 with Docker Desktop
- **Runtime:** Docker + docker-compose (all services containerized)
- **Language:** Python 3.12 (use the official `python:3.12-slim` base image)
- **Architecture:**
  ```
  docker-compose
  ├── nginx          → generates access logs (standard Docker nginx image)
  └── tinysiem       → FastAPI app (DuckDB + ChromaDB embedded inside)
        └── shared volume: reads nginx access.log in real time
  ```

---

## Security Requirements (Non-Negotiable)

These apply to every file generated. Do not skip or defer any of these.

- **API authentication:** All endpoints protected by a static API key passed as
  `Authorization: Bearer <key>` header. Key loaded from environment variable
  `TINYSIEM_API_KEY`. Reject all requests missing or mismatching the key with HTTP 401.
- **No hardcoded secrets:** Every secret, key, and path lives in `.env`.
  Provide `.env.example` with placeholder values and safe defaults.
- **`.env` excluded from version control:** `.gitignore` must include `.env`,
  `*.db`, `chroma_store/`, and `logs/`.
- **Input validation:** All ingest endpoints validate payload structure using
  Pydantic v2 models. Reject malformed payloads with HTTP 422.
- **No arbitrary code execution:** Decoder and rule definitions are YAML files
  parsed safely — never use `eval()` or `exec()` on any external input.
- **Dependency pinning:** All dependencies pinned to exact versions in
  `requirements.txt`. Use only packages with active maintenance and no known
  critical CVEs at time of generation.
- **Minimal attack surface:** No unnecessary endpoints. No debug endpoints in
  production config. FastAPI docs (`/docs`, `/redoc`) disabled by default,
  controlled by `TINYSIEM_DEBUG=false` environment variable.
- **Non-root container:** `Dockerfile` must run the application as a non-root
  user (`appuser`).
- **Read-only volume for logs:** The nginx log volume mounted into TinySIEM
  must be mounted read-only (`:ro`).
- **Structured logging:** Application logs use Python `structlog` or standard
  `logging` in JSON format. Never log raw log line content at INFO level or above
  to avoid log injection.

---

## Tech Stack — Exact Versions

Resolve the latest stable version at time of generation for each. Document the
resolved versions in a comment at the top of `requirements.txt`.

```
fastapi                 # latest stable
uvicorn[standard]       # latest stable
pydantic                # v2 latest stable
pydantic-settings       # latest stable (for .env loading)
duckdb                  # latest stable
chromadb                # latest stable
python-dotenv           # latest stable
pyyaml                  # latest stable
structlog               # latest stable
httpx                   # latest stable (for testing only)
pytest                  # latest stable (for testing only)
pytest-asyncio          # latest stable (for testing only)
```

---

## Project Structure

Generate exactly this structure. Do not add files not listed here.

```
tinysiem/
├── docker-compose.yml
├── .env.example
├── .gitignore
│
├── nginx/
│   └── nginx.conf              # minimal nginx config, access log in combined format
│
├── app/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py                 # FastAPI app entry point
│   ├── config.py               # settings loaded from .env via pydantic-settings
│   ├── auth.py                 # API key dependency
│   │
│   ├── ingest/
│   │   ├── __init__.py
│   │   ├── router.py           # POST /ingest/raw and POST /ingest/file endpoints
│   │   └── models.py           # Pydantic models for ingest payloads
│   │
│   ├── decoder/
│   │   ├── __init__.py
│   │   ├── engine.py           # YAML decoder loader and field extractor
│   │   └── decoders/
│   │       └── nginx_access.yaml   # decoder definition for nginx access logs
│   │
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── duckdb_store.py     # DuckDB init, insert, query functions
│   │   └── chroma_store.py     # ChromaDB init, upsert, semantic search functions
│   │
│   ├── rules/
│   │   ├── __init__.py
│   │   ├── engine.py           # rule loader and evaluator
│   │   └── rules/
│   │       ├── http_404_spike.yaml     # example rule: many 404s from same IP
│   │       └── http_500_error.yaml     # example rule: server errors
│   │
│   ├── alerts/
│   │   ├── __init__.py
│   │   └── file_writer.py      # writes triggered alerts to alerts.log (JSONL format)
│   │
│   └── tests/
│       ├── __init__.py
│       ├── test_ingest.py
│       ├── test_decoder.py
│       └── test_rules.py
│
└── logs/                       # shared volume mount point (nginx writes here)
    └── .gitkeep
```

---

## Component Specifications

### 1. Ingest Endpoints

**POST `/ingest/raw`**
- Accepts a single JSON event: `{ "source": "nginx", "raw": "<log line string>" }`
- Protected by API key
- Passes raw line to decoder engine
- On successful decode: write to DuckDB + ChromaDB, then evaluate rules
- Returns: `{ "status": "ok", "event_id": "<uuid>" }`

**POST `/ingest/file`**
- Accepts multipart file upload (plain text, one log line per line)
- Protected by API key
- Processes each line through the same pipeline as `/ingest/raw`
- Returns: `{ "status": "ok", "processed": <count>, "failed": <count> }`

**GET `/health`**
- Public endpoint (no API key required)
- Returns: `{ "status": "ok", "version": "0.1.0" }`

---

### 2. Decoder Engine

Decoders are YAML files loaded from `app/decoder/decoders/`. Each defines:

```yaml
name: nginx_access
source: nginx
type: regex                    # supported types: regex, json, kv
pattern: '<regex with named groups>'
fields:                        # field mapping: normalized_name: regex_group_name
  timestamp: time_local
  source_ip: remote_addr
  method: request_method
  uri: request_uri
  status_code: status
  response_size: body_bytes_sent
  user_agent: http_user_agent
  referer: http_referer
timestamp_field: timestamp
timestamp_format: '%d/%b/%Y:%H:%M:%S %z'
```

Decoder engine behavior:
- Loads all YAML files from the decoders directory on startup
- Matches incoming log to decoder by `source` field
- Extracts named fields using the pattern
- Returns a normalized event dict with a generated UUID and `ingested_at` timestamp
- If no decoder matches: log a warning, return `None` (do not crash)
- If regex fails to match: log a warning, return `None` (do not crash)

---

### 3. DuckDB Storage

Table name: `events`

```sql
CREATE TABLE IF NOT EXISTS events (
    id              VARCHAR PRIMARY KEY,
    source          VARCHAR NOT NULL,
    ingested_at     TIMESTAMP NOT NULL,
    event_time      TIMESTAMP,
    source_ip       VARCHAR,
    method          VARCHAR,
    uri             VARCHAR,
    status_code     INTEGER,
    response_size   INTEGER,
    user_agent      VARCHAR,
    referer         VARCHAR,
    raw             VARCHAR NOT NULL,
    extra           JSON        -- any fields not in schema go here
);
```

- Database file path loaded from env: `TINYSIEM_DUCKDB_PATH`
- Connection managed with context manager, closed cleanly on shutdown
- No ORM — use raw DuckDB Python API with parameterized queries only
- Index on `ingested_at` and `source_ip` for query performance

---

### 4. ChromaDB Storage

Collection name: `events`

Each document stored with:
- `id`: same UUID as DuckDB event
- `document`: the decoded raw log line (used for embedding)
- `metadata`: `{ source, ingested_at, source_ip, status_code, uri }`

- Persistence directory loaded from env: `TINYSIEM_CHROMA_PATH`
- Use default embedding function (sentence-transformers, local, no API key needed)
- Expose a `search_similar(text, n_results=5)` function for future AI triage use

---

### 5. Rule Engine

Rules are YAML files loaded from `app/rules/rules/`. Each defines:

```yaml
name: http_404_spike
description: "Multiple 404 responses from the same IP in a short window"
severity: medium              # low | medium | high | critical
source: nginx
condition:
  type: threshold             # supported types: threshold, field_match
  field: status_code
  value: 404
  operator: eq                # eq | neq | gt | gte | lt | lte | contains
  threshold_count: 10         # trigger if this many matches in window
  window_seconds: 60
mitre_tactic: "Discovery"
mitre_technique: "T1595"
```

Rule engine behavior:
- Loads all YAML rule files on startup
- After each event is stored, evaluates all rules whose `source` matches
- For `field_match`: check if event field satisfies operator + value
- For `threshold`: query DuckDB — count matching events in the time window
- If rule triggers: pass event + rule metadata to alert writer
- Rules must never crash the ingest pipeline — wrap evaluation in try/except

---

### 6. Alert File Writer

- Writes to `TINYSIEM_ALERTS_PATH` (default: `alerts/alerts.log`)
- Format: one JSON object per line (JSONL)
- Each alert record:

```json
{
  "alert_id": "<uuid>",
  "triggered_at": "<iso8601>",
  "rule_name": "http_404_spike",
  "severity": "medium",
  "mitre_tactic": "Discovery",
  "mitre_technique": "T1595",
  "event_id": "<event uuid>",
  "source_ip": "1.2.3.4",
  "summary": "Rule 'http_404_spike' triggered: 12 events matched in 60s window"
}
```

- File is opened in append mode, written with file lock to avoid corruption
- Rotate log if size exceeds `TINYSIEM_ALERT_MAX_MB` (default: 50)

---

### 7. Docker Setup

**`docker-compose.yml`** must define:

```yaml
services:
  nginx:
    image: nginx:stable-alpine
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./logs:/var/log/nginx          # nginx writes here
    ports:
      - "8080:80"

  tinysiem:
    build: ./app
    env_file: .env
    volumes:
      - ./logs:/app/logs:ro            # tinysiem reads nginx logs (read-only)
      - tinysiem_data:/app/data        # persistent storage for DuckDB + Chroma
    ports:
      - "8000:8000"
    depends_on:
      - nginx

volumes:
  tinysiem_data:
```

**`app/Dockerfile`** requirements:
- Base: `python:3.12-slim`
- Create non-root user `appuser` with no shell
- `COPY requirements.txt` and `pip install --no-cache-dir` before copying source
- Run as `appuser`
- Expose port 8000
- Entrypoint: `uvicorn app.main:app --host 0.0.0.0 --port 8000`

---

### 8. Environment Variables (`.env.example`)

```dotenv
# API Security
TINYSIEM_API_KEY=change-this-to-a-long-random-string

# Application
TINYSIEM_DEBUG=false
TINYSIEM_VERSION=0.1.0

# Storage paths (inside container)
TINYSIEM_DUCKDB_PATH=/app/data/tinysiem.duckdb
TINYSIEM_CHROMA_PATH=/app/data/chroma_store

# Alerts
TINYSIEM_ALERTS_PATH=/app/data/alerts/alerts.log
TINYSIEM_ALERT_MAX_MB=50
```

---

## Tests

Write basic tests covering:
- `test_ingest.py`: POST to `/ingest/raw` with a valid nginx log line returns 200
- `test_ingest.py`: POST to `/ingest/raw` without API key returns 401
- `test_ingest.py`: POST to `/ingest/raw` with malformed payload returns 422
- `test_decoder.py`: nginx decoder correctly extracts all fields from a sample log line
- `test_rules.py`: `field_match` rule triggers correctly on matching event

Use `pytest` with `pytest-asyncio` and `httpx.AsyncClient` for endpoint tests.

---

## What NOT to Build in v0.1

Do not implement the following — they are planned for future versions:

- No UI or dashboard
- No real-time log file tailing (use `/ingest/file` to manually push logs for now)
- No Slack or webhook alert destinations
- No multi-user authentication
- No AI triage or Claude API integration (ChromaDB plumbing only)
- No log retention policy or purge jobs
- No rate limiting on ingest endpoints (future)
- No Sigma rule format compatibility (future)

---

## Deliverables Checklist

Before considering v0.1 complete, verify:

- [ ] `docker-compose up` starts both containers without errors
- [ ] `GET /health` returns 200
- [ ] `POST /ingest/raw` with a valid nginx log line returns 200
  and event appears in DuckDB and ChromaDB
- [ ] `POST /ingest/raw` without API key returns 401
- [ ] Rule `http_500_error` triggers and writes to `alerts.log`
- [ ] `pytest` passes all tests
- [ ] No secrets in any committed file
- [ ] Application runs as non-root inside container

---

## Starting Instructions for Claude Code

1. Read this entire prompt before writing any code.
2. Generate all files in order: `docker-compose.yml` → `Dockerfile` →
   `requirements.txt` → `config.py` → `auth.py` → storage → decoder → rules →
   alerts → ingest → `main.py` → tests.
3. After generating each file, pause and confirm the structure is consistent
   before moving to the next.
4. Do not invent features not listed here.
5. If anything in this prompt is ambiguous, ask before writing code.
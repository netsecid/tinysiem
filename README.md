# TinySIEM

A lightweight, AI-native Security Information and Event Management system built for small security teams, solo analysts, and developers who want a clean alternative to bloated platforms.

TinySIEM ingests logs, decodes them with configurable YAML decoders, evaluates detection rules, writes alerts — and now ships a Datadog-style live Events UI.

---

## What's in v0.3

### Backend
- **Log ingestion** via REST API — single line (`POST /ingest/raw`) or bulk file (`POST /ingest/file`)
- **YAML decoder engine** — regex, JSON, and key-value parsers (nginx access log included)
- **Dual storage** — DuckDB for structured queries, ChromaDB for semantic search
- **YAML rule engine** — `field_match` and `threshold` condition types
- **File-based alerting** — JSONL append log with automatic rotation
- **API key auth** on all endpoints except `GET /health`
- **CORS** enabled for browser-based UI access
- **Events query API** — `GET /events` with full filter, search, pagination, and time-range support
- **Facets API** — `GET /events/facets` returns dynamic value counts (source, status, method, IP) for sidebar rendering
- **Histogram API** — `GET /events/histogram` returns time-bucketed event counts for sparkline charts

### UI (`ui/events.html` + `ui/alerts.html` — served at `http://localhost:8000`)
- Datadog-style **left sidebar** with dynamic facets — source, status class, HTTP method, source IP; each shows value counts with proportion bars; clicking filters the table in real time
- **Search bar** with field syntax: `ip:10.0.0.1 status:404 method:POST /api/login`
- **Collapsible histogram** sparkline above the table (Chart.js)
- **Active filter chips** strip — one chip per active filter with individual remove
- **Dense events table** — time (ms precision), source badge, IP, colored method badge, URI, status badge, response size, raw log (truncated)
- **Expandable rows** — click to reveal all extracted fields; click a field value to add it as a filter
- **Full Raw Log modal** — complete raw line + all parsed fields + Copy Raw / Copy as JSON
- **Live mode** — polls every 3 s, new rows slide in with animation
- **Dark / Light theme** toggle, persisted in localStorage
- **CSV export** of current result set

### Alerts page (`ui/alerts.html`)
- Left sidebar with **Severity** and **Rule Name** facets — click to filter
- Dense alerts table — triggered time, rule name, severity badge (critical/high/medium/low), source IP, MITRE tactic, MITRE technique ID badge, summary
- **Expandable rows** — click to reveal all alert fields inline
- **Full detail modal** — all fields + Copy as JSON
- **CSV export** of current alert set
- Same dark/light theme toggle as Events page, config shared via localStorage

### Scripts
- `scripts/gen_nginx_logs.py` — generate realistic nginx access logs to stdout
- `scripts/ingest_test_logs.py` — generate + POST directly to TinySIEM (no curl needed)

---

## Prerequisites

- Docker Desktop
- Docker Compose v2

No local Python required to run the stack.

---

## Quick Start

**1. Clone and configure**

```bash
git clone https://github.com/your-username/tinysiem.git
cd tinysiem
cp .env.example .env
```

Edit `.env` and set a strong API key:

```dotenv
TINYSIEM_API_KEY=your-long-random-secret-here
```

**2. Start the stack**

```bash
docker-compose up --build
```

This starts:
- **nginx** on `http://localhost:8080` — generates access logs
- **TinySIEM** on `http://localhost:8000` — API + UI

**3. Open the UI**

```
http://localhost:8000
```

Enter your endpoint (`http://localhost:8000`) and API key when prompted. The config is saved in browser localStorage.

**4. Seed some test data**

```bash
# Requires Python 3.x — uses only stdlib, no pip install needed
python scripts/ingest_test_logs.py 500
```

This generates 500 realistic nginx log lines spread over 2 hours and POSTs them directly to the API.

---

## API Reference

All endpoints except `GET /health` require `Authorization: Bearer <TINYSIEM_API_KEY>`.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/ingest/raw` | Ingest a single log line |
| `POST` | `/ingest/file` | Bulk ingest from uploaded file |
| `GET` | `/events` | Query events with filters, search, pagination |
| `GET` | `/events/facets` | Dynamic field value counts for current filter context |
| `GET` | `/events/histogram` | Time-bucketed event counts |
| `GET` | `/alerts` | Query alerts with filters and pagination |
| `GET` | `/alerts/facets` | Severity and rule name counts for sidebar |

**`GET /events` query parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `source` | string | Exact source match |
| `source_ip` | string | IP contains match |
| `status_code` | int | Exact status code |
| `status_min` / `status_max` | int | Status code range (e.g. 400–499 for 4xx) |
| `method` | string | HTTP method (case-insensitive) |
| `uri` | string | URI contains match |
| `q` | string | Full-text search on raw log line |
| `start` / `end` | ISO datetime | Time window |
| `limit` / `offset` | int | Pagination (max limit: 1000) |

---

## Ingesting Logs

**Single line:**

```bash
curl -X POST http://localhost:8000/ingest/raw \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"source": "nginx", "raw": "192.168.1.1 - - [19/May/2026:15:00:00 +0000] \"GET /admin HTTP/1.1\" 403 512 \"-\" \"curl/8.6.0\""}'
```

**Bulk file:**

```bash
curl -X POST "http://localhost:8000/ingest/file?source=nginx" \
  -H "Authorization: Bearer your-api-key" \
  -F "file=@logs/access.log"
```

**Generate and ingest test data (Python, no dependencies):**

```bash
python scripts/ingest_test_logs.py 1000
```

---

## How It Works

```
POST /ingest/raw
  → auth check (Bearer token)
  → decoder engine  (YAML regex → normalized fields + UUID)
  → DuckDB          (structured storage, indexed by time + IP)
  → ChromaDB        (vector storage for future semantic search)
  → rule engine     (field_match / threshold conditions)
  → alert writer    (JSONL append to alerts.log)
```

---

## Project Structure

```
tinysiem/
├── docker-compose.yml
├── .env.example
├── nginx/
│   └── nginx.conf              ← log_format tinysiem (combined-compatible)
├── app/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py                 ← FastAPI entry; CORS; StaticFiles /ui; routers
│   ├── config.py
│   ├── auth.py
│   ├── ingest/                 ← POST /ingest/raw, /ingest/file
│   ├── events/                 ← GET /events, /events/facets, /events/histogram
│   ├── decoder/                ← YAML decoder engine + decoders/nginx_access.yaml
│   ├── storage/
│   │   ├── duckdb_store.py     ← query_events, get_event_facets, get_event_histogram
│   │   └── chroma_store.py
│   ├── rules/                  ← YAML rule engine + rules/
│   ├── alerts/
│   └── tests/
├── ui/
│   └── events.html             ← standalone Events UI (served at /ui/events.html)
├── scripts/
│   ├── gen_nginx_logs.py       ← generate nginx log lines to stdout
│   └── ingest_test_logs.py     ← generate + POST to TinySIEM (stdlib only)
└── logs/                       ← shared volume (nginx writes, tinysiem reads :ro)
```

---

## Decoders

`app/decoder/decoders/*.yaml` — add a YAML file per log source:

```yaml
name: nginx_access
source: nginx
type: regex          # regex | json | kv
pattern: '^(?P<remote_addr>\S+) ...'
fields:
  source_ip: remote_addr
  status_code: status
timestamp_field: timestamp
timestamp_format: '%d/%b/%Y:%H:%M:%S %z'
```

## Rules

`app/rules/rules/*.yaml` — two condition types:

```yaml
name: http_404_spike
severity: medium
source: nginx
condition:
  type: threshold
  field: status_code
  value: 404
  operator: eq
  threshold_count: 10
  window_seconds: 60
mitre_tactic: "Discovery"
mitre_technique: "T1595"
```

---

## Running Tests

```bash
pip install -r app/requirements.txt
pytest
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `TINYSIEM_API_KEY` | *(required)* | Bearer token for API auth |
| `TINYSIEM_DEBUG` | `false` | Enables `/docs` and `/redoc` |
| `TINYSIEM_DUCKDB_PATH` | `/app/data/tinysiem.duckdb` | DuckDB file |
| `TINYSIEM_CHROMA_PATH` | `/app/data/chroma_store` | ChromaDB directory |
| `TINYSIEM_ALERTS_PATH` | `/app/data/alerts/alerts.log` | Alert output |
| `TINYSIEM_ALERT_MAX_MB` | `50` | Alert file rotation limit |

---

## Roadmap

- **v0.4** — Dashboard page (event volume chart, top IPs, top rules fired, alert summary)
- **v0.5** — AI triage via Claude API (ChromaDB plumbing already in place)
- **Future** — Rules editor UI, real-time SSE log tail, Sigma rule format, Slack/webhook alerts

---

## License

MIT — see [LICENSE](LICENSE).

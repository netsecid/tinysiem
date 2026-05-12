# TinySIEM

A lightweight, AI-native Security Information and Event Management system built for small security teams, solo analysts, and developers who want a clean alternative to bloated platforms.

TinySIEM ingests logs, decodes them with configurable YAML decoders, evaluates detection rules, and writes alerts — with a ChromaDB semantic layer ready for AI triage in future versions.

---

## What's in v0.1

- **Log ingestion** via REST API (single line or bulk file upload)
- **YAML decoder engine** — regex, JSON, and key-value parsers (nginx access log included)
- **Dual storage** — DuckDB for structured event queries, ChromaDB for semantic search
- **YAML rule engine** — `field_match` and `threshold` condition types
- **File-based alerting** — JSONL append log with automatic rotation
- **API key auth** on all endpoints except `/health`
- **Docker Compose** setup: nginx log generator + TinySIEM API

---

## Prerequisites

- Docker Desktop
- Docker Compose v2

That's it. No local Python required to run the stack.

---

## Quick Start

**1. Clone and configure**

```bash
git clone https://github.com/your-username/tinysiem.git
cd tinysiem
cp .env.example .env
```

Open `.env` and set a strong API key:

```dotenv
TINYSIEM_API_KEY=your-long-random-secret-here
```

**2. Start the stack**

```bash
docker-compose up --build
```

This starts:
- **nginx** on `http://localhost:8080` — generates access logs
- **TinySIEM API** on `http://localhost:8000`

**3. Verify it's running**

```bash
curl http://localhost:8000/health
# {"status":"ok","version":"0.1.0"}
```

---

## Ingesting Logs

**Single log line:**

```bash
curl -X POST http://localhost:8000/ingest/raw \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "nginx",
    "raw": "192.168.1.1 - - [10/Oct/2023:13:55:36 +0000] \"GET /admin/login HTTP/1.1\" 404 0 \"-\" \"curl/7.88.1\""
  }'
```

Response:

```json
{"status": "ok", "event_id": "3f2a1b4c-..."}
```

**Bulk file upload:**

```bash
curl -X POST "http://localhost:8000/ingest/file?source=nginx" \
  -H "Authorization: Bearer your-api-key" \
  -F "file=@/path/to/access.log"
```

Response:

```json
{"status": "ok", "processed": 120, "failed": 3}
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

### Decoders

Decoders live in `app/decoder/decoders/`. Each YAML file maps a log source to a parsing strategy:

```yaml
name: nginx_access
source: nginx
type: regex
pattern: '^(?P<remote_addr>\S+) ...'
fields:
  source_ip: remote_addr
  status_code: status
  ...
```

Supported types: `regex`, `json`, `kv`.

### Rules

Rules live in `app/rules/rules/`. Two condition types are supported:

**field_match** — triggers when a decoded field satisfies a condition:

```yaml
name: http_500_error
severity: high
source: nginx
condition:
  type: field_match
  field: status_code
  value: 500
  operator: eq        # eq | neq | gt | gte | lt | lte | contains
```

**threshold** — triggers when matching events exceed a count within a time window:

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
```

### Alerts

Triggered alerts are written to `TINYSIEM_ALERTS_PATH` (default: `/app/data/alerts/alerts.log`) in JSONL format:

```json
{
  "alert_id": "uuid",
  "triggered_at": "2026-05-12T10:00:00+00:00",
  "rule_name": "http_500_error",
  "severity": "high",
  "mitre_tactic": "Impact",
  "mitre_technique": "T1499",
  "event_id": "uuid",
  "source_ip": "1.2.3.4",
  "summary": "Rule 'http_500_error' triggered on event uuid"
}
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `TINYSIEM_API_KEY` | *(required)* | Bearer token for API auth |
| `TINYSIEM_DEBUG` | `false` | Enables `/docs` and `/redoc` when `true` |
| `TINYSIEM_DUCKDB_PATH` | `/app/data/tinysiem.duckdb` | DuckDB database file path |
| `TINYSIEM_CHROMA_PATH` | `/app/data/chroma_store` | ChromaDB persistence directory |
| `TINYSIEM_ALERTS_PATH` | `/app/data/alerts/alerts.log` | Alert output file |
| `TINYSIEM_ALERT_MAX_MB` | `50` | Alert file size limit before rotation |

---

## Running Tests

Install dependencies locally (Python 3.12+):

```bash
pip install -r app/requirements.txt
pytest
```

The test suite mocks ChromaDB (no model download) and uses a temporary DuckDB file, so tests run fast without any external services.

---

## Project Structure

```
tinysiem/
├── docker-compose.yml
├── .env.example
├── nginx/
│   └── nginx.conf
├── app/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py           ← FastAPI entry point
│   ├── config.py         ← env var settings
│   ├── auth.py           ← API key dependency
│   ├── ingest/           ← POST /ingest/raw and /ingest/file
│   ├── decoder/          ← YAML decoder engine + decoders/
│   ├── storage/          ← DuckDB and ChromaDB clients
│   ├── rules/            ← YAML rule engine + rules/
│   ├── alerts/           ← JSONL alert file writer
│   └── tests/
└── logs/                 ← shared volume (nginx → tinysiem, read-only)
```

---

## Roadmap

v0.1 is intentionally minimal. Planned for future versions:

- Real-time log file tailing
- Slack / webhook alert destinations
- AI triage using the Claude API (ChromaDB plumbing is already in place)
- Dashboard UI
- Log retention and purge policies
- Sigma rule format compatibility

---

## License

MIT — see [LICENSE](LICENSE).

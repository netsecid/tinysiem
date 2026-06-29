# TinySIEM

A lightweight, self-hosted Security Information and Event Management system for small security teams, solo analysts, and developers who want operational visibility without the complexity of enterprise platforms.

TinySIEM ingests logs from any source, decodes them with YAML-configured parsers, evaluates detection rules in real time, fires alerts, and provides a clean browser-based UI — all running in a single Docker Compose stack.

---

## Features

**Ingestion**
- REST API for single-line and bulk log ingestion
- Beats-compatible endpoint (Filebeat, Winlogbeat, Metricbeat)
- Syslog listener — UDP and TCP, auto-detects RFC 3164 / RFC 5424

**Parsing**
- YAML decoder engine — regex, JSON, and key-value formats
- Built-in decoders: nginx access, syslog RFC 3164/5424, Windows Event Log, AWS CloudTrail, iptables
- AI-assisted parser generation via Claude API
- Hot-reload: add a YAML file, no rebuild required

**Detection**
- YAML rule engine — `field_match`, `threshold`, and multi-step `correlation` types
- MITRE ATT&CK tactic and technique tagging
- AI-assisted rule generation
- Ships with example rules: 404 spike, 500 errors, brute-force-then-success

**Alerting**
- Append-only JSONL alert log with automatic rotation
- Per-alert triage workflow (open → investigating → resolved)
- Email and webhook notifications

**UI**
- Events viewer — search, facets, histogram, expandable rows, live mode
- Alerts viewer — severity/rule facets, triage panel
- Dashboard — 24h summary, top IPs, top rules, severity breakdown
- Parsers — CRUD + AI generator + live test panel
- Rules — CRUD + AI generator
- Audit Log — append-only record of every user action and AI call
- Configuration — all settings in one place
- Dark / light theme

**Security**
- JWT auth (login page → token stored in browser)
- Role-based access control: `superadmin`, `admin`, `analyst`
- Full audit log: auth events, user management, parser/rule changes, AI calls, API errors
- Non-root container, parameterized SQL, `yaml.safe_load` throughout

---

## Quick Start

```bash
# 1. Clone and configure
git clone https://github.com/your-username/tinysiem.git
cd tinysiem
cp .env.example .env
# Edit .env — set TINYSIEM_API_KEY and TINYSIEM_JWT_SECRET

# 2. Start the stack
docker-compose up --build

# 3. Open the UI
open http://localhost:8000
# Login with: admin / (value of TINYSIEM_SUPERADMIN_PASSWORD, default: admin)
```

Seed test data (stdlib only, no pip install needed):
```bash
python scripts/ingest_test_logs.py 500
```

→ See [docs/quickstart.md](docs/quickstart.md) for a full walkthrough including Filebeat and syslog setup.

---

## How It Works

```
Log source (nginx / syslog / Beats / curl)
  → POST /ingest/raw  |  POST /ingest/beats  |  UDP/TCP :5140/:5141
      → auth check
      → decoder engine   — YAML regex/json/kv → normalized event + UUID
      → DuckDB           — structured storage, indexed by time + IP
      → ChromaDB         — vector storage (AI triage, future use)
      → rule engine      — field_match / threshold / correlation
      → alert writer     — JSONL append → notifications
```

---

## Stack

| Component | Technology |
|---|---|
| API | FastAPI (Python 3.12) |
| Storage | DuckDB (events + audit), JSONL (alerts) |
| Vector store | ChromaDB |
| UI | Vanilla HTML/CSS/JS — no build step |
| Container | Docker Compose, non-root `appuser` |
| AI | Claude API (optional — parser/rule generation) |

---

## Documentation

| Doc | Contents |
|---|---|
| [Quick Start](docs/quickstart.md) | Installation, first run, seeding data, Filebeat/syslog setup |
| [API Reference](docs/api-reference.md) | All endpoints, parameters, request/response examples |
| [Decoders](docs/decoders.md) | YAML format, built-in decoders, writing custom parsers |
| [Rules](docs/rules.md) | YAML format, condition types, MITRE tagging, correlation rules |
| [Configuration](docs/configuration.md) | All environment variables |
| [Development](docs/development.md) | Running tests, architecture details, project structure |

---

## License

MIT — see [LICENSE](LICENSE).

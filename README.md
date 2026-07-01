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
- YAML rule engine — `field_match`, `threshold`, and multi-step `correlation` condition types
- MITRE ATT&CK tactic and technique tagging
- AI-assisted rule generation
- Ships with example rules: 404 spike, 500 errors, brute-force-then-success

**Alerting**
- Append-only JSONL alert log with automatic rotation
- Per-alert triage workflow: open → investigating → resolved
- Email (SMTP) and webhook notifications
- AI Explain — one-click Claude analysis of any alert

**Smart Baselines**
- Statistical baseline learning per source and hour-of-day bucket
- Z-score anomaly detection with configurable deviation threshold
- Violation tracking with acknowledgement workflow

**Incident Cases**
- Full case management: create, link alerts, update status, close
- Status lifecycle: open → investigating → resolved
- Notes, severity, and assigned-to tracking per case

**API Integrations**
- Pull-based log polling for AWS CloudTrail and Google Workspace
- Fernet-encrypted credential storage (`TINYSIEM_MASTER_KEY`)
- Background scheduler checks every 60 s; configurable per-integration interval
- Full CRUD API + manual trigger from the UI

**Custom Dashboard**
- Per-user configurable dashboard saved to the database
- 7 widget types: event volume chart, top sources, top IPs, alert severity distribution, recent alerts, case status, baseline health
- Edit mode: add / remove / reconfigure widgets in-browser
- HTML export via the API
- Auto-refresh every 60 s per widget

**UI**
- Events — search, sidebar facets, time histogram, expandable rows, live-tail mode
- Alerts — severity/rule facets, triage panel, AI Explain
- Dashboard — fully configurable, per-user widget layout
- Cases — incident management, linked alert list
- Smart Baselines — health summary, violation table with acknowledge
- Integrations — AWS/Google Workspace, encrypted credentials, run history
- Sources — per-source event counts and last-seen timestamps
- Parsers — CRUD + AI generator + live test panel
- Rules — CRUD + AI generator
- Audit Log — append-only record of every user action and API error
- Configuration — settings, user management (superadmin)
- Dark / light theme

**Security**
- JWT authentication (HS256); login page → token stored in `localStorage`
- Role-based access control: `superadmin` › `admin` › `analyst`
- Full audit log: auth events, user changes, parser/rule edits, AI calls, API errors
- Fernet-encrypted integration credentials at rest
- Constant-time API key comparison (`secrets.compare_digest`)
- Timing-safe login — bcrypt always runs regardless of whether the username exists
- Security response headers: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`
- LIKE wildcard escaping on all filter parameters (prevents filter-bypass via `%` / `_`)
- Non-root container (`appuser`), parameterized SQL, `yaml.safe_load()` throughout

**MCP Server (optional)**
- Model Context Protocol server mountable at `/mcp` for Claude Desktop integration
- 5 tools: `list_events`, `get_alerts`, `list_cases`, `get_baselines`, `run_integration`
- JWT-authenticated, analyst role required

---

## Quick Start

```bash
# 1. Clone and configure
git clone https://github.com/your-username/tinysiem.git
cd tinysiem
cp .env.example .env
# Edit .env — set TINYSIEM_API_KEY, TINYSIEM_JWT_SECRET, and TINYSIEM_SUPERADMIN_PASSWORD
```

Generate strong values:
```bash
openssl rand -hex 32   # TINYSIEM_API_KEY
openssl rand -hex 32   # TINYSIEM_JWT_SECRET
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"  # TINYSIEM_MASTER_KEY (optional — required for Integrations)
```

```bash
# 2. Start the stack
docker-compose up --build

# 3. Open the UI
open http://localhost:8000
# Login with: admin / (value of TINYSIEM_SUPERADMIN_PASSWORD, default: admin)
# Change this password immediately via Configuration → Users
```

Seed test data (Python stdlib only, no pip install):
```bash
python scripts/ingest_test_logs.py 500
```

→ See [docs/quickstart.md](docs/quickstart.md) for a full walkthrough including Filebeat, syslog, and integration setup.

---

## How It Works

```
Log source (nginx / syslog / Beats / curl / integration poller)
  → POST /ingest/raw  |  POST /ingest/beats  |  UDP/TCP :5140/:5141
      → auth check (Bearer token)
      → decoder engine   — YAML regex/json/kv → normalized event + UUID
      → DuckDB           — structured storage (events + audit + cases + baselines + ...)
      → ChromaDB         — vector storage (AI triage, future use)
      → rule engine      — field_match / threshold / correlation
      → alert writer     — JSONL append → email/webhook notifications
```

Background jobs:
```
Scheduler (asyncio, every 60 s)
  → integration runner  — pull events from AWS CloudTrail / Google Workspace
  → baseline learner    — update per-source hourly buckets
```

---

## Stack

| Component | Technology |
|---|---|
| API | FastAPI (Python 3.12) |
| Storage | DuckDB — events, alerts triage, cases, baselines, integrations, dashboard, audit |
| Alert log | JSONL (append-only, rotated at configurable size) |
| Vector store | ChromaDB |
| UI | Vanilla HTML/CSS/JS — no build step |
| Container | Docker Compose, non-root `appuser` |
| AI | Claude API (optional — parser/rule generation, alert explain) |
| Credentials | `cryptography` (Fernet AES-128-CBC + HMAC-SHA256) |

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
| [Troubleshooting](docs/troubleshooting.md) | Common errors and fixes for startup, auth, ingest, rules, UI |

---

## License

MIT — see [LICENSE](LICENSE).

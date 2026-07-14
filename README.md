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

**Security & Hardening**
- JWT authentication (HS256), role-based access control: `superadmin` › `admin` › `analyst`
- Login brute-force lockout — exponential backoff per `(username, IP)` after repeated failures
- Forced password change for the seeded superadmin while it holds the default password, 12-character minimum on every password
- Token revocation — per-user `token_epoch` + `POST /auth/logout`; password change, role change, or user update instantly invalidates existing sessions for that user
- Global API key scoped to `/ingest/*` only — every other endpoint requires a JWT from `POST /auth/login`
- Syslog listener source-CIDR allowlist + message size cap, with drop counters in `/health`
- Content-Security-Policy on the UI + fully self-hosted fonts and scripts — **zero external network requests at runtime** (air-gap friendly)
- CORS defaults to same-origin only; opt in specific origins via `TINYSIEM_CORS_ORIGINS`
- Built-in TLS — set `TINYSIEM_TLS_CERT`/`TINYSIEM_TLS_KEY` to serve HTTPS directly, no reverse proxy required
- Startup guardrails: refuses to boot with a weak `TINYSIEM_JWT_SECRET`; warns on a still-default superadmin password or a missing `TINYSIEM_MASTER_KEY` with integrations configured
- Static `/sbom` endpoint — installed dependency inventory generated at build time
- Full audit log: auth events, user changes, parser/rule edits, AI calls, API errors
- Fernet-encrypted integration credentials at rest
- Constant-time API key comparison (`secrets.compare_digest`)
- Timing-safe login — bcrypt always runs regardless of whether the username exists
- Security response headers: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`
- LIKE wildcard escaping on all filter parameters (prevents filter-bypass via `%` / `_`)
- Non-root container (`appuser`), parameterized SQL, `yaml.safe_load()` throughout

**SOC Quality of Life**
- Per-rule alert suppression window — repeated firings for the same rule + source IP collapse into one alert with a `suppressed_count`
- Self-monitoring — security-relevant events (failed logins, lockouts, user/integration changes) feed the detection pipeline as their own source, with a built-in rule that alerts on brute-force attempts against TinySIEM itself
- One-shot backup endpoint — DuckDB export (Parquet) + alerts + custom rules/decoders as a downloadable tar.gz; see [Backup & Restore](docs/backup.md)

**Analyst Experience**
- Entity pivot view — click any IP in Events, Alerts, or Cases to see first/last seen, event volume histogram, top methods/URIs/status codes, and every related alert and case
- IOC watchlists — match ingested events against IP/CIDR/user-agent-substring/URI-substring indicator lists; a hit fires a `watchlist:<list_name>` alert; CSV import for bulk loading from any threat-intel export
- Rule backtesting — "what would this rule have fired on in the last N days?" for both saved and not-yet-saved rules, with sample matches
- Saved searches + shareable deep links — Events and Alerts serialize their current filters into the URL; paste it to a teammate or save it as a named search
- Per-rule exceptions — except a known-noisy field/value from a specific rule (with a mandatory reason) instead of disabling the whole rule
- CSV export — server-side, honors every active filter, proper quoting, 10,000-row cap
- MITRE ATT&CK coverage matrix — see which of the 14 Enterprise tactics your loaded rules actually cover

**MCP Server (optional)**
- Model Context Protocol server mountable at `/mcp` for Claude Desktop integration
- 5 tools: `list_events`, `get_alerts`, `list_parsers`, `list_rules`, `get_health`
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
```

If `TINYSIEM_SUPERADMIN_PASSWORD` was left at its default (`admin`), the login page will
prompt for a new password (12+ characters) immediately after the first login — this is
enforced by the server, not optional. Set a strong value before first boot to skip it.

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
      → rule engine      — field_match / threshold / correlation, source-scoped counting
      → alert writer     — JSONL append (suppression-aware) → email/webhook notifications
```

Security-relevant audit events (failed logins, lockouts, user/integration changes) are
additionally mirrored into the same pipeline as source `tinysiem_internal`, so the rule
engine can alert on attacks against TinySIEM itself.

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
| Storage | DuckDB — events, alerts triage, cases, baselines, integrations, dashboard, audit, users |
| Alert log | JSONL (append-only, rotated at configurable size, suppression-aware) |
| UI | Vanilla HTML/CSS/JS — no build step; self-hosted fonts + scripts (zero external requests) |
| Container | Docker Compose, non-root `appuser`; optional built-in TLS via env vars |
| AI | Claude API (optional — parser/rule generation, alert explain) |
| Credentials | `cryptography` (Fernet AES-128-CBC + HMAC-SHA256) |

---

## Documentation

| Doc | Contents |
|---|---|
| [Quick Start](docs/quickstart.md) | Installation, first run, seeding data, Filebeat/syslog setup |
| [API Reference](docs/api-reference.md) | All endpoints, parameters, request/response examples |
| [Integrations](docs/integrations.md) | AWS CloudTrail and Google Workspace setup guides |
| [Decoders](docs/decoders.md) | YAML format, built-in decoders, writing custom parsers |
| [Rules](docs/rules.md) | YAML format, condition types, MITRE tagging, correlation rules |
| [Configuration](docs/configuration.md) | All environment variables, TLS setup, security checklist |
| [Backup & Restore](docs/backup.md) | Triggering a backup, manual restore procedure |
| [Development](docs/development.md) | Running tests, architecture details, project structure |
| [Troubleshooting](docs/troubleshooting.md) | Common errors and fixes for startup, auth, ingest, rules, UI |

---

## License

MIT — see [LICENSE](LICENSE).

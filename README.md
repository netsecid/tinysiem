# TinySIEM

A lightweight, self-hosted Security Information and Event Management system for small security teams, solo analysts, and developers who want operational visibility without the complexity of enterprise platforms.

TinySIEM ingests logs from any source, decodes them with YAML-configured parsers, evaluates detection rules in real time, fires alerts, and provides a clean browser-based UI — all running in a single Docker Compose stack.

---

## Features

**Ingestion**
- REST API for single-line and bulk log ingestion
- Beats-compatible endpoint (Filebeat, Winlogbeat, Metricbeat)
- Syslog listener — UDP and TCP, auto-detects RFC 3164 / RFC 5424
- Real-time file tailers — `scripts/ingest_auth_log.py --follow` (sshd auth.log) and `scripts/ingest_syslog_tail.py` (any raw-log file: ufw, fail2ban, …); logrotate-aware, per-line HTTP retry, systemd-ready

**Parsing**
- YAML decoder engine — regex, JSON, and key-value formats
- Built-in decoders: nginx access, syslog RFC 3164/5424, Windows Event Log, AWS CloudTrail, iptables, ufw, fail2ban — plus a custom sshd auth-log decoder
- AI-assisted parser generation (Anthropic, OpenAI, DeepSeek, opencode — or any OpenAI-compatible endpoint)
- Hot-reload: add a YAML file, no rebuild required

**Detection**
- YAML rule engine — `field_match`, `threshold`, and multi-step `correlation` condition types
- MITRE ATT&CK tactic and technique tagging
- AI-assisted rule generation
- Ships with example rules: 404 spike, 500 errors, brute-force-then-success, SSH brute-force, fail2ban ban/unban, ufw repeated-block

**Alerting**
- Append-only JSONL alert log with automatic rotation
- Per-alert triage workflow: open → investigating → resolved
- Email (SMTP) and webhook notifications
- AI Explain — one-click AI analysis of any alert

**Smart Baselines**
- Statistical baseline learning per source and hour-of-day bucket
- Z-score anomaly detection with configurable deviation threshold
- Violation tracking with acknowledgement workflow

**Incident Cases**
- Full case management: create from scratch, from an alert, or directly from a raw event
- Link/unlink alerts and events, comment timeline, per-rule playbook step tracking
- Status lifecycle: open → investigating → resolved (with a required true/false-positive classification on close)

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
- **Detection Fidelity tab** — executive SOC pipeline view: **KPI strip** (sources, events, rules, alerts rate, total alerts, Fidelity %) over **3 detail panels** (data sources, top rules by alerts in window, recent alerts) + outcomes footnote; Fidelity % (`100×TP/(TP+FP+benign)`, null-guarded, all-time, **low-sample tag below 10 classified cases**); **1m/1h/24h window filter** drives all volume metrics (units adapt); `#fidelity` deep-link, dark + light themes
- **Detection Coverage tab** — MITRE ATT&CK Navigator-style heatmap: KPI strip (rules mapped · techniques covered · tactics covered · alerts · matrix version · unmapped) + summary line + full matrix with all 14 tactics and ≥190 techniques (covered cells + gaps), log-scaled alert intensity, hover tooltips, click-to-drill rule list + recent alerts; matrix bundled as `app/rules/data/mitre_enterprise.json` (MITRE STIX, ATT&CK v18.1 default); `#coverage` deep-link, 1m/1h/24h filter, dark + light themes; rule create/update validates (tactic, technique) pair against the matrix
- Auto-refresh every 60 s per widget

**UI**
- Home — AI natural-language search landing page with structured results (target badge, filter chips, ranked top-IP table with country flags, severity pills, deep-link); falls back to manual search links if no provider is configured
- Events — search, sidebar facets, time histogram, expandable rows, live-tail mode, New Case / Add to Case
- Alerts — severity/rule facets, triage panel, AI Explain, New Case / Add to Case
- Dashboard — fully configurable, per-user widget layout + Detection Fidelity executive pipeline tab
- Cases — incident management, linked alert and event list, comments, playbook
- Entity pivot — click any IP anywhere to see its history and every related alert/case
- Rules — CRUD + AI generator + backtest + MITRE coverage tab
- Parsers — CRUD + AI generator + live test panel
- Settings — one tabbed page: Instance, Users & Access, Notifications, Retention, Ingestion, Baselines, Integrations, Sources, Reports, AI Config (admin/superadmin)
- Audit Log — append-only record of every user action and API error (superadmin)
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

**GeoIP Enrichment**
- Offline IP → country/city/ASN enrichment at ingest — db-ip lite CSV (stdlib-only, no registration) or MaxMind GeoLite2 `.mmdb`
- New event columns `country_code` / `country_name` / `city` / `asn`; per-country threshold rules and `/events/facets` counts
- `GET /geoip/{ip}` lookup endpoint, geolocation card on the entity page, flag badge in the events table
- `scripts/fetch_geoip_db.py` (download) + `scripts/backfill_geoip.py` (enrich historical events; run with the server stopped)

**Read-Only SQL Sandbox**
- `POST /query/sql` — run `SELECT`/`WITH`/`SHOW`/`DESCRIBE`/`EXPLAIN`/`VALUES` against the event store, for analysts and AI agents
- Safety model: statement allowlist, blocked-keyword scan, row cap + cell truncation, thread-based timeout, single-flight lock — and every query is audited
- JWT-gated (analyst+), uses an in-process second connection so it never contends with the writer

**Real-Time Log Tailers**
- `scripts/ingest_auth_log.py --follow` — tail sshd `auth.log` (tail -F semantics, inode detection across logrotate, per-line retry)
- `scripts/ingest_syslog_tail.py --source <decoder> --follow <file>` — generic raw-line tailer; lines with no decoder match (422) are skipped, not retried
- Designed to run as systemd units — exactly one tailer per file (two = duplicate events)

**MCP Server (optional)**
- Model Context Protocol server at `/mcp/sse` (SSE transport) for Claude Desktop and other MCP clients
- 8 tools: `list_events`, `get_alerts`, `list_parsers`, `list_rules`, `get_health`, `investigate_ip`, `get_alert_context`, `query_events_sql`
- JWT-authenticated, analyst role required

---

## Quick Start

```bash
# 1. Clone and configure
git clone https://github.com/netsecid/tinysiem.git
cd tinysiem
cp .env.example .env
# Edit .env — set TINYSIEM_API_KEY, TINYSIEM_JWT_SECRET, and TINYSIEM_SUPERADMIN_PASSWORD
```

Generate strong values:
```bash
openssl rand -hex 32   # TINYSIEM_API_KEY
openssl rand -hex 32   # TINYSIEM_JWT_SECRET
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"  # TINYSIEM_MASTER_KEY (required for API Integrations and saving an AI provider API key)
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

## Native Run (no Docker)

TinySIEM also runs directly on Python 3.11+ — useful on hosts where Docker isn't available:

```bash
python3.11 -m venv .venv && .venv/bin/pip install -r app/requirements.txt
cp .env.example .env   # set TINYSIEM_UI_DIR to the repo's ui/ path
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Set `TINYSIEM_UI_DIR=<repo>/ui` so the UI is served from the native checkout, and add
`--ssl-certfile/--ssl-keyfile` for HTTPS (see [Configuration → TLS](docs/configuration.md#tls)).
The live deployment runs this way under systemd (see [Development](docs/development.md)).

---

## How It Works

A log line is ingested (REST, syslog, Beats, or a file tailer), decoded by a YAML parser into a normalized event, enriched with GeoIP country/city/ASN when a database is configured, stored in DuckDB, checked against the IOC watchlist, and evaluated by the rule engine — a match writes an alert, which can trigger an email/webhook and feed into a case. Everything runs through one shared pipeline regardless of entry point, including security-relevant events about TinySIEM itself (failed logins, lockouts), so the same rule engine can detect attacks against the tool.

→ See [Architecture](docs/architecture.md) for the full diagram-first walkthrough — system overview, the ingest-to-alert sequence, the AI provider abstraction, and background jobs.

---

## Stack

| Component | Technology |
|---|---|
| API | FastAPI (Python 3.12) |
| Storage | DuckDB — events, cases (+ alert/event links), users, baselines, watchlists, saved searches, integrations, dashboard, audit; GeoIP via offline db-ip CSV / MaxMind mmdb |
| Alert log | JSONL (append-only, rotated at configurable size, suppression-aware) |
| UI | Vanilla HTML/CSS/JS — no build step; self-hosted fonts + scripts (zero external requests) |
| Container | Docker Compose, non-root `appuser`; optional built-in TLS via env vars |
| AI | Optional, provider-agnostic — Anthropic, OpenAI, DeepSeek, or any OpenAI-compatible endpoint, configured in-app (no env var) |
| Credentials | `cryptography` (Fernet AES-128-CBC + HMAC-SHA256) |

---

## Documentation

| Doc | Contents |
|---|---|
| [Architecture](docs/architecture.md) | Diagram-first high-level overview — system design, data flow, AI layer, background jobs |
| [Quick Start](docs/quickstart.md) | Installation, first run, seeding data, Filebeat/syslog setup |
| [API Reference](docs/api-reference.md) | All endpoints, parameters, request/response examples |
| [Integrations](docs/integrations.md) | AWS CloudTrail and Google Workspace setup guides |
| [Decoders](docs/decoders.md) | YAML format, built-in decoders, writing custom parsers |
| [Rules](docs/rules.md) | YAML format, condition types, MITRE tagging, correlation rules |
| [Configuration](docs/configuration.md) | All environment variables, AI provider setup, TLS setup, security checklist |
| [Backup & Restore](docs/backup.md) | Triggering a backup, manual restore procedure |
| [Development](docs/development.md) | Running tests, project structure, implementation notes |
| [Troubleshooting](docs/troubleshooting.md) | Common errors and fixes for startup, auth, ingest, rules, UI |

---

## License

MIT — see [LICENSE](LICENSE).

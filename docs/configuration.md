# Configuration

All configuration is via environment variables. Copy `.env.example` to `.env` and edit before starting the stack.

---

## Required

| Variable | Description |
|---|---|
| `TINYSIEM_API_KEY` | Bearer token for machine-to-machine ingest. Use a long random string (32+ chars). |
| `TINYSIEM_JWT_SECRET` | Secret used to sign JWTs. Use a 64-char random string. Container will not start without this. |

Generate strong values:
```bash
openssl rand -hex 32   # TINYSIEM_API_KEY
openssl rand -hex 32   # TINYSIEM_JWT_SECRET
```

---

## Authentication

| Variable | Default | Description |
|---|---|---|
| `TINYSIEM_JWT_EXPIRY_HOURS` | `24` | JWT lifetime in hours |
| `TINYSIEM_SUPERADMIN_PASSWORD` | `admin` | Initial password for the `admin` superadmin account. Only used when the users table is empty (first boot). **Change after first login.** |

---

## Storage

| Variable | Default | Description |
|---|---|---|
| `TINYSIEM_DUCKDB_PATH` | `/app/data/tinysiem.duckdb` | DuckDB database file path |
| `TINYSIEM_CHROMA_PATH` | `/app/data/chroma_store` | ChromaDB vector store directory |
| `TINYSIEM_ALERTS_PATH` | `/app/data/alerts/alerts.log` | Alert JSONL output file |
| `TINYSIEM_ALERT_MAX_MB` | `50` | Alert file size limit before rotation (MB) |

---

## Retention

| Variable | Default | Description |
|---|---|---|
| `TINYSIEM_RETENTION_DAYS` | `90` | Events older than this are archived and removed from DuckDB |
| `TINYSIEM_ARCHIVE_PATH` | `/app/data/archive` | Directory for archived event files (Parquet) |

---

## Syslog Listeners

| Variable | Default | Description |
|---|---|---|
| `TINYSIEM_SYSLOG_UDP_PORT` | `5140` | UDP syslog listener port. Set to `0` to disable. |
| `TINYSIEM_SYSLOG_TCP_PORT` | `5141` | TCP syslog listener port. Set to `0` to disable. |

---

## Beats Endpoint

| Variable | Default | Description |
|---|---|---|
| `TINYSIEM_BEATS_ENABLED` | `true` | Enable the `POST /ingest/beats` Elasticsearch-compatible bulk endpoint |

---

## Notifications

| Variable | Default | Description |
|---|---|---|
| `TINYSIEM_SMTP_HOST` | `` | SMTP server hostname. Leave empty to disable email alerts. |
| `TINYSIEM_SMTP_PORT` | `587` | SMTP port |
| `TINYSIEM_SMTP_FROM` | `` | Sender email address |
| `TINYSIEM_SMTP_TO` | `` | Recipient email address |
| `TINYSIEM_SMTP_TLS` | `true` | Use STARTTLS |
| `TINYSIEM_SMTP_USER` | `` | SMTP username |
| `TINYSIEM_SMTP_PASS` | `` | SMTP password |
| `TINYSIEM_WEBHOOK_URL` | `` | Webhook URL for alert notifications. Leave empty to disable. |
| `TINYSIEM_NOTIFY_MIN_SEV` | `high` | Minimum severity to trigger notifications: `low`, `medium`, `high`, `critical` |

---

## Reports

| Variable | Default | Description |
|---|---|---|
| `TINYSIEM_REPORT_SCHEDULE` | `disabled` | Scheduled report cadence: `disabled`, `daily`, or `weekly` |

---

## API Integrations

| Variable | Default | Description |
|---|---|---|
| `TINYSIEM_MASTER_KEY` | `` | Fernet key for encrypting integration credentials at rest. **Required to use API Integrations.** Returns `503` on integration endpoints when not set. |

Generate a Fernet key:
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

The key must be exactly 32 URL-safe base64-encoded bytes (44 characters including the trailing `=`). Store it only in `.env` — never commit it to version control. If the key is rotated, existing integration credentials must be re-entered because they were encrypted with the old key.

---

## AI (Claude API)

| Variable | Default | Description |
|---|---|---|
| `TINYSIEM_CLAUDE_API_KEY` | `` | Anthropic API key. Leave empty to disable AI features. Parser/rule generation and Alert Explain return `503` when not set. |

---

## MCP Server

| Variable | Default | Description |
|---|---|---|
| `TINYSIEM_MCP_ENABLED` | `false` | Mount the Model Context Protocol server at `/mcp` for Claude Desktop integration. Set to `true` to enable. |

When enabled, Claude Desktop can query TinySIEM via the MCP protocol using a valid JWT. Requires `analyst` role or above.

---

## Debug

| Variable | Default | Description |
|---|---|---|
| `TINYSIEM_DEBUG` | `false` | Enable FastAPI `/docs` and `/redoc` (Swagger / ReDoc). **Never enable in production.** |

---

## Security Checklist

Before exposing TinySIEM outside localhost:

- [ ] `TINYSIEM_API_KEY` — long random string, not the default placeholder
- [ ] `TINYSIEM_JWT_SECRET` — 64+ char random string, not the default placeholder
- [ ] `TINYSIEM_SUPERADMIN_PASSWORD` — changed from `admin` on first login (or set a strong value before first boot)
- [ ] `TINYSIEM_DEBUG=false` — never enable Swagger in production
- [ ] `TINYSIEM_MASTER_KEY` — set if using API Integrations; keep it out of git
- [ ] `.env` — present in `.gitignore` (it is by default); never committed
- [ ] CORS — the default `*` origin is acceptable for localhost-only tools; restrict if exposed externally by adding an nginx reverse proxy with appropriate headers

---

→ [Troubleshooting](troubleshooting.md) — common errors and fixes

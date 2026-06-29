# Configuration

All configuration is via environment variables. Set them in `.env` (copy from `.env.example`).

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
| `TINYSIEM_SUPERADMIN_PASSWORD` | `admin` | Initial password for the `admin` superadmin account. Only used when the users table is empty (first boot). Change after first login. |

---

## Storage

| Variable | Default | Description |
|---|---|---|
| `TINYSIEM_DUCKDB_PATH` | `/app/data/tinysiem.duckdb` | DuckDB database file path |
| `TINYSIEM_CHROMA_PATH` | `/app/data/chroma_store` | ChromaDB vector store directory |
| `TINYSIEM_ALERTS_PATH` | `/app/data/alerts/alerts.log` | Alert JSONL output file |
| `TINYSIEM_ALERT_MAX_MB` | `50` | Alert file size limit before rotation |

---

## Retention

| Variable | Default | Description |
|---|---|---|
| `TINYSIEM_RETENTION_DAYS` | `90` | Events older than this are archived |
| `TINYSIEM_ARCHIVE_PATH` | `/app/data/archive` | Directory for archived event files |

---

## Syslog Listeners

| Variable | Default | Description |
|---|---|---|
| `TINYSIEM_SYSLOG_UDP_PORT` | `5140` | UDP syslog listener port (set to `0` to disable) |
| `TINYSIEM_SYSLOG_TCP_PORT` | `5141` | TCP syslog listener port (set to `0` to disable) |

---

## Beats Endpoint

| Variable | Default | Description |
|---|---|---|
| `TINYSIEM_BEATS_ENABLED` | `true` | Enable the `POST /ingest/beats` endpoint |

---

## Notifications

| Variable | Default | Description |
|---|---|---|
| `TINYSIEM_SMTP_HOST` | `` | SMTP server hostname. Leave empty to disable email. |
| `TINYSIEM_SMTP_PORT` | `587` | SMTP port |
| `TINYSIEM_SMTP_FROM` | `` | Sender email address |
| `TINYSIEM_SMTP_TO` | `` | Recipient email address |
| `TINYSIEM_SMTP_TLS` | `true` | Use STARTTLS |
| `TINYSIEM_SMTP_USER` | `` | SMTP username |
| `TINYSIEM_SMTP_PASS` | `` | SMTP password |
| `TINYSIEM_WEBHOOK_URL` | `` | Webhook URL for alert notifications. Leave empty to disable. |
| `TINYSIEM_NOTIFY_MIN_SEV` | `high` | Minimum severity to trigger notifications (`low`, `medium`, `high`, `critical`) |

---

## Reports

| Variable | Default | Description |
|---|---|---|
| `TINYSIEM_REPORT_SCHEDULE` | `disabled` | Scheduled report cadence: `disabled`, `daily`, `weekly` |

---

## AI (Claude API)

| Variable | Default | Description |
|---|---|---|
| `TINYSIEM_CLAUDE_API_KEY` | `` | Anthropic API key. Leave empty to disable AI features. Parser/rule generation returns 503 when not set. |

---

## MCP Server

| Variable | Default | Description |
|---|---|---|
| `TINYSIEM_MCP_ENABLED` | `false` | Mount the MCP server at `/mcp` for Claude Desktop integration |

---

## Debug

| Variable | Default | Description |
|---|---|---|
| `TINYSIEM_DEBUG` | `false` | Enable FastAPI `/docs` and `/redoc`. Never enable in production. |

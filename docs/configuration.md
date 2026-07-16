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
| `TINYSIEM_SYSLOG_ALLOW_CIDRS` | `` | Comma-separated CIDRs allowed to send syslog. Empty = allow all sources. |
| `TINYSIEM_SYSLOG_MAX_BYTES` | `8192` | Maximum accepted syslog message size in bytes. Oversized messages are dropped and counted in `/health`. |

---

## Beats Endpoint

| Variable | Default | Description |
|---|---|---|
| `TINYSIEM_BEATS_ENABLED` | `true` | Enable the `POST /ingest/beats` Elasticsearch-compatible bulk endpoint |

---

## CORS

| Variable | Default | Description |
|---|---|---|
| `TINYSIEM_CORS_ORIGINS` | `` | Comma-separated list of allowed cross-origin URLs (e.g. `http://192.168.1.50:8000`). Empty means same-origin only — set this if you access the UI from a different host/port than the API. |

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

## AI Provider

AI features are entirely optional, off by default, and configured through the UI rather than an environment variable — there is no `TINYSIEM_*` variable for an API key or model name.

Go to **Settings → AI Config** (admin role required) and pick one of:

| Provider | `base_url` needed? | Notes |
|---|---|---|
| `anthropic` | No | Uses the Anthropic Messages API directly. |
| `openai` | No | Defaults to `https://api.openai.com/v1`. |
| `deepseek` | No | Defaults to `https://api.deepseek.com/v1`. |
| `custom` | **Yes** | Any OpenAI-compatible endpoint — a self-hosted model gateway, Ollama, LM Studio, etc. |

The **Model** field is free text — providers ship new models faster than this doc (or any dropdown) could track, so check your provider's own documentation for the exact model name/ID to enter. Click **Test Connection** after saving to confirm the key and endpoint actually work before relying on them.

The API key is encrypted at rest the same way integration credentials are — see [`TINYSIEM_MASTER_KEY`](#api-integrations) above; without it set, AI Config save requests will still work (the key is stored, just less safely — set the master key before storing anything sensitive in production).

Every feature — parser generation, rule generation, alert explain, event analysis, playbook generation/refinement, and the Home page's natural-language search — calls whichever provider is configured through the same interface, so switching providers doesn't require reconfiguring each feature separately. See [Architecture → AI Layer](architecture.md#ai-layer-optional) for how this abstraction works, and [API Reference → AI](api-reference.md#ai) for the endpoints.

If no provider is configured, AI-powered UI elements degrade gracefully — the Home page falls back to a plain message with manual links to Events/Alerts/Cases, and buttons like "Explain with AI" surface a clear "not configured" error instead of failing silently.

`TINYSIEM_AI_DAILY_CALL_LIMIT` (default `100`) caps how many AI-powered calls (explain-alert, analyze-events, home search) a single user can make per rolling 24-hour window — a cost-abuse guard, not a security boundary. Raise it if your team's legitimate usage exceeds the default.

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

## TLS

| Variable | Default | Description |
|---|---|---|
| `TINYSIEM_TLS_CERT` | `` | Path (inside the container) to a PEM certificate. When set together with `TINYSIEM_TLS_KEY`, uvicorn serves HTTPS instead of HTTP. |
| `TINYSIEM_TLS_KEY` | `` | Path (inside the container) to the matching PEM private key. |

Generate a self-signed certificate and drop it into the persisted `tinysiem_data` volume (already mounted at `/app/data`), then point both variables at it:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout key.pem -out cert.pem -subj "/CN=your-hostname"
docker cp cert.pem tinysiem-tinysiem-1:/app/data/tls/cert.pem
docker cp key.pem tinysiem-tinysiem-1:/app/data/tls/key.pem
```

Then set in `.env`:
```
TINYSIEM_TLS_CERT=/app/data/tls/cert.pem
TINYSIEM_TLS_KEY=/app/data/tls/key.pem
```

and `docker-compose restart tinysiem`. For a real deployment, use a certificate from your own CA or Let's Encrypt instead of a self-signed one.

---

## Security Checklist

Before exposing TinySIEM outside localhost:

- [ ] `TINYSIEM_API_KEY` — long random string; only authenticates `/ingest/*` as of v1.4
- [ ] `TINYSIEM_JWT_SECRET` — 64+ char random string; the container refuses to start below 32 characters
- [ ] `TINYSIEM_SUPERADMIN_PASSWORD` — the seeded `admin` account is forced to change its password on first login if this is left at the default `admin`
- [ ] `TINYSIEM_DEBUG=false` — never enable Swagger in production
- [ ] `TINYSIEM_MASTER_KEY` — set if using API Integrations; keep it out of git
- [ ] `TINYSIEM_CORS_ORIGINS` — default is same-origin only; set explicitly only for origins you actually need
- [ ] `TINYSIEM_TLS_CERT` / `TINYSIEM_TLS_KEY` — set for HTTPS; plain HTTP otherwise
- [ ] `TINYSIEM_SYSLOG_ALLOW_CIDRS` — restrict to your log-source networks if the syslog ports are reachable beyond localhost
- [ ] `.env` — present in `.gitignore` (it is by default); never committed

---

→ [Troubleshooting](troubleshooting.md) — common errors and fixes

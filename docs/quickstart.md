# Quick Start

## Prerequisites

- Docker Desktop (or Docker Engine + Compose v2)
- No local Python required to run the stack

---

## 1. Clone and Configure

```bash
git clone https://github.com/netsecid/tinysiem.git
cd tinysiem
cp .env.example .env
```

Edit `.env` and set required values:

```dotenv
TINYSIEM_API_KEY=replace-with-a-long-random-string
TINYSIEM_JWT_SECRET=replace-with-a-64-char-random-string
TINYSIEM_SUPERADMIN_PASSWORD=change-this-password
```

Generate strong values:
```bash
openssl rand -hex 32   # use for API_KEY
openssl rand -hex 32   # use for JWT_SECRET
```

`TINYSIEM_API_KEY` authenticates log ingestion only (`/ingest/raw`, `/ingest/file`,
`/ingest/beats`) — it will not work against `/events`, `/alerts`, or any other endpoint. Log
in via the UI (or `POST /auth/login`) to get a JWT for everything else. `TINYSIEM_JWT_SECRET`
must be at least 32 characters or the container refuses to start.

If you plan to use **API Integrations** (AWS CloudTrail, Google Workspace), also generate a Fernet key:
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Add output to .env as: TINYSIEM_MASTER_KEY=<key>
```

---

## 2. Start the Stack

```bash
docker-compose up --build
```

This starts:
- **nginx** on `http://localhost:8080` — generates realistic access logs into the shared `./logs/` volume
- **TinySIEM** on `http://localhost:8000` — API + UI

---

## 3. Log In

Open `http://localhost:8000` — you'll be redirected to the login page.

Default credentials:
- **Username:** `admin`
- **Password:** value of `TINYSIEM_SUPERADMIN_PASSWORD` (default: `admin`)

If you left `TINYSIEM_SUPERADMIN_PASSWORD` at its default, the login page will require you to
set a new password (12+ characters) immediately after your first login — this is enforced by
the server, not a suggestion. Set a strong value in `.env` before first boot (see step 1) to
skip this prompt entirely.

After five failed login attempts for the same username from the same IP, further attempts are
locked out with an increasing backoff (starting at 60 seconds) — this is expected, not a bug;
wait for the backoff to elapse and try again with the correct password.

---

## 4. Seed Test Data

The included script generates realistic nginx log lines and POSTs them to the API (Python stdlib only, no pip install):

```bash
# Inside Docker (recommended)
docker-compose exec tinysiem python scripts/ingest_test_logs.py 500

# Or with local Python 3
python scripts/ingest_test_logs.py 500
```

After seeding, open the Events or Dashboard page — you should see data immediately. The baseline learner will begin building hour-of-day models after data accumulates across a few buckets.

---

## 5. Ingest Real Logs

### Single line (curl)

```bash
curl -X POST http://localhost:8000/ingest/raw \
  -H "Authorization: Bearer $TINYSIEM_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"source": "nginx", "raw": "192.168.1.1 - - [29/Jun/2026:10:00:00 +0000] \"GET /admin HTTP/1.1\" 403 512 \"-\" \"curl/8.6.0\""}'
```

### Bulk file upload

```bash
curl -X POST "http://localhost:8000/ingest/file?source=nginx" \
  -H "Authorization: Bearer $TINYSIEM_API_KEY" \
  -F "file=@/var/log/nginx/access.log"
```

### Filebeat

Add to `filebeat.yml`:

```yaml
output.elasticsearch:
  hosts: ["http://localhost:8000/ingest/beats"]
  api_key: "ignored:$TINYSIEM_API_KEY"

filebeat.inputs:
  - type: log
    paths: ["/var/log/nginx/access.log"]
    fields:
      source: nginx
```

### Syslog (rsyslog)

```
*.* @localhost:5140    # UDP
*.* @@localhost:5141   # TCP
```

---

## 6. Rebuilding After Changes

```bash
# Full rebuild (required after any Python/Dockerfile change)
docker-compose up --build

# Restart only (safe after ui/ HTML changes — ui/ is a volume mount)
docker-compose restart tinysiem
```

---

## 7. Run Tests

```bash
docker-compose exec -w /app tinysiem pytest tests/ -v
```

---

## 8. Optional: TLS and Backups

For anything beyond localhost, serve HTTPS directly by setting `TINYSIEM_TLS_CERT` /
`TINYSIEM_TLS_KEY` — see [Configuration → TLS](configuration.md#tls) for the self-signed-cert
recipe. Trigger an on-demand backup (DuckDB export + alerts + custom rules) with
`POST /admin/backup` as a superadmin — see [Backup & Restore](backup.md).

---

→ [Troubleshooting](troubleshooting.md) — common errors and fixes

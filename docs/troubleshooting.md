# Troubleshooting

---

## Diagnostics First

Before diving into specific issues, pull the container logs — most errors are logged as structured JSON:

```bash
# Live logs
docker-compose logs -f tinysiem

# Last 100 lines
docker-compose logs --tail=100 tinysiem

# Health check
curl -s http://localhost:8000/health | python3 -m json.tool
```

All app log lines are structured JSON:
```json
{"time":"2026-06-29 10:00:00","level":"WARNING","logger":"app.decoder.engine","msg":"No decoder for source 'unknown'"}
```

---

## Container Won't Start

### `pydantic_settings.env_settings.EnvSettingsError` or `ValidationError`

**Cause:** `TINYSIEM_API_KEY` or `TINYSIEM_JWT_SECRET` is missing. Both are required with no default and the container will crash immediately without them.

**Fix:** Ensure `.env` contains both values:
```dotenv
TINYSIEM_API_KEY=replace-with-a-long-random-string
TINYSIEM_JWT_SECRET=replace-with-a-64-char-random-string
```

```bash
cp .env.example .env
# Edit .env, then:
docker-compose up --build
```

---

### Port already in use

```
Error: Bind for 0.0.0.0:8000 failed: port is already allocated
```

**Fix:** Another process is using port 8000 or 8080. Find and stop it, or change ports in `docker-compose.yml`:
```bash
lsof -i :8000    # find the process
kill <PID>
```

---

### `data/` directory permission error

**Cause:** The named Docker volume `tinysiem_data` can't be written to by the non-root `appuser` inside the container.

**Fix:**
```bash
docker-compose down -v   # removes the volume — data will be lost
docker-compose up --build
```

If you want to preserve data, inspect the volume first:
```bash
docker volume inspect tinysiem_tinysiem_data
```

---

### Changes to Python files not taking effect

**Cause:** `docker-compose restart` does NOT rebuild the image. Python code is baked into the image at build time.

**Fix:** Always rebuild after changing any `.py` file:
```bash
docker-compose up --build
```

Changes to `ui/*.html` don't need a rebuild (the `ui/` directory is a volume mount).

---

## Login / Authentication

### `401 Unauthorized` on login

**Cause options:**
1. Wrong username or password
2. Account doesn't exist

**Fix:** The default superadmin account is created on first boot with:
- Username: `admin`
- Password: value of `TINYSIEM_SUPERADMIN_PASSWORD` in `.env` (default: `admin`)

If you changed `TINYSIEM_SUPERADMIN_PASSWORD` after the first boot, the database already has the old password — the env var only sets the initial password when the users table is empty.

**Reset the superadmin password:**
```bash
docker-compose exec -w /app tinysiem python3 -c "
from app.storage import duckdb_store
from app.password import hash_password
duckdb_store.init_db()
duckdb_store.update_user_password('admin', hash_password('newpassword'))
print('done')
"
```

---

### `401 Unauthorized` on API requests

**Cause options:**
1. Using the wrong token type — the ingest API (`/ingest/*`) accepts `Bearer <TINYSIEM_API_KEY>` (the static key from `.env`). The user-facing API accepts `Bearer <JWT>` (obtained from `POST /auth/login`).
2. JWT has expired (default: 24 hours).
3. The API key in `.env` doesn't match what you're sending.

**Fix:**
```bash
# Test the static API key
curl -s http://localhost:8000/health   # no auth needed
curl -s http://localhost:8000/events -H "Authorization: Bearer $TINYSIEM_API_KEY"

# Get a fresh JWT
curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
```

In the UI, JWT expiry redirects you to `/ui/login.html`. Log in again to get a new token.

---

### `403 Insufficient permissions`

**Cause:** The logged-in user's role doesn't have access to the requested endpoint.

| Role | Access |
|---|---|
| `analyst` | Events, Alerts (read + triage), Dashboard, Reports (read) |
| `admin` | Everything above + Users (read), Parsers, Rules, Audit, Notifications, Retention, Reports (send) |
| `superadmin` | Everything above + User create/delete |

**Fix:** Log in as a user with a higher role, or have a superadmin update the user's role via **Configuration → Users**.

---

### Audit Log page shows "access restricted"

**Cause:** The logged-in user is `analyst` role. Audit Log requires `admin` or `superadmin`.

**Fix:** Log in as an admin.

---

## Log Ingest

### `422 Unprocessable Entity` on `POST /ingest/raw`

**Cause:** No registered decoder matched the `source` + `raw` combination.

```json
{ "detail": "Log line could not be decoded" }
```

**Debug:**
```bash
# Check which decoders are loaded
curl -s http://localhost:8000/health | python3 -m json.tool
docker-compose logs tinysiem | grep "decoder"
```

**Common causes:**
- `source` field doesn't match any decoder's `source:` value — they must match exactly (e.g. `"nginx"` not `"Nginx"`)
- The regex pattern in the decoder doesn't cover this log format variant
- The decoder YAML has a syntax error and failed to load silently

**Fix:** Check the container logs for `"No decoder for source"` or `"Failed to load decoder"` warnings. Test your decoder on the Parsers page UI → Test panel.

---

### Bulk file ingest reports many errors

```json
{ "ingested": 10, "errors": 490, "total": 500 }
```

**Cause:** Most lines don't match the decoder. Common reasons:
- Mixed log formats in the file (e.g. nginx + upstream error lines)
- Wrong `source` query parameter
- Decoder regex doesn't handle all line variants

**Fix:** Test a single failing line first:
```bash
curl -X POST http://localhost:8000/ingest/raw \
  -H "Authorization: Bearer $TINYSIEM_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"source":"nginx","raw":"<failing line here>"}'
```

---

### Syslog messages not appearing

**Cause options:**
1. Port not exposed in `docker-compose.yml`
2. Sending to the wrong port (UDP vs TCP)
3. Firewall blocking the port
4. No matching decoder for `syslog_rfc3164` or `syslog_rfc5424`

**Fix:**
```bash
# Verify listeners are up
curl -s http://localhost:8000/health | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['listeners'])"
# Expected: {"udp": true, "tcp": true}

# Test UDP manually
echo '<14>Jun 29 10:00:00 host sshd[123]: test message' | nc -u localhost 5140

# Test TCP manually
echo '<14>Jun 29 10:00:00 host sshd[123]: test message' | nc localhost 5141
```

If `listeners.udp` or `listeners.tcp` is `false`, check the logs for port-binding errors:
```bash
docker-compose logs tinysiem | grep "syslog\|5140\|5141"
```

Set `TINYSIEM_SYSLOG_UDP_PORT=0` or `TINYSIEM_SYSLOG_TCP_PORT=0` to disable a listener.

---

### `503 Service Unavailable` on `POST /ingest/beats`

**Cause:** `TINYSIEM_BEATS_ENABLED=false` in `.env`.

**Fix:** Set `TINYSIEM_BEATS_ENABLED=true` and rebuild.

---

## Decoders

### Custom decoder not loading

**Cause options:**
1. File not in `app/decoder/decoders/custom/` — decoders outside this directory (and the built-in directory) are not scanned
2. YAML syntax error — check the container log for `"Failed to load decoder"` warnings
3. Missing required fields (`name`, `source`, `type`)

**Debug:**
```bash
docker-compose logs tinysiem | grep "decoder\|Failed to load"
```

**Fix:** Validate your YAML:
```bash
python3 -c "import yaml; yaml.safe_load(open('app/decoder/decoders/custom/myparser.yaml'))"
```

---

### Regex matches but fields are empty

**Cause:** The `fields:` mapping references a capture group name that doesn't exist in `pattern:`.

**Example problem:**
```yaml
pattern: '^(?P<ip>\S+) ...'
fields:
  source_ip: remote_addr   # wrong — capture group is named "ip", not "remote_addr"
```

**Fix:** Make sure every value under `fields:` matches a named group in `pattern:`.

---

### Timestamp not being parsed / `event_time` is null

**Cause options:**
1. `timestamp_field` refers to a field name that isn't being extracted
2. `timestamp_format` doesn't match the actual timestamp string
3. Timezone offset format mismatch

**Debug:** Use the Parsers page test panel — it shows all extracted fields including `event_time`. If `event_time` is null but other fields are populated, the timestamp parsing is the issue.

**Common `timestamp_format` patterns:**

| Format | Example |
|---|---|
| `'%d/%b/%Y:%H:%M:%S %z'` | `29/Jun/2026:10:00:00 +0000` (nginx) |
| `'%Y-%m-%dT%H:%M:%S.%f%z'` | `2026-06-29T10:00:00.000Z` (ISO 8601) |
| `'%b %d %H:%M:%S'` | `Jun 29 10:00:00` (syslog, no year) |
| `'%Y-%m-%d %H:%M:%S'` | `2026-06-29 10:00:00` |

---

## Detection Rules

### Rule is not firing

**Cause options:**
1. `source` in the rule doesn't match the event's `source` field
2. `field` or `value` doesn't match what the decoder extracts
3. For threshold rules: the count hasn't reached `threshold_count` yet
4. For field_match rules: `operator` mismatch (e.g. `eq` on a string field where the value has extra whitespace)

**Debug — check what the decoder actually extracts:**
```bash
# Ingest a test line and check the stored event
curl -X POST http://localhost:8000/ingest/raw \
  -H "Authorization: Bearer $TINYSIEM_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"source":"nginx","raw":"<your log line>"}'

# Then query for it
curl -s "http://localhost:8000/events?limit=1" \
  -H "Authorization: Bearer $TINYSIEM_API_KEY"
```

Compare the extracted field values against what your rule checks. Integer fields (`status_code`, `response_size`) are stored as integers — use integer values in the rule, not strings.

---

### Threshold rule fires but count seems wrong

**Cause:** The threshold counter is global for `(rule_name, field_value)` — not per source IP or per user. If 5 different IPs each send 2 × 404s within the window, the rule fires (total = 10).

If you want per-IP thresholds, use a `correlation` rule with `capture_field: source_ip`.

---

### Correlation rule state was lost

**Cause:** Correlation state is held in memory (`_corr_state` dict). It is cleared on container restart.

This is by design — state is ephemeral. If you restart the container during an active attack sequence, the correlation window resets.

**Workaround:** Set a generous `window_seconds` so the attack sequence is still within the window after a typical restart.

---

## AI Features

### `503` on parser or rule generate

```json
{ "detail": "TINYSIEM_CLAUDE_API_KEY not set" }
```

**Fix:** Add your Anthropic API key to `.env`:
```dotenv
TINYSIEM_CLAUDE_API_KEY=sk-ant-...
```

Then rebuild: `docker-compose up --build`

---

### `502 Claude API error`

**Cause:** The Anthropic API returned an error (rate limit, invalid key, network issue).

**Fix:** Check the audit log (`/ui/audit.html`) for the `ai.call` entry with `status=error` — the `error_msg` field contains the raw API error. Common causes:
- Invalid API key — verify at console.anthropic.com
- Rate limit — wait and retry
- Model unavailable — the default model is `claude-sonnet-4-6`

---

### AI-generated YAML is invalid

**Cause:** The model occasionally produces YAML with minor formatting issues, especially for complex log formats.

**Fix:** The generate endpoint returns the raw YAML — copy it into the parser/rule editor, fix the issue manually, and save. Use the Test panel to validate before saving.

---

## UI

### Redirected to login immediately after logging in

**Cause options:**
1. JWT expiry — check `TINYSIEM_JWT_EXPIRY_HOURS` (default 24)
2. Browser blocked `localStorage` (private/incognito mode in some browsers)
3. Clock skew — if the server clock is significantly ahead of the browser, the JWT appears expired immediately

**Fix:** Check browser console for errors. Verify the server time:
```bash
docker-compose exec tinysiem date
```

---

### Data not refreshing in the UI

**Cause:** The UI uses polling (not WebSockets). Events page polls on search; Dashboard and Alerts refresh on button click or page load.

**Fix:** Click the ↻ refresh button, or reload the page. If data is being ingested but not appearing, check the time range filter — the default is "Last 24h" on most pages.

---

### "No audit events found" on Audit Log page

**Cause:** The default time range is "Last 24h". If the container was just started and no activity has occurred in the last 24 hours, there's nothing to show.

**Fix:** Change the time range dropdown to "All time" and click Search.

---

## Performance

### Queries are slow / UI takes a long time to load

**Cause options:**
1. Very large event table with no time filter — always add a `start` filter for large datasets
2. `q` (full-text) search on a large table — `q` does `LIKE '%...%'` on the raw column, which is a full scan
3. DuckDB file is fragmented after many inserts

**Fix:**
```bash
# Check event count
curl -s "http://localhost:8000/events?limit=1" \
  -H "Authorization: Bearer $TINYSIEM_API_KEY" | python3 -c "import sys,json; print(json.load(sys.stdin)['total'], 'events')"

# Run retention to archive old events
curl -s -X POST http://localhost:8000/retention/run \
  -H "Authorization: Bearer <admin-jwt>"
```

Use specific filters (`source_ip`, `status_code`, `start`/`end`) instead of `q` when possible — indexed columns are much faster.

---

### DuckDB file growing very large

**Cause:** Events accumulate with no retention policy enforced.

**Fix:** Set `TINYSIEM_RETENTION_DAYS` (default: 30) in `.env` and run retention manually or wait for the automatic background job. Archived events are stored as compressed files in `TINYSIEM_ARCHIVE_PATH`.

---

## Still Stuck?

1. Check structured container logs: `docker-compose logs --tail=200 tinysiem`
2. Check the Audit Log page — every API error is recorded with full request context
3. Enable debug mode temporarily to access `/docs` (Swagger UI):
   ```dotenv
   TINYSIEM_DEBUG=true
   ```
   Then rebuild and try the failing request directly from `/docs`.
4. Open an issue at the project repository with the relevant log output.

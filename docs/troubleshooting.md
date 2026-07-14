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
3. Account is temporarily locked out (see next section) — check for `429`, not `401`

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
user = duckdb_store.get_user_by_username('admin')
duckdb_store.update_user(user['id'], password_hash=hash_password('a-new-12-char-or-longer-password'))
print('done')
"
```

This also bumps the user's `token_epoch`, so any existing sessions for that account are invalidated — log in again with the new password.

---

### `429 Too Many Requests` on login

**Cause:** The account (scoped to `username` + source IP) has failed 5 or more login attempts and is locked out with an exponential backoff (60s, doubling, capped at 15 minutes). The response body includes `retry_after_seconds` in the audit log entry (`auth.lockout` event type), though the HTTP response itself is intentionally generic and doesn't reveal timing or whether the account exists.

**Fix:** Wait for the backoff window to elapse, then try again with the correct password — a successful login immediately clears the lockout counter for that `(username, IP)` pair. There is no manual unlock endpoint; the lockout state is in-memory and also clears on container restart.

---

### Stuck on "set a new password" after logging in

**Cause:** The account has `must_change_password` set — this happens automatically for the seeded `admin` superadmin if `TINYSIEM_SUPERADMIN_PASSWORD` was left at its default (`admin`). While this flag is set, every endpoint except `GET /auth/me`, `POST /auth/logout`, and `POST /auth/change-password` returns `403` with `{"detail": "password_change_required"}` — this is enforced server-side, not just a UI nag screen.

**Fix:** Submit a new password (12+ characters) via the panel that appears after login, or call `POST /auth/change-password` directly:
```bash
curl -X POST http://localhost:8000/auth/change-password \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"current_password":"admin","new_password":"a-new-12-char-or-longer-password"}'
```
The response includes a fresh token — the old one stops working immediately (password change bumps `token_epoch`).

---

### `401 Unauthorized` on API requests

**Cause options:**
1. **Using the API key on a non-ingest endpoint.** As of v1.4, `TINYSIEM_API_KEY` only authenticates `/ingest/raw`, `/ingest/file`, and `/ingest/beats` — it is rejected everywhere else. This is a common upgrade gotcha: a script that used to query `/events` or `/alerts` with the API key will now get `401` and must switch to a JWT.
2. JWT has expired (default: 24 hours).
3. JWT was revoked — the user logged out (`POST /auth/logout`), changed their password, or a superadmin updated their account; all of these bump `token_epoch` and invalidate every previously-issued token for that user.
4. The user account was deleted after the token was issued.
5. The API key in `.env` doesn't match what you're sending.

**Fix:**
```bash
# Test the static API key — ingest only
curl -s http://localhost:8000/health   # no auth needed
curl -s -X POST http://localhost:8000/ingest/raw \
  -H "Authorization: Bearer $TINYSIEM_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"source":"nginx","raw":"..."}'

# Everything else needs a JWT
curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
curl -s http://localhost:8000/events -H "Authorization: Bearer $JWT"
```

An `admin`+ or `superadmin` JWT also works on the ingest endpoints, in addition to the API key — the API key is the exception now, not the default credential.

In the UI, JWT expiry (or revocation) redirects you to `/ui/login.html`. Log in again to get a new token.

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
5. The source IP isn't in `TINYSIEM_SYSLOG_ALLOW_CIDRS` — messages are silently dropped, not rejected with an error
6. The message exceeds `TINYSIEM_SYSLOG_MAX_BYTES` (default 8192) — also silently dropped

**Fix:**
```bash
# Verify listeners are up and check drop counters
curl -s http://localhost:8000/health | python3 -m json.tool
# Look at listeners.syslog_udp.enabled, listeners.syslog_tcp.enabled, listeners.syslog_dropped

# Test UDP manually
echo '<14>Jun 29 10:00:00 host sshd[123]: test message' | nc -u localhost 5140

# Test TCP manually
echo '<14>Jun 29 10:00:00 host sshd[123]: test message' | nc localhost 5141
```

If `listeners.syslog_udp.enabled` or `listeners.syslog_tcp.enabled` is `false`, check the logs for port-binding errors:
```bash
docker-compose logs tinysiem | grep "syslog\|5140\|5141"
```

If `listeners.syslog_dropped.cidr` is increasing, the sending host's IP isn't covered by `TINYSIEM_SYSLOG_ALLOW_CIDRS` — add its CIDR (or leave the variable empty to allow all sources, the default). If `listeners.syslog_dropped.size` is increasing, messages are larger than `TINYSIEM_SYSLOG_MAX_BYTES` — raise the limit or trim the sender's message format.

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

**Cause:** The threshold counter is scoped to the rule's own `source` (a rule with `source: nginx` only counts events from `nginx`; a rule with `source: "*"` counts across all sources) but is **not** further scoped per source IP or per user within that source. If 5 different IPs each send 2 × 404s from `nginx` within the window, the rule fires (total = 10).

If you want per-IP thresholds, use a `correlation` rule with `capture_field: source_ip`.

If you're seeing the *built-in* `tinysiem-internal-brute-force` rule fire unexpectedly, remember it only counts `401`s from the `tinysiem_internal` source (self-monitoring feed) — real `401`s from a monitored application like nginx don't contribute to it, by design.

---

### Correlation rule state was lost

**Cause:** Correlation state is held in memory (`_corr_state` dict). It is cleared on container restart.

This is by design — state is ephemeral. If you restart the container during an active attack sequence, the correlation window resets.

**Workaround:** Set a generous `window_seconds` so the attack sequence is still within the window after a typical restart.

---

## AI Features

### `503` on parser or rule generate

```json
{ "detail": "AI features require configuration in Settings → AI Config" }
```

**Fix:** Log in with an admin (or higher) account, go to **Settings → AI Config**, choose a provider (Anthropic, OpenAI, DeepSeek, or a custom OpenAI-compatible endpoint), enter a model and API key (not required for a keyless local Ollama server), and click **Save**. Use **Test Connection** to confirm it works before relying on it.

---

### `502 AI provider error`

**Cause:** The configured provider's API returned an error (rate limit, invalid key, network issue, unreachable host).

**Fix:** Check the audit log (`/ui/audit.html`) for the `ai.call` entry with `status=error` — the `error_msg` field contains the raw provider error. Common causes:
- Invalid API key — re-check it under Settings → AI Config, or verify at the provider's own console
- Rate limit — wait and retry
- Model unavailable — confirm the selected model is still offered by the provider (or, for Ollama, that it's been pulled locally)
- Unreachable base URL — for a custom/local provider, confirm the host is reachable from inside the container (not just from your own machine)

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

## API Integrations

### `503 Service Unavailable` on integration endpoints

```json
{ "detail": "TINYSIEM_MASTER_KEY not set — integrations require credential encryption" }
```

**Fix:** Generate a Fernet key and add it to `.env`:
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

```dotenv
TINYSIEM_MASTER_KEY=<output from above>
```

Then recreate the container (must use `up -d`, not `restart`, to pick up new env vars):
```bash
docker-compose up -d
```

---

### Integration created but never pulling events

**Cause options:**
1. Integration is disabled — check the Enabled toggle in the UI or `GET /integrations/{id}`
2. AWS credentials don't have permission to read the CloudTrail S3 bucket
3. Google Workspace service account isn't configured as a domain-wide delegation authority
4. The background scheduler hasn't run yet — it polls every 60 s

**Debug:**
```bash
# Check recent run history
curl -s "http://localhost:8000/integrations/<id>/runs" \
  -H "Authorization: Bearer <jwt>" | python3 -m json.tool
```

Look at `status` and `error_message` on the most recent run. Common errors:
- `NoCredentialsError` — AWS credentials invalid or missing
- `AccessDenied` — bucket or CloudTrail read permission missing
- `ServiceAccountError` — Google service account JSON is malformed or lacks domain delegation

**Manually trigger to test immediately:**
```bash
curl -s -X POST "http://localhost:8000/integrations/<id>/trigger" \
  -H "Authorization: Bearer <jwt>"
```

---

### Integration events appear but alerts don't fire

**Cause:** Events are ingested correctly but the rule engine evaluates them using the integration's source name (e.g. `aws_cloudtrail`). If no rule targets that source, no alerts are fired.

**Fix:** Create a rule with `source: aws_cloudtrail` (or whatever source the integration uses). Check the Sources page to confirm what source name is being set.

---

## Custom Dashboard

### Widget shows "No data"

**Cause options:**
1. The time range for the widget covers a period with no events
2. The selected source filter doesn't match any data
3. Widget config has an invalid value (e.g. `buckets: 0`)

**Fix:** Open the widget's settings (pencil icon in edit mode) and verify the config. For `event_volume`, try increasing the `hours` value. Check the Events page with the same filters to confirm data exists.

---

### Dashboard layout not saving

**Cause:** `PUT /dashboard` requires a JWT (not just the API key) since the layout is per-user.

**Fix:** Ensure you're logged in via the login page, not using a raw API key. Check browser console for 401 errors.

---

### HTML export is empty or malformed

**Cause:** The dashboard has no widgets, or a widget's data fetch failed.

**Fix:** Add at least one widget and verify it shows data before exporting. Check the container logs for export errors:
```bash
docker-compose logs tinysiem | grep "export"
```

---

## Smart Baselines

### No baselines being learned

**Cause:** The baseline learner runs as a background asyncio task. It needs events to have been ingested for at least one hour bucket before it can build a baseline.

**How learning works:** After events accumulate, the learner calculates mean and standard deviation per `(source, hour_of_day, day_of_week)` bucket. With fewer than ~5 samples, the bucket exists but the stddev is unreliable.

**Fix:** Ingest data over several days and let the scheduler run. Alternatively, seed test data:
```bash
python scripts/ingest_test_logs.py 2000
```

---

### Baseline violations not being acknowledged

**Cause:** The `PATCH /baselines/violations/{id}` endpoint updates the `acknowledged` field in DuckDB. Due to a known DuckDB 1.1.x constraint (UPDATE fails on tables with a PRIMARY KEY + secondary index), the baselines tables use a pattern that avoids secondary indexes. If you added a `CREATE INDEX` to the `baseline_violations` table manually, UPDATE will silently fail.

**Fix:** Do not add secondary indexes to the baselines, cases, integrations, or integration_runs tables. See the DuckDB constraint note in [Development](development.md).

---

## CORS & Browser Access

### Browser console shows a CORS error / "blocked by CORS policy"

**Cause:** As of v1.4, CORS defaults to same-origin only. If the UI is served from a different host or port than the API it's calling (e.g. you're pointing the login page's "Server URL" field at a different origin than the page itself was loaded from), the browser blocks the cross-origin request.

**Fix:** Set `TINYSIEM_CORS_ORIGINS` to the exact origin(s) that need access, comma-separated:
```dotenv
TINYSIEM_CORS_ORIGINS=http://192.168.1.50:8000,http://localhost:3000
```
Then recreate the container (env var change, needs `up`, not `restart`):
```bash
docker-compose up -d
```
If the UI and API are served from the same origin (the default single-container setup), you should never need to set this.

---

## TLS

### Container starts but still serves plain HTTP

**Cause:** `TINYSIEM_TLS_CERT` and `TINYSIEM_TLS_KEY` must **both** be set — the entrypoint script only switches to HTTPS when both are present and non-empty.

**Fix:** Verify both are set and point to files that actually exist inside the container:
```bash
docker-compose exec tinysiem sh -c 'echo $TINYSIEM_TLS_CERT $TINYSIEM_TLS_KEY; ls -l $TINYSIEM_TLS_CERT $TINYSIEM_TLS_KEY'
```
See [Configuration → TLS](configuration.md#tls) for the full setup recipe.

### `curl: (60) SSL certificate problem` when testing

**Cause:** A self-signed certificate isn't trusted by your client by default — this is expected.

**Fix:** Use `curl -k` (or your client's equivalent "insecure"/skip-verification flag) against a self-signed cert, or install a certificate from a real CA (Let's Encrypt, your org's internal CA) for anything beyond local testing.

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

# Development

For a conceptual, diagram-first overview of how the system fits together, see [Architecture](architecture.md). This document covers the practical side: running tests, the file-by-file project layout, and implementation gotchas that don't fit a diagram.

## Running Tests

Tests must run inside the Docker container — DuckDB is installed in the image, not on the host:

```bash
# Full suite
docker-compose exec -w /app tinysiem pytest tests/ -v

# Single file
docker-compose exec -w /app tinysiem pytest tests/test_audit.py -v

# Single test
docker-compose exec -w /app tinysiem pytest tests/test_audit.py::test_login_success_creates_audit -v

# Quick summary (no verbose output)
docker-compose exec -w /app tinysiem pytest tests/ -q
```

Test coverage: **546 tests** across ingest, events, alerts, parsers, rules (incl. exceptions, backtest, MITRE coverage, name/filename invariant), users, auth, correlation, syslog, Beats, retention, reports, notifications, audit, AI (provider abstraction, home search), baselines, cases (incl. alert and event linkage, playbooks), entities, watchlists, saved searches, integrations, dashboard, alert enrichment, SQL sandbox, GeoIP, startup checks, and hardening (lockout, forced password change, token revocation, API key scoping, syslog guardrails, CORS, TLS, startup guardrails, SBOM, suppression, self-monitoring, backup, footprint).

One known, pre-existing flaky test: `tests/test_csv_export_sanitization.py` occasionally fails only when run as part of the full suite (never in isolation) due to test-order-dependent DB state — not a regression signal on its own.

---

## Project Structure

```
tinysiem/
├── docker-compose.yml
├── .env.example
├── .env                        — gitignored; contains secrets
├── nginx/
│   └── nginx.conf              — log_format tinysiem; access/error log paths
├── app/
│   ├── Dockerfile
│   ├── docker-entrypoint.sh    — conditional HTTPS (uvicorn --ssl-certfile/--ssl-keyfile) if TLS env vars are set
│   ├── requirements.txt
│   ├── generate_sbom.py        — pip-freeze → JSON, baked into the image as /app/sbom.json at build time
│   ├── startup_checks.py       — validate_jwt_secret() (fatal); warn_if_default_superadmin_password(), warn_if_integrations_missing_master_key() (advisory)
│   ├── main.py                 — FastAPI entry; lifespan; routers; security headers + CSP middleware
│   ├── config.py               — pydantic-settings for TINYSIEM_* env vars; parse_cors_origins() (no AI env vars — AI config is DB-backed, see app/ai/)
│   ├── crypto.py               — Fernet encrypt()/decrypt() helpers, keyed by TINYSIEM_MASTER_KEY; used by integrations and AI Config
│   ├── auth.py                 — JWT creation/validation (epoch claim); Bearer dependency; role checks incl. ingest-only API key scoping; live user/epoch/password-gate lookup; secrets.compare_digest
│   ├── auth_router.py          — POST /auth/login (timing-safe, lockout-gated); GET /auth/me; POST /auth/logout; POST /auth/change-password
│   ├── auth_lockout.py         — in-memory brute-force lockout tracker, exponential backoff, time-based eviction
│   ├── password.py             — bcrypt helpers + monkey-patch for bcrypt >= 4.0; MIN_PASSWORD_LENGTH
│   ├── admin/
│   │   └── router.py           — POST /admin/backup — DuckDB Parquet export + alerts + custom rules/decoders as tar.gz
│   ├── sbom/
│   │   └── router.py           — GET /sbom — serves the build-time dependency inventory
│   ├── audit/
│   │   ├── store.py            — log_event() — non-blocking, never raises; also feeds security_feed
│   │   ├── security_feed.py    — mirrors allowlisted audit events into the ingest pipeline as source tinysiem_internal
│   │   └── router.py           — GET /audit, GET /audit/facets
│   ├── ingest/
│   │   ├── router.py           — POST /ingest/raw, /ingest/file, /ingest/beats
│   │   └── pipeline.py         — shared process_line() used by HTTP routes + syslog; runs the watchlist matcher on every stored event
│   ├── events/
│   │   └── router.py           — GET /events, /events/facets, /events/histogram, GET /events/{id}, GET /events/{id}/cases
│   ├── alerts/
│   │   ├── router.py           — GET /alerts, /alerts/facets, /alerts/triage-summary, GET/PATCH /alerts/{id}, GET /alerts/{id}/cases
│   │   └── file_writer.py      — JSONL append + rotation + flock; the one place anything (rule hits or watchlist hits) appends to alerts.log
│   ├── cases/
│   │   ├── router.py           — case CRUD, comments, playbook steps, and alert/event linkage (POST/DELETE /cases/{id}/alerts and /events)
│   │   └── store.py            — DuckDB CRUD for cases, case_alerts, case_events, case_comments, case_playbook_steps
│   ├── entities/
│   │   └── router.py           — GET /entities/ip/{value} — read-only aggregation (first/last seen, histogram, related alerts + cases) over existing data; no dedicated storage
│   ├── watchlists/
│   │   ├── router.py           — CRUD + /bulk + /import (CSV) for IOC watchlist entries; API-only, no dedicated UI page yet
│   │   ├── store.py            — DuckDB CRUD for watchlist_entries
│   │   └── matcher.py          — in-memory cache (exact IPs, CIDRs, UA/URI substrings), reload_cache() on startup + every mutation; check_event() called by the ingest pipeline
│   ├── searches/
│   │   └── router.py           — GET/POST/DELETE /searches — saved filter queries for the Events and Alerts pages
│   ├── baselines/
│   │   ├── router.py           — GET /baselines, GET/PATCH /baselines/violations, DELETE /baselines/{source}
│   │   ├── store.py            — DuckDB CRUD; z-score calculation
│   │   └── learner.py          — background bucket update job (Welford's online algorithm)
│   ├── integrations/
│   │   ├── router.py           — GET/POST /integrations, PATCH/DELETE/{id}, /run, /runs
│   │   ├── store.py            — DuckDB CRUD; Fernet encrypt/decrypt (via app/crypto.py); credential masking
│   │   ├── runner.py           — run_integration(); run_due() scheduler
│   │   └── drivers/
│   │       ├── __init__.py     — DRIVERS registry
│   │       ├── aws_cloudtrail.py
│   │       └── google_workspace.py
│   ├── geoip/
│   │   ├── provider.py         — CsvGeoProvider / MaxMindGeoProvider / Null; family-aware binary search
│   │   ├── router.py           — GET /geoip/{ip} (analyst+)
│   │   └── __init__.py         — configure()/enrich_event()/lookup(); called from duckdb_store.insert_event()
│   ├── query/
│   │   └── router.py           — POST /query/sql — read-only sandbox (statement allowlist, blocked-keyword scan, row cap + cell truncation, thread timeout, single-flight lock, audit)
│   ├── dashboard/
│   │   ├── router.py           — GET/PUT/DELETE /dashboard, POST /dashboard/export/html
│   │   ├── renderer.py         — HTML export; html.escape() throughout
│   │   └── widgets.py          — widget data fetchers for all 7 types
│   ├── sources/
│   │   └── router.py           — GET /sources
│   ├── decoder/
│   │   ├── engine.py           — load_decoders(), decode(source, raw); _get_nested() for dotted paths
│   │   └── decoders/           — built-in YAML decoders
│   │       ├── nginx-access.yaml
│   │       ├── syslog-rfc3164.yaml
│   │       ├── syslog-rfc5424.yaml
│   │       ├── windows-event.yaml
│   │       ├── aws-cloudtrail.yaml
│   │       ├── iptables.yaml
│   │       ├── ufw.yaml        — UFW block lines (regex; inline rsyslog ISO8601 offset)
│   │       ├── fail2ban.yaml   — fail2ban Ban/Unban/Found lines (naive tz via timestamp_tz)
│   │       ├── tinysiem-internal.yaml  — self-monitoring feed (source tinysiem_internal)
│   │       └── custom/         — drop custom decoders here (hot-reloaded; sshd-auth.yaml ships here)
│   ├── rules/
│   │   ├── engine.py           — load_rules(), evaluate(); threshold (source-scoped) + correlation + suppression state
│   │   ├── router.py           — GET/POST/PUT/DELETE /rules, /rules/generate, /rules/{name}/backtest, /rules/mitre-coverage, /rules/{name}/exceptions, /rules/{name}/playbook/generate
│   │   ├── backtest.py         — "what would this rule have fired on in the last N days" against real historical events
│   │   ├── exceptions_store.py — DuckDB CRUD for rule_exceptions
│   │   └── rules/
│   │       ├── tinysiem-internal-brute-force.yaml  — built-in self-monitoring rule (filename must match its internal name: field — enforced on create/update)
│   │       └── custom/         — drop custom rules here (hot-reloaded; ssh-bruteforce, ssh-bruteforce-then-success, fail2ban-ban, fail2ban-unban, ufw-repeated-blocks ship here)
│   ├── parsers/
│   │   └── router.py           — GET/POST/PUT/DELETE /parsers, /parsers/generate, /parsers/{name}/test
│   ├── users/
│   │   └── router.py           — GET/POST/PUT/DELETE /users
│   ├── mcp_server/
│   │   └── server.py           — FastMCP app; _JWTMiddleware with role check; 8 tools (list_events, get_alerts, list_parsers, list_rules, get_health, investigate_ip, get_alert_context, query_events_sql); mounted at /mcp/sse only if TINYSIEM_MCP_ENABLED
│   ├── ai/
│   │   ├── router.py           — POST /ai/explain-alert, /ai/analyze-events, /ai/search, GET/PUT /ai/config, POST /ai/config/test
│   │   ├── provider_factory.py — get_active_provider(); PROVIDER_PRESETS (anthropic / openai / deepseek / custom base_url)
│   │   ├── config_store.py     — CRUD for the single-row ai_config table; API key encrypted via app/crypto.py
│   │   ├── claude.py           — generate_parser(), generate_rule(); _log_ai_call() shared by every AI feature
│   │   ├── enrichment.py       — explain_alert(), analyze_events(), generate_playbook(), refine_playbook()
│   │   ├── home_search.py      — run_search() — the 3-call extract→query→summarize flow behind the Home page search box
│   │   └── providers/
│   │       ├── base.py                        — AIProvider protocol + ChatResult dataclass
│   │       ├── anthropic_provider.py           — wraps the Anthropic SDK
│   │       └── openai_compatible_provider.py   — wraps the OpenAI SDK with a configurable base_url (covers OpenAI, DeepSeek, and any OpenAI-compatible endpoint)
│   ├── notifications/
│   │   ├── router.py           — POST /notifications/test, GET /notifications/config
│   │   └── sender.py           — email (SMTP) + webhook dispatch
│   ├── retention/
│   │   ├── router.py           — GET /retention/status, POST /retention/run
│   │   └── archiver.py         — archive_old_events(); Parquet export
│   ├── reports/
│   │   ├── router.py           — GET /reports/generate, /reports/download, POST /reports/send
│   │   └── generator.py        — aggregate report data; HTML render
│   ├── storage/
│   │   └── duckdb_store.py     — all DuckDB table definitions + ops; single _conn + threading.Lock; _escape_like(); count_events_in_window(source-scoped)
│   ├── listeners/
│   │   └── syslog.py           — asyncio UDP + TCP syslog listeners; RFC auto-detect; CIDR allowlist + size cap; drop counters
│   └── tests/                  — 69 files, 546 tests. conftest.py sets env vars + JWT-backed role fixtures (analyst_headers/admin_headers/superadmin_headers) and an ingest-only API key fixture before any app.* module is imported. Organized roughly one file per router/feature module (test_ingest.py, test_events.py, test_alerts.py, test_cases.py, test_case_event_linkage.py, test_rules_crud.py, test_correlation_rules.py, test_watchlist_matching.py, test_home_search.py, test_ai_search_endpoint.py, test_auth.py, test_auth_lockout.py, test_baselines.py, test_integrations.py, test_dashboard.py, test_backup.py, etc.) — see the directory for the authoritative, current list rather than relying on this doc.
├── ui/
│   ├── nav.js                  — shared top nav bar (Dashboard · Events · Alerts · Cases · Rules · Parsers) + profile dropdown (Settings, Audit Log for superadmin); active-item highlight from location.pathname
│   ├── shared.css               — nav styling, design tokens, badge styles
│   ├── fonts.css                — @font-face rules for self-hosted IBM Plex Sans/Mono
│   ├── fonts/                   — vendored IBM Plex TTF files (Sans 400/500/600, Mono 400/500)
│   ├── vendor/
│   │   └── chart.umd.min.js    — vendored Chart.js (same version previously loaded from a CDN)
│   ├── login.html               — includes forced password-change panel
│   ├── home.html                — AI natural-language search landing page; redirect target of `/` and the nav logo
│   ├── dashboard.html          — custom widgets, edit mode, auto-refresh
│   ├── events.html             — includes New Case / Add to Case buttons on each expand-row
│   ├── alerts.html              — includes triage panel, New Case / Add to Case, and the tabbed Alert/Logs/Rule detail modal
│   ├── cases.html               — case detail panel supports a `?case_id=` deep link
│   ├── entity.html              — IP entity pivot/summary page
│   ├── rules.html               — includes its own MITRE ATT&CK coverage tab and a resizable rule-list column
│   ├── parsers.html            — resizable parser-list column
│   ├── audit.html               — superadmin-only, reachable via the profile dropdown (not the top nav)
│   └── settings.html           — 10 tabs: Instance, Users & Access, Notifications, Retention, Ingestion, Baselines, Integrations, Sources, Reports, AI Config
├── scripts/
│   ├── gen_nginx_logs.py       — generate nginx log lines to stdout
│   ├── ingest_test_logs.py     — generate + POST to TinySIEM (stdlib only)
│   ├── ingest_file.py          — bulk-upload any log/CSV file (20k lines/request, retries, rejects file)
│   ├── ingest_auth_log.py      — parse auth.log* → normalized JSONL; --follow = real-time sshd tailer (systemd-ready)
│   ├── ingest_syslog_tail.py   — generic raw-line tailer (--source <decoder> --follow <file>; 422 = skip-not-retry) — used for ufw/fail2ban
│   ├── fetch_geoip_db.py       — download current db-ip lite CSV files (no registration)
│   ├── backfill_geoip.py       — enrich historical events (rebuild events table; run with server stopped)
│   └── mcp_probe.py            — MCP SSE client probe (initialize + tools/list + call a tool)
└── logs/                       — shared Docker volume (nginx writes, tinysiem reads :ro)
```

---

## Key Implementation Notes

### DuckDB thread safety
A single global `_conn` is protected by `threading.Lock()`. All queries must hold this lock. Python's `threading.Lock` is not re-entrant — never call a DuckDB function from within an already-locked block unless the called function acquires its own separate lock or you've guaranteed no re-entry.

**Known DuckDB 1.1.x constraint:** `UPDATE` on a table that has a `PRIMARY KEY` **and** any secondary `CREATE INDEX` can raise an internal error. The safe default followed throughout this codebase: never add `CREATE INDEX` to a table that receives `UPDATE` statements, and use a DELETE + INSERT pattern instead of UPDATE where a secondary index is genuinely needed. This applies to `baselines`, `baseline_violations`, `cases`, `integrations`, `integration_runs`, `watchlist_entries`, `ai_config`, and `case_playbook_steps`. Purely insert/delete tables (`case_alerts`, `case_events`, `saved_searches`, `rule_exceptions`) never hit this constraint since they have no `UPDATE` path at all.

`case_comments` is a known exception to the "never combine the two" rule of thumb: it has both a secondary index (`idx_comments_case`) and a real `UPDATE` (`update_comment()`, editing a comment's `body`/`edited_at`) — and it works fine in practice, presumably because the update never touches the indexed `case_id` column itself. Treat the blanket rule above as the safe default for new tables rather than a proven-universal constraint; if you need to UPDATE a column that isn't part of any secondary index, it may be safe, but the DELETE+INSERT pattern remains the well-tested fallback if you hit the error.

### LIKE wildcard escaping
`_build_where()` in `duckdb_store.py` calls `_escape_like(val)` before embedding user input in `LIKE`/`ILIKE` patterns. This escapes `%`, `_`, and `\` so user-supplied strings are treated literally, preventing filter-bypass via SQL metacharacters.

### Audit log
`audit.log_event()` is fire-and-forget: it catches and logs all exceptions internally and never propagates. Hook it at action sites, not in middleware, to capture meaningful actor/resource context.

### Security headers middleware
`main.py` adds `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Referrer-Policy: strict-origin-when-cross-origin` to every response via a FastAPI `@app.middleware("http")` handler. Requests under `/ui` additionally get a `Content-Security-Policy` header (`default-src 'self'`, `script-src`/`style-src 'self' 'unsafe-inline'`, `frame-ancestors 'none'`, etc.) — API responses outside `/ui` don't need it.

### Timing-safe login
`auth_router.py` always runs bcrypt verification regardless of whether the username exists, using a pre-computed `_DUMMY_HASH`. This prevents an attacker from enumerating valid usernames by measuring the difference between a ~100 ms bcrypt response and a <1 ms short-circuit response. The lockout check (`app/auth_lockout.py`) runs *before* this, so a locked-out request never reaches bcrypt at all.

### Token epoch (revocation)
Every user row carries a `token_epoch` integer; every JWT carries an `epoch` claim matching the value at issue time. `require_auth` compares the two on every request and rejects a mismatch with `401`. Password change, `/auth/logout`, and any superadmin-driven user update bump the stored epoch, instantly invalidating every previously-issued token for that user — there's no token blocklist to maintain.

### Self-monitoring feed
`app/audit/store.py`'s `log_event()` calls `security_feed.feed()` on every audit event. `feed()` only acts on an allowlist of event types (`auth.login`, `auth.lockout`, `user.*`, `integration.*`); everything else is a no-op. Allowlisted events are re-ingested as source `tinysiem_internal` via the normal `process_line()` pipeline, so ordinary detection rules can fire on them — nothing in that pipeline calls back into `log_event()`, so there's no recursion risk.

### Threshold counting is source-scoped
`count_events_in_window()` takes an optional `source` parameter; `_evaluate_rule` passes the firing rule's own `source` unless it's the wildcard `"*"`. This keeps rules like the built-in self-monitoring brute-force rule from counting matching events from unrelated sources.

### Integration credential encryption
`app/integrations/store.py` uses Fernet symmetric encryption (`cryptography` package). Each credential value is individually encrypted and stored as a base64 ciphertext. `TINYSIEM_MASTER_KEY` is the Fernet key. The API never returns raw credentials — they are masked to `**...LAST4` on all read endpoints.

### Syslog auto-detection
`detect_format(raw)` checks whether the field after the priority `<N>` starts with `"1 "` (RFC 5424 version number). If yes, routes to `syslog_rfc5424`; otherwise `syslog_rfc3164`.

### Decoder arg order
`decoder_engine.decode(source, raw)` — `source` is always first. This matches the ingest pipeline in `app/ingest/pipeline.py`. (The integration runner previously had these reversed — fixed in security hardening commit.)

### Rule engine: evaluate() returns None
`rule_engine.evaluate(event)` writes alerts internally via `file_writer.write_alert(rule, event)`. It has no return value. Callers should not iterate its return value.

### `process_line(source, raw, strict=True)`
Shared by all ingest paths (HTTP routes + syslog listeners). `strict=False` stores a minimal raw event when no decoder matches (used by Beats and syslog where decoder availability isn't guaranteed).

### conftest.py ordering
`conftest.py` must set env vars before any `app.*` module is imported (pydantic-settings reads them at import time). Never import `app.*` at module level in test files. It also pins every `TINYSIEM_*` var (including `TINYSIEM_MASTER_KEY`, `TINYSIEM_GEOIP_DB_PATH`, `TINYSIEM_GEOIP_ASN_PATH`) — a live `.env` in the CWD would otherwise leak into the suite.

### SQL sandbox (read-only)
`app/query/router.py` guards `POST /query/sql`: statement allowlist (SELECT/WITH/SHOW/DESCRIBE/EXPLAIN/VALUES), comments stripped BEFORE the keyword check, bare `;` rejected, blocked-keyword scan, row cap + 500-char cell truncation, thread-based timeout (`fut.result(timeout=)` — DuckDB 1.1.3 has no `statement_timeout`), single-flight `_exec_lock` (busy → 429), and every query audited as `query.sql`. It connects to the same DB file **in-process** — a second connection is fine; only a second *process* hits the single-writer file lock.

### Timestamps are naive UTC everywhere
DuckDB TIMESTAMP stores no timezone; every parsed `event_time` is normalized to naive UTC at decode (decoders may declare `timestamp_tz` for naive logs — see `app/decoder/engine.py::_parse_timestamp`). The API serializes every timestamp with an explicit `Z` suffix so browsers parse them as UTC, and the UI renders browser-local time. Filter params are UTC — never send local time. For live windows in SQL compare with `epoch(ingested_at) >= epoch(current_timestamp) - N` (server-local `current_timestamp` on a CST host is 8h off stored UTC).

### GeoIP enrichment chokepoint
`duckdb_store.insert_event()` calls `geoip.enrich_event()` — one hook covers raw/file/beats/syslog/integrations. Providers: db-ip lite CSV (stdlib-only binary search; formats vary by release — parser maps by column count) or MaxMind `.mmdb` (`pip install geoip2`, optional dep). Historical backfill rebuilds the table via `CREATE TABLE events_new AS SELECT ... LEFT JOIN` + `DROP`/`ALTER RENAME` (UPDATE is blocked by PK + indexes); run with the server stopped.

### AI Config encryption
`app/ai/config_store.py` upserts the single-row `ai_config` via DELETE+INSERT (DuckDB UPDATE constraint). The API key is Fernet-encrypted via `app/crypto.py` — **saving a config with an `api_key` raises `MasterKeyNotConfigured` when `TINYSIEM_MASTER_KEY` is unset**; there is no plaintext fallback (older docs claiming otherwise are stale). Switching provider without a new key clears the old key rather than leaking it across providers.

### Real-time tailers (systemd)
`ingest_auth_log.py --follow` and `ingest_syslog_tail.py` implement tail -F semantics in stdlib (start at EOF, inode detection for logrotate, per-line POST with 3-attempt backoff). `ingest_syslog_tail.py` treats 422 (no decoder match) as permanent — counted and skipped, never retried. Run exactly ONE tailer per file (two = duplicate events). The live VPS runs them as `tinysiem-{sshd,ufw,fail2ban}-tailer.service`.

### Repo-tree mutation landmines (tests)
`test_rules_crud.py`/`test_parsers.py` autouse fixtures USED to unlink every `*.yaml` in the repo's custom dirs; `test_audit.py` leaked created files. Now diff-only cleanup. If custom files vanish after a pytest run: `git status` → `git checkout -- <path>`. Don't blame `git stash` first.

---

## Adding a New API Module

1. Create `app/<module>/router.py` with an `APIRouter`
2. Add auth dependency: `Depends(require_analyst)`, `require_admin`, or `require_superadmin`
3. Add audit hooks: `from app.audit import store as audit; audit.log_event(...)`
4. Include the router in `app/main.py` lifespan and router list
5. Write tests in `tests/test_<module>.py`

---

## UI Pages

All pages are single self-contained HTML files — no build step, no framework. Vanilla JS + CSS. IBM Plex Sans + IBM Plex Mono are self-hosted (`ui/fonts.css` + `ui/fonts/`) — the UI makes zero external network requests at runtime, including Chart.js, which is vendored at `ui/vendor/chart.umd.min.js`.

A shared `ui/nav.js` renders the identical top nav bar and profile dropdown on every page and highlights the active link from `location.pathname` — pages no longer each carry their own copy of the sidenav.

Page-level conventions:
- Module-level `S` object holds all page state
- `TH = document.documentElement` — theme applied as `data-theme` attribute on `<html>`
- `ts_jwt`, `ts_ep`, `ts_theme`, `ts_username`, `ts_role`, `ts_key` persisted in `localStorage`
- JWT decoded client-side via `parseJwt()` for role checks and expiry
- `api(path)` helper handles auth headers and 401 → redirect to login
- `esc(s)` for all user-controlled strings inserted into HTML — escapes `&`, `<`, `>`, `"`, `'`

**XSS pattern — never use inline onclick with user data:**
```javascript
// Wrong — &#39; is HTML-decoded back to ' by the browser before JS runs
html += `<div onclick="clickFacet('${esc(val)}')">`;

// Correct — data-* attributes + event delegation
html += `<div data-fkey="${esc(key)}" data-fval="${esc(val)}">`;
container.addEventListener('click', e => {
    const el = e.target.closest('[data-fkey]');
    if (el) clickFacet(el.dataset.fkey, el.dataset.fval);
});
```

---

→ [Troubleshooting](troubleshooting.md) — common errors and fixes

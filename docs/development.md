# Development

## Running Tests

Tests must run inside the Docker container — DuckDB and ChromaDB are installed in the image, not on the host:

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

Test coverage: **216 tests** across ingest, events, alerts, parsers, rules, users, auth, correlation, syslog, Beats, retention, reports, notifications, audit, AI, baselines, cases, integrations, and dashboard.

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
│   ├── requirements.txt
│   ├── main.py                 — FastAPI entry; lifespan; routers; security headers middleware
│   ├── config.py               — pydantic-settings for TINYSIEM_* env vars
│   ├── auth.py                 — JWT creation/validation; Bearer dependency; role checks; secrets.compare_digest
│   ├── auth_router.py          — POST /auth/login (timing-safe); GET /auth/me
│   ├── password.py             — bcrypt helpers + monkey-patch for bcrypt >= 4.0
│   ├── audit/
│   │   ├── store.py            — log_event() — non-blocking, never raises
│   │   └── router.py           — GET /audit, GET /audit/facets
│   ├── ingest/
│   │   ├── router.py           — POST /ingest/raw, /ingest/file, /ingest/beats
│   │   └── pipeline.py         — shared process_line() used by HTTP routes + syslog
│   ├── events/
│   │   └── router.py           — GET /events, /events/facets, /events/histogram
│   ├── alerts/
│   │   ├── router.py           — GET /alerts, /alerts/facets, PATCH /alerts/{id}
│   │   └── file_writer.py      — JSONL append + rotation + flock
│   ├── cases/
│   │   ├── router.py           — GET/POST /cases, GET/PATCH/DELETE /cases/{id}
│   │   └── store.py            — DuckDB CRUD for cases table
│   ├── baselines/
│   │   ├── router.py           — GET /baselines, GET/PATCH /baselines/violations
│   │   ├── store.py            — DuckDB CRUD; z-score calculation
│   │   └── learner.py          — background bucket update job
│   ├── integrations/
│   │   ├── router.py           — GET/POST /integrations, PATCH/DELETE/{id}, /trigger, /runs
│   │   ├── store.py            — DuckDB CRUD; Fernet encrypt/decrypt; credential masking
│   │   ├── runner.py           — run_integration(); run_due() scheduler
│   │   └── drivers/
│   │       ├── __init__.py     — DRIVERS registry
│   │       ├── aws_cloudtrail.py
│   │       └── google_workspace.py
│   ├── dashboard/
│   │   ├── router.py           — GET/PUT /dashboard, POST /dashboard/export/html
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
│   │       └── custom/         — drop custom decoders here (hot-reloaded)
│   ├── rules/
│   │   ├── engine.py           — load_rules(), evaluate(); threshold + correlation state
│   │   ├── router.py           — GET/POST/PUT/DELETE /rules, POST /rules/generate
│   │   └── rules/
│   │       └── custom/         — drop custom rules here (hot-reloaded)
│   ├── parsers/
│   │   └── router.py           — GET/POST/PUT/DELETE /parsers, /parsers/generate, /parsers/{name}/test
│   ├── users/
│   │   └── router.py           — GET/POST/PUT/DELETE /users
│   ├── mcp_server/
│   │   └── server.py           — FastMCP app; _JWTMiddleware with role check; 5 tools
│   ├── ai/
│   │   └── claude.py           — generate_parser(), generate_rule(); AI call audit
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
│   │   ├── duckdb_store.py     — all DuckDB ops; single _conn + threading.Lock; _escape_like()
│   │   └── chroma_store.py     — ChromaDB upsert (non-fatal; future AI triage)
│   ├── listeners/
│   │   └── syslog.py           — asyncio UDP + TCP syslog listeners; RFC auto-detect
│   └── tests/
│       ├── conftest.py         — env vars + chromadb stub + fixtures
│       ├── test_ingest.py
│       ├── test_events.py
│       ├── test_alerts.py
│       ├── test_auth.py
│       ├── test_users.py
│       ├── test_parsers.py
│       ├── test_rules.py
│       ├── test_rules_crud.py
│       ├── test_audit.py
│       ├── test_builtin_decoders.py
│       ├── test_beats_ingest.py
│       ├── test_syslog_listener.py
│       ├── test_correlation_rules.py
│       ├── test_retention.py
│       ├── test_reports.py
│       ├── test_notifications.py
│       ├── test_baselines.py
│       ├── test_cases.py
│       ├── test_integrations.py
│       ├── test_dashboard.py
│       └── test_ai.py
├── ui/
│   ├── shared.css              — nav component, tokens, badge styles
│   ├── login.html
│   ├── dashboard.html          — custom widgets, edit mode, auto-refresh
│   ├── events.html
│   ├── alerts.html
│   ├── cases.html
│   ├── baselines.html
│   ├── rules.html
│   ├── parsers.html
│   ├── audit.html
│   ├── users.html
│   └── configuration.html      — settings + integrations + users
├── scripts/
│   ├── gen_nginx_logs.py       — generate nginx log lines to stdout
│   └── ingest_test_logs.py     — generate + POST to TinySIEM (stdlib only)
└── logs/                       — shared Docker volume (nginx writes, tinysiem reads :ro)
```

---

## Key Implementation Notes

### DuckDB thread safety
A single global `_conn` is protected by `threading.Lock()`. All queries must hold this lock. Python's `threading.Lock` is not re-entrant — never call a DuckDB function from within an already-locked block unless the called function acquires its own separate lock or you've guaranteed no re-entry.

**Known DuckDB 1.1.x constraint:** `UPDATE` on a table that has a `PRIMARY KEY` **and** any secondary `CREATE INDEX` raises an internal error. Workaround: never add `CREATE INDEX` to tables that receive `UPDATE` statements. Affected tables use a DELETE + INSERT pattern instead of UPDATE. This applies to `baselines`, `baseline_violations`, `cases`, `integrations`, and `integration_runs`.

### LIKE wildcard escaping
`_build_where()` in `duckdb_store.py` calls `_escape_like(val)` before embedding user input in `LIKE`/`ILIKE` patterns. This escapes `%`, `_`, and `\` so user-supplied strings are treated literally, preventing filter-bypass via SQL metacharacters.

### Audit log
`audit.log_event()` is fire-and-forget: it catches and logs all exceptions internally and never propagates. Hook it at action sites, not in middleware, to capture meaningful actor/resource context.

### Security headers middleware
`main.py` adds `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Referrer-Policy: strict-origin-when-cross-origin` to every response via a FastAPI `@app.middleware("http")` handler.

### Timing-safe login
`auth_router.py` always runs bcrypt verification regardless of whether the username exists, using a pre-computed `_DUMMY_HASH`. This prevents an attacker from enumerating valid usernames by measuring the difference between a ~100 ms bcrypt response and a <1 ms short-circuit response.

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
`conftest.py` must set env vars and stub `chromadb` in `sys.modules` before any `app.*` module is imported. Never import `app.*` at module level in test files.

---

## Adding a New API Module

1. Create `app/<module>/router.py` with an `APIRouter`
2. Add auth dependency: `Depends(require_analyst)`, `require_admin`, or `require_superadmin`
3. Add audit hooks: `from app.audit import store as audit; audit.log_event(...)`
4. Include the router in `app/main.py` lifespan and router list
5. Write tests in `tests/test_<module>.py`

---

## UI Pages

All pages are single self-contained HTML files — no build step, no framework. Vanilla JS + CSS. IBM Plex Sans + IBM Plex Mono from Google Fonts.

Page-level conventions:
- Module-level `S` object holds all page state
- `TH = document.documentElement` — theme applied as `data-theme` attribute on `<html>`
- `ts_jwt`, `ts_ep`, `ts_theme`, `ts_nav_collapsed` persisted in `localStorage`
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

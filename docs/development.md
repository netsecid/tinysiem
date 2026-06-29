# Development

## Running Tests

Tests must run inside the Docker container — the app uses DuckDB and ChromaDB that aren't installed on the host:

```bash
# Full suite
docker-compose exec -w /app tinysiem pytest tests/ -v

# Single file
docker-compose exec -w /app tinysiem pytest tests/test_audit.py -v

# Single test
docker-compose exec -w /app tinysiem pytest tests/test_audit.py::test_login_success_creates_audit -v
```

Test coverage: 145 tests across ingest, events, alerts, parsers, rules, users, auth, correlation, syslog, Beats, retention, reports, notifications, and audit.

---

## Project Structure

```
tinysiem/
├── docker-compose.yml
├── .env.example
├── nginx/
│   └── nginx.conf              — log_format tinysiem; access/error log paths
├── app/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py                 — FastAPI entry; lifespan; routers; exception handler
│   ├── config.py               — pydantic-settings for TINYSIEM_* env vars
│   ├── auth.py                 — JWT creation/validation; Bearer dependency; role checks
│   ├── auth_router.py          — POST /auth/login
│   ├── password.py             — bcrypt helpers
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
│   │   └── file_writer.py      — JSONL append + rotation
│   ├── decoder/
│   │   ├── engine.py           — load_decoders(), decode(); _get_nested() for dotted paths
│   │   └── decoders/           — built-in YAML decoders
│   │       ├── nginx-access.yaml
│   │       ├── syslog-rfc3164.yaml
│   │       ├── syslog-rfc5424.yaml
│   │       ├── windows-event.yaml
│   │       ├── aws-cloudtrail.yaml
│   │       ├── iptables.yaml
│   │       └── custom/         — drop custom decoders here
│   ├── rules/
│   │   ├── engine.py           — load_rules(), evaluate(); threshold + correlation state
│   │   ├── router.py           — GET/POST/PUT/DELETE /rules, POST /rules/generate
│   │   └── rules/              — built-in YAML rules
│   │       └── custom/         — drop custom rules here
│   ├── parsers/
│   │   └── router.py           — GET/POST/PUT/DELETE /parsers, /parsers/generate, /parsers/{name}/test
│   ├── users/
│   │   └── router.py           — GET/POST/PUT/DELETE /users
│   ├── storage/
│   │   ├── duckdb_store.py     — all DuckDB operations; single _conn + threading.Lock
│   │   └── chroma_store.py     — ChromaDB upsert (non-fatal; future AI triage)
│   ├── listeners/
│   │   └── syslog.py           — asyncio UDP + TCP syslog listeners; auto-detects RFC
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
│   └── tests/
│       ├── conftest.py         — env vars + chromadb stub + fixtures (must run before any app import)
│       ├── test_ingest.py
│       ├── test_events.py
│       ├── test_alerts.py
│       ├── test_auth.py
│       ├── test_users.py
│       ├── test_parsers.py
│       ├── test_rules.py
│       ├── test_audit.py
│       ├── test_builtin_decoders.py
│       ├── test_beats_ingest.py
│       ├── test_syslog_listener.py
│       ├── test_correlation_rules.py
│       ├── test_retention.py
│       ├── test_reports.py
│       └── test_notifications.py
├── ui/
│   ├── shared.css              — nav component, tokens, badge styles
│   ├── login.html
│   ├── dashboard.html
│   ├── events.html
│   ├── alerts.html
│   ├── rules.html
│   ├── parsers.html
│   ├── audit.html
│   ├── users.html
│   └── configuration.html
├── scripts/
│   ├── gen_nginx_logs.py       — generate nginx log lines to stdout
│   └── ingest_test_logs.py     — generate + POST to TinySIEM (stdlib only)
└── logs/                       — shared Docker volume (nginx writes, tinysiem reads :ro)
```

---

## Key Implementation Notes

### DuckDB thread safety
A single global `_conn` is protected by `threading.Lock()`. All queries must acquire this lock. The `_counts()` helper in `get_audit_facets` is a nested function defined inside the `with _lock:` block — it calls `_conn.execute()` directly without re-acquiring (Python `Lock` is not re-entrant).

### Audit log
`audit.log_event()` is fire-and-forget: it catches and logs all exceptions internally and never propagates. Hook it at action sites, not in middleware, to get meaningful actor/resource context.

### Syslog auto-detection
`detect_format(raw)` checks whether the string after the priority field starts with `"1 "` (RFC 5424 version number). If yes, route to `syslog_rfc5424` decoder; otherwise `syslog_rfc3164`.

### Decoder field resolution
`_get_nested(data, key)` resolves dotted paths (e.g. `winlog.event_id`) in JSON-type decoders. Used in `_apply_fields` and `_parse_timestamp`.

### `process_line(source, raw, strict=True)`
Extracted to `app/ingest/pipeline.py` and shared by all ingest paths (HTTP routes + syslog listeners). `strict=False` stores a minimal raw event when no decoder matches (used by Beats and syslog paths where decoder availability isn't guaranteed).

### conftest.py ordering
`conftest.py` must set env vars and stub `chromadb` in `sys.modules` **before** any `app.*` module is imported. Never import `app.*` at module level in test files.

---

## Adding a New API Module

1. Create `app/<module>/router.py` with an `APIRouter`
2. Add audit hooks using `from app.audit import store as audit; audit.log_event(...)`
3. Import and include the router in `app/main.py`
4. Add tests in `app/tests/test_<module>.py`

---

## UI Pages

All pages are single self-contained HTML files — no build step, no framework. Vanilla JS + CSS. IBM Plex Sans + IBM Plex Mono from Google Fonts.

Page-level conventions:
- Module-level `S` object holds all page state
- `TH = document.documentElement` — theme applied as `data-theme` attribute
- `ts_jwt`, `ts_ep`, `ts_theme`, `ts_nav_collapsed` persisted in `localStorage`
- JWT decoded client-side via `parseJwt()` for role checks and expiry
- `api(path)` helper handles auth headers and 401 → redirect to login
- `esc(s)` for all user-controlled strings inserted into HTML

---

→ [Troubleshooting](troubleshooting.md) — common errors and fixes

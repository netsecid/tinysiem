# TinySIEM v0.7 — Operations Design Spec

**Date:** 2026-06-29
**Status:** Approved for implementation
**Builds on:** v0.6 AI-Native (JWT auth, role hierarchy, parser/rule CRUD, MCP server)

---

## Overview

v0.7 makes TinySIEM production-grade. It adds four operational pillars: alert triage (analysts can track and resolve alerts), alert notifications (email/webhook on rule fire), log retention with automatic archiving (DuckDB stays bounded), and scheduled reports (daily/weekly digest delivered via email or downloadable).

No new frontend framework is introduced. All UI changes extend the existing vanilla JS + CSS pages.

---

## Section 1 — Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  UI Layer     alerts.html (triage panel)                        │
│               dashboard.html (triage status cards)              │
│               configuration.html (notifications + retention)    │
└───────────────────────────┬─────────────────────────────────────┘
                            │ REST
┌───────────────────────────▼─────────────────────────────────────┐
│  API Layer    PATCH /alerts/{alert_id}   (triage update)        │
│               GET  /alerts/{alert_id}    (single alert)         │
│               POST /notifications/test   (smoke test)           │
│               GET  /retention/status     (archive stats)        │
│               GET  /reports/generate     (JSON report)          │
│               GET  /reports/download     (HTML attachment)       │
└───────────────────────────┬─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│  Service Layer  app/notifications/sender.py  (email + webhook)  │
│                 app/retention/archiver.py    (DuckDB → JSONL.gz)│
│                 app/reports/generator.py     (aggregate queries) │
│                 Background threads: archiver + report scheduler  │
└───────────────────────────┬─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│  Storage     DuckDB: events table (existing)                    │
│              DuckDB: alert_triage table (NEW)                   │
│              DuckDB: users table (existing)                     │
│              JSONL: alerts.log (existing, immutable/append-only)│
│              JSONL.gz: /app/data/archive/ (NEW, retention only) │
└─────────────────────────────────────────────────────────────────┘
```

---

## Section 2 — Feature 1: Alert Triage Workflow

### Design principles

The existing `alerts.log` JSONL file is immutable (append-only). Triage state is mutable. Keeping them separate avoids JSONL rewrite complexity and preserves the audit trail.

A new DuckDB table `alert_triage` holds mutable per-alert state. The read path merges JSONL + triage.

### DuckDB table

```sql
CREATE TABLE IF NOT EXISTS alert_triage (
    alert_id    VARCHAR PRIMARY KEY,
    status      VARCHAR NOT NULL DEFAULT 'open',   -- open | investigating | resolved
    notes       TEXT    NOT NULL DEFAULT '',
    assigned_to VARCHAR NOT NULL DEFAULT '',        -- username
    updated_at  TIMESTAMP,
    updated_by  VARCHAR NOT NULL DEFAULT ''         -- username of updater
)
```

### Read merge logic (in `_read_all_alerts()`)

1. Load JSONL → `list[dict]`
2. Load all rows from `alert_triage` → `dict[alert_id, triage_row]`
3. For each alert dict: overlay triage fields if found; otherwise inject defaults (`status='open'`, `notes=''`, `assigned_to=''`)

This means triage rows are created lazily on first PATCH (no insert needed on alert fire).

### API additions

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/alerts/{alert_id}` | analyst+ | Return single alert with triage state merged |
| `PATCH` | `/alerts/{alert_id}` | analyst+ | Update triage fields |

`PATCH` body (all fields optional):
```json
{ "status": "investigating", "notes": "Looking at source IP", "assigned_to": "jsmith" }
```

`PATCH` validates:
- `status` must be `open | investigating | resolved` if provided
- `alert_id` must exist in JSONL (scan `_read_all_alerts` filtered by id) — 404 if not found
- `assigned_to` must be empty string OR a valid username from the users table (or just any non-empty string is fine — keep it simple, no foreign key check)

### UI changes — `alerts.html`

Add a right-side triage panel that opens when a row is clicked:
- Alert metadata (rule_name, severity, triggered_at, source_ip, summary, MITRE)
- **Status dropdown**: open / investigating / resolved (styled with severity-style colors)
- **Notes textarea**: free-form text
- **Assigned to input**: text input (autocomplete from `/users` list)
- **Save** button: calls `PATCH /alerts/{alert_id}`
- Triage status badge on each row in the table: colored pill (open=gray, investigating=amber, resolved=green)

### UI changes — `dashboard.html`

Replace or augment the existing alert severity cards with triage status counts:
- Add 3 stat cards: **Open**, **Investigating**, **Resolved** (read from a new `/alerts/triage-summary` endpoint or derived from `/alerts/facets` extended to include status counts)
- Triage summary endpoint: `GET /alerts/triage-summary` → `{ "open": N, "investigating": N, "resolved": N }`

---

## Section 3 — Feature 2: Alert Notifications

### Approach

- Stdlib only: `smtplib` (email) + `urllib.request` (webhook) — no new PyPI packages
- Notifications are best-effort: failure is logged but never raises (ingest must not fail due to SMTP down)
- Configuration via env vars (no runtime DB config in v0.7 — v0.8 can move to DB)

### Environment variables (new)

```
TINYSIEM_SMTP_HOST          # e.g. smtp.gmail.com (empty = disabled)
TINYSIEM_SMTP_PORT          # default 587
TINYSIEM_SMTP_USER          # SMTP username
TINYSIEM_SMTP_PASS          # SMTP password
TINYSIEM_SMTP_FROM          # From address
TINYSIEM_SMTP_TO            # Comma-separated recipients
TINYSIEM_SMTP_TLS           # true | false (default true — STARTTLS)
TINYSIEM_WEBHOOK_URL        # HTTP/HTTPS URL (empty = disabled)
TINYSIEM_NOTIFY_MIN_SEV     # low | medium | high | critical (default high)
```

### Module: `app/notifications/sender.py`

```python
def should_notify(severity: str) -> bool
def send_email(alert: dict) -> None      # non-raising; logs errors
def send_webhook(alert: dict) -> None    # non-raising; logs errors
def notify(alert: dict) -> None          # calls both if configured and severity qualifies
```

Email subject: `[TinySIEM] {severity.upper()} alert: {rule_name}`
Email body: plain text with alert fields + link to alerts page

Webhook payload (JSON POST):
```json
{
  "alert_id": "...", "rule_name": "...", "severity": "...",
  "triggered_at": "...", "source_ip": "...", "summary": "...",
  "mitre_tactic": "...", "mitre_technique": "..."
}
```

### Hook into `file_writer.write_alert()`

After `fh.write(json.dumps(alert) + "\n")` and before `fh.flush()`:
```python
from app.notifications.sender import notify
notify(alert)   # non-raising — logged internally
```

### API: `POST /notifications/test`

Auth: admin+
Body: `{ "channel": "email" | "webhook" | "all" }`
Returns: `{ "email": "sent" | "skipped" | "error: ...", "webhook": "..." }`
Sends a synthetic test alert.

### Configuration page additions

Add a "Notifications" section to `ui/configuration.html`:
- Shows current env var values (masked password)
- Note: "Configured via environment variables — restart required to apply"
- Test button → calls `POST /notifications/test`
- Shows last test result

---

## Section 4 — Feature 3: Log Retention

### Approach

- Background thread started at lifespan, runs every 6 hours
- Archives events older than `TINYSIEM_RETENTION_DAYS` (default 30) days
- Archive files: `/app/data/archive/archive-{YYYY-MM-DD}-{seq}.jsonl.gz`
- Each file capped at `TINYSIEM_ARCHIVE_CHUNK_MB` (default 500) MB uncompressed
- After successful write, DELETE those event IDs from DuckDB
- Thread-safe: uses existing `_lock` from `duckdb_store`

### Environment variables (new)

```
TINYSIEM_RETENTION_DAYS     # default 30
TINYSIEM_ARCHIVE_PATH       # default /app/data/archive
TINYSIEM_ARCHIVE_CHUNK_MB   # default 500
```

### Module: `app/retention/archiver.py`

```python
def archive_old_events() -> dict          # {"archived": N, "files": [...]}
def get_retention_status() -> dict        # {"online_count": N, "archive_files": [...], ...}
def start_retention_thread() -> None      # called from lifespan
```

Archive algorithm:
1. Query events where `ingested_at < now - retention_days`, ORDER BY ingested_at, LIMIT 50000
2. Open gzip file for writing
3. For each event row: write JSON line + track byte count; if bytes ≥ chunk_mb, close and open next file
4. Collect all archived `id` values
5. DELETE FROM events WHERE id IN (...)  — batched in chunks of 1000
6. Log result; return summary

### API: `GET /retention/status`

Auth: admin+
Returns:
```json
{
  "online_events": 142893,
  "retention_days": 30,
  "archive_path": "/app/data/archive",
  "archive_files": [
    { "name": "archive-2026-05-01-001.jsonl.gz", "size_mb": 12.4, "created": "2026-05-01T06:00:00" }
  ],
  "last_run": "2026-06-28T06:00:00",
  "last_archived": 5021
}
```

### Configuration page additions

Add a "Retention" section:
- Shows current retention window + online event count + archive file list
- "Run Now" button → `POST /retention/run` (triggers archive immediately, returns summary)
- Refresh on response

---

## Section 5 — Feature 4: Scheduled Reports

### Approach

- Reports are generated from existing API data (no new storage)
- `GET /reports/generate?period=daily|weekly` → JSON
- `GET /reports/download?period=daily|weekly` → HTML file (Content-Disposition: attachment)
- Background thread sends reports via email on schedule
- PDF is out of scope — HTML is sufficient for v0.7

### Environment variables (new)

```
TINYSIEM_REPORT_SCHEDULE    # disabled | daily | weekly (default disabled)
TINYSIEM_REPORT_EMAIL       # comma-separated recipients (uses SMTP config)
TINYSIEM_REPORT_HOUR        # hour to send (0-23, default 8)
```

### Module: `app/reports/generator.py`

```python
def generate_report(period: str) -> dict    # period: 'daily' | 'weekly'
def render_html(report: dict) -> str        # returns full HTML string
```

Report data structure:
```json
{
  "period": "daily",
  "generated_at": "2026-06-29T08:00:00",
  "window_start": "2026-06-28T08:00:00",
  "window_end": "2026-06-29T08:00:00",
  "summary": {
    "total_events": 14293,
    "total_alerts": 42,
    "alerts_by_severity": { "critical": 2, "high": 8, "medium": 32 },
    "alerts_by_status": { "open": 35, "investigating": 5, "resolved": 2 }
  },
  "top_source_ips": [{ "ip": "10.0.0.1", "count": 4821 }],
  "top_rules": [{ "rule": "nginx-http-404-spike", "count": 28 }],
  "recent_critical_alerts": [...]
}
```

Data sourced from:
- `duckdb_store.count_events_in_window()` or direct DuckDB queries for event totals
- `_read_all_alerts()` filtered to the report window
- `duckdb_store.get_event_facets()` for top source IPs

### API

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/reports/generate` | analyst+ | Return JSON report |
| `GET` | `/reports/download` | analyst+ | Return HTML file attachment |
| `POST` | `/reports/send` | admin+ | Trigger immediate email delivery |

---

## Section 6 — New File Map

```
app/
  notifications/
    __init__.py
    sender.py            # send_email, send_webhook, notify
  retention/
    __init__.py
    archiver.py          # archive_old_events, get_retention_status, background thread
  reports/
    __init__.py
    generator.py         # generate_report, render_html, background scheduler
  alerts/
    router.py            # MODIFIED: add PATCH, GET /{alert_id}, triage-summary
  storage/
    duckdb_store.py      # MODIFIED: add alert_triage table, triage CRUD functions
  config.py              # MODIFIED: add 10 new env vars, bump version to "0.7.0"
  main.py                # MODIFIED: start retention + report threads in lifespan

ui/
  alerts.html            # MODIFIED: triage panel, status badge on rows
  dashboard.html         # MODIFIED: triage status cards
  configuration.html     # MODIFIED: notifications + retention + reports sections

app/tests/
  test_alert_triage.py   # 12 tests
  test_notifications.py  # 8 tests
  test_retention.py      # 8 tests
  test_reports.py        # 6 tests
```

---

## Section 7 — Role Permissions (v0.7 additions)

| Endpoint | Required Role |
|---|---|
| `GET /alerts/{alert_id}` | analyst+ |
| `PATCH /alerts/{alert_id}` | analyst+ |
| `GET /alerts/triage-summary` | analyst+ |
| `POST /notifications/test` | admin+ |
| `GET /retention/status` | admin+ |
| `POST /retention/run` | admin+ |
| `GET /reports/generate` | analyst+ |
| `GET /reports/download` | analyst+ |
| `POST /reports/send` | admin+ |

---

## Section 8 — Security Constraints

- All new endpoints require JWT auth (no exceptions)
- Notification credentials (SMTP pass, webhook URL) never returned by API — only a `configured: true/false` flag
- Archive files written with `0o640` permissions (owner read/write, group read)
- Report HTML output is escaped — no raw alert data injected without `html.escape()`
- Webhook payloads are fixed-schema (no user-controlled field injection)
- Background threads are daemon threads — they die with the main process

---

## Section 9 — Version

Config bump: `"0.6.0"` → `"0.7.0"` in `app/config.py`

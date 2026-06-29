# v0.7 Operations Implementation Plan

**Goal:** Add alert triage, alert notifications, log retention with archiving, and scheduled reports to TinySIEM.

**Architecture:** Four self-contained feature modules (`app/notifications/`, `app/retention/`, `app/reports/`) wired into existing lifespan + routers. Alert triage uses a new DuckDB `alert_triage` table; all other storage reuses existing DuckDB + JSONL. No new PyPI dependencies — stdlib only (smtplib, urllib.request, gzip, threading).

**Tech Stack:** FastAPI (sync handlers), DuckDB, stdlib smtplib/urllib/gzip/threading, vanilla HTML/JS/CSS

**Design doc:** `docs/superpowers/specs/2026-06-29-v07-operations-design.md`

## Global Constraints

- Python 3.12; all route handlers are sync — no async/await
- No new PyPI packages — use stdlib only for new features
- All new endpoints require JWT auth
- Background threads are daemon threads (`thread.daemon = True`)
- SMTP/webhook credentials never returned by any API endpoint
- `html.escape()` on all alert data injected into report HTML
- All existing 65 tests must still pass after each task
- Version string: `"0.7.0"` in `app/config.py`
- No new HTML framework — vanilla JS + CSS, same CSS variables as existing pages
- Tests run inside Docker: `docker-compose exec -w /app tinysiem pytest tests/ -v`

---

## Task 1: Alert triage workflow

**Files modified:**
- `app/storage/duckdb_store.py` — add `init_alert_triage_table()`, `get_triage()`, `upsert_triage()`
- `app/alerts/router.py` — add `GET /alerts/triage-summary`, `GET /alerts/{alert_id}`, `PATCH /alerts/{alert_id}`; update `_read_all_alerts()` to merge triage
- `app/config.py` — bump version to `"0.7.0"`
- `app/main.py` — call `init_alert_triage_table()` in lifespan
- `app/tests/test_alert_triage.py` — new test file

**Interfaces produced:**
- `duckdb_store.init_alert_triage_table()` — called in lifespan
- `duckdb_store.get_triage_map() -> dict[str, dict]` — all triage rows keyed by alert_id
- `duckdb_store.upsert_triage(alert_id, status, notes, assigned_to, updated_by)` — INSERT OR REPLACE

- [ ] **Step 1: Add alert_triage table to duckdb_store**

In `app/storage/duckdb_store.py`, add after the existing `init_db()` function:

```python
def init_alert_triage_table() -> None:
    with _lock:
        _conn.execute("""
            CREATE TABLE IF NOT EXISTS alert_triage (
                alert_id    VARCHAR PRIMARY KEY,
                status      VARCHAR NOT NULL DEFAULT 'open',
                notes       TEXT    NOT NULL DEFAULT '',
                assigned_to VARCHAR NOT NULL DEFAULT '',
                updated_at  TIMESTAMP,
                updated_by  VARCHAR NOT NULL DEFAULT ''
            )
        """)

def get_triage_map() -> dict:
    with _lock:
        rows = _conn.execute(
            "SELECT alert_id, status, notes, assigned_to, updated_at, updated_by FROM alert_triage"
        ).fetchall()
    return {
        row[0]: {
            "status": row[1],
            "notes": row[2],
            "assigned_to": row[3],
            "updated_at": row[4].isoformat() if row[4] else None,
            "updated_by": row[5],
        }
        for row in rows
    }

def upsert_triage(alert_id: str, status: str, notes: str, assigned_to: str, updated_by: str) -> None:
    from datetime import datetime
    with _lock:
        _conn.execute("""
            INSERT INTO alert_triage (alert_id, status, notes, assigned_to, updated_at, updated_by)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (alert_id) DO UPDATE SET
                status = excluded.status,
                notes = excluded.notes,
                assigned_to = excluded.assigned_to,
                updated_at = excluded.updated_at,
                updated_by = excluded.updated_by
        """, [alert_id, status, notes, assigned_to, datetime.utcnow(), updated_by])
```

- [ ] **Step 2: Call init_alert_triage_table in lifespan**

In `app/main.py`, add inside lifespan after `duckdb_store.init_db()`:
```python
duckdb_store.init_alert_triage_table()
```

Also import the function at top.

- [ ] **Step 3: Update _read_all_alerts to merge triage state**

In `app/alerts/router.py`, update `_read_all_alerts()`:

```python
def _read_all_alerts() -> list[dict]:
    from app.storage.duckdb_store import get_triage_map
    path = Path(settings.tinysiem_alerts_path)
    if not path.exists():
        return []
    alerts = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    triage = get_triage_map()
    for a in alerts:
        aid = a.get("alert_id", "")
        t = triage.get(aid, {})
        a["status"] = t.get("status", "open")
        a["notes"] = t.get("notes", "")
        a["assigned_to"] = t.get("assigned_to", "")
        a["triage_updated_at"] = t.get("updated_at")
        a["triage_updated_by"] = t.get("updated_by", "")
    return alerts
```

- [ ] **Step 4: Add triage-summary, single-alert, and PATCH endpoints**

In `app/alerts/router.py`, add these routes (place triage-summary and generate BEFORE `/{alert_id}` to avoid shadowing):

```python
from pydantic import BaseModel
from typing import Optional
from app.auth import require_admin

_VALID_STATUSES = {"open", "investigating", "resolved"}

class TriagePatch(BaseModel):
    status: Optional[str] = None
    notes: Optional[str] = None
    assigned_to: Optional[str] = None

@router.get("/triage-summary")
def triage_summary(_: AuthUser = Depends(require_analyst)):
    from collections import Counter
    alerts = _read_all_alerts()
    counts = Counter(a.get("status", "open") for a in alerts)
    return {
        "open": counts.get("open", 0),
        "investigating": counts.get("investigating", 0),
        "resolved": counts.get("resolved", 0),
    }

@router.get("/{alert_id}")
def get_alert(alert_id: str, _: AuthUser = Depends(require_analyst)):
    from fastapi import HTTPException
    alerts = _read_all_alerts()
    for a in alerts:
        if a.get("alert_id") == alert_id:
            return a
    raise HTTPException(status_code=404, detail="Alert not found")

@router.patch("/{alert_id}")
def patch_alert(
    alert_id: str,
    body: TriagePatch,
    current_user: AuthUser = Depends(require_analyst),
):
    from fastapi import HTTPException
    from app.storage.duckdb_store import get_triage_map, upsert_triage
    # Validate status
    if body.status is not None and body.status not in _VALID_STATUSES:
        raise HTTPException(status_code=422, detail=f"status must be one of {sorted(_VALID_STATUSES)}")
    # Validate alert exists
    alerts = _read_all_alerts()
    existing = next((a for a in alerts if a.get("alert_id") == alert_id), None)
    if not existing:
        raise HTTPException(status_code=404, detail="Alert not found")
    # Merge patch onto existing triage state
    new_status = body.status if body.status is not None else existing.get("status", "open")
    new_notes = body.notes if body.notes is not None else existing.get("notes", "")
    new_assigned = body.assigned_to if body.assigned_to is not None else existing.get("assigned_to", "")
    upsert_triage(alert_id, new_status, new_notes, new_assigned, current_user.username)
    # Return updated alert
    existing["status"] = new_status
    existing["notes"] = new_notes
    existing["assigned_to"] = new_assigned
    return existing
```

- [ ] **Step 5: Update alerts.html with triage panel and status badges**

Add status badge column to the alert table rows. Add a detail/triage panel on the right side that opens on row click (similar to events.html expand). Panel shows: rule_name, severity, triggered_at, source_ip, summary, MITRE fields, then status dropdown (open/investigating/resolved), notes textarea, assigned_to text input, Save button.

Status badge color mapping:
- open: `#6b7280` (gray)
- investigating: `#f59e0b` (amber)
- resolved: `#22c55e` (green)

The Save button calls `PATCH /alerts/{alert_id}` with the current panel values.

- [ ] **Step 6: Update dashboard.html with triage status cards**

Add three stat cards (Open / Investigating / Resolved) that fetch from `GET /alerts/triage-summary`. Place them in a new "Alert Status" section below the severity cards.

- [ ] **Step 7: Write test_alert_triage.py**

Create `app/tests/test_alert_triage.py` with:
1. `test_get_alerts_includes_triage_fields` — GET /alerts includes status/notes/assigned_to fields with defaults
2. `test_triage_summary_returns_counts` — GET /alerts/triage-summary returns open/investigating/resolved
3. `test_get_single_alert` — GET /alerts/{alert_id} returns one alert
4. `test_get_single_alert_not_found` — 404 when alert_id doesn't exist
5. `test_patch_alert_status` — PATCH /alerts/{id} updates status
6. `test_patch_alert_invalid_status` — 422 on bad status value
7. `test_patch_alert_not_found` — 404 on unknown alert_id
8. `test_patch_alert_partial_update` — PATCH with only notes leaves status unchanged
9. `test_patch_alert_requires_auth` — 401 without token
10. `test_triage_summary_requires_auth` — 401 without token

Tests must pre-seed an alert in the alerts JSONL file to enable read/patch operations. Use a tmp file via a fixture.

- [ ] **Step 8: Rebuild Docker and run all tests**

```bash
docker-compose up --build -d
docker-compose exec -w /app tinysiem pytest tests/ -v
```

Expected: all existing 65 tests + 10 new triage tests = 75+ tests passing.

---

## Task 2: Alert notifications

**Files new:**
- `app/notifications/__init__.py`
- `app/notifications/sender.py`

**Files modified:**
- `app/alerts/file_writer.py` — call `notify(alert)` after write
- `app/config.py` — add SMTP/webhook env vars
- `app/alerts/router.py` — add `POST /notifications/test`
- `ui/configuration.html` — add Notifications section
- `app/tests/test_notifications.py` — new test file

- [ ] **Step 1: Add env vars to config.py**

```python
tinysiem_smtp_host: str = ""
tinysiem_smtp_port: int = 587
tinysiem_smtp_user: str = ""
tinysiem_smtp_pass: str = ""
tinysiem_smtp_from: str = ""
tinysiem_smtp_to: str = ""
tinysiem_smtp_tls: bool = True
tinysiem_webhook_url: str = ""
tinysiem_notify_min_sev: str = "high"
```

- [ ] **Step 2: Create app/notifications/sender.py**

```python
import json
import logging
import smtplib
import ssl
import urllib.request
from email.mime.text import MIMEText

from app.config import settings

logger = logging.getLogger(__name__)
_SEV_ORDER = ["low", "medium", "high", "critical"]

def should_notify(severity: str) -> bool:
    sev = (severity or "").lower()
    min_sev = (settings.tinysiem_notify_min_sev or "high").lower()
    try:
        return _SEV_ORDER.index(sev) >= _SEV_ORDER.index(min_sev)
    except ValueError:
        return False

def send_email(alert: dict) -> None:
    if not settings.tinysiem_smtp_host or not settings.tinysiem_smtp_to:
        return
    try:
        subject = f"[TinySIEM] {alert.get('severity','').upper()} alert: {alert.get('rule_name','')}"
        body = (
            f"Alert ID:    {alert.get('alert_id')}\n"
            f"Rule:        {alert.get('rule_name')}\n"
            f"Severity:    {alert.get('severity')}\n"
            f"Source IP:   {alert.get('source_ip')}\n"
            f"Triggered:   {alert.get('triggered_at')}\n"
            f"MITRE:       {alert.get('mitre_tactic')} / {alert.get('mitre_technique')}\n\n"
            f"Summary: {alert.get('summary')}\n"
        )
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = settings.tinysiem_smtp_from or settings.tinysiem_smtp_user
        msg["To"] = settings.tinysiem_smtp_to
        recipients = [r.strip() for r in settings.tinysiem_smtp_to.split(",") if r.strip()]
        if settings.tinysiem_smtp_tls:
            ctx = ssl.create_default_context()
            with smtplib.SMTP(settings.tinysiem_smtp_host, settings.tinysiem_smtp_port) as s:
                s.starttls(context=ctx)
                if settings.tinysiem_smtp_user:
                    s.login(settings.tinysiem_smtp_user, settings.tinysiem_smtp_pass)
                s.sendmail(msg["From"], recipients, msg.as_string())
        else:
            with smtplib.SMTP(settings.tinysiem_smtp_host, settings.tinysiem_smtp_port) as s:
                if settings.tinysiem_smtp_user:
                    s.login(settings.tinysiem_smtp_user, settings.tinysiem_smtp_pass)
                s.sendmail(msg["From"], recipients, msg.as_string())
    except Exception as exc:
        logger.error(f"Notification email failed: {exc}")

def send_webhook(alert: dict) -> None:
    if not settings.tinysiem_webhook_url:
        return
    try:
        payload = json.dumps({k: alert.get(k) for k in [
            "alert_id", "rule_name", "severity", "triggered_at",
            "source_ip", "summary", "mitre_tactic", "mitre_technique"
        ]}).encode()
        req = urllib.request.Request(
            settings.tinysiem_webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            logger.info(f"Webhook delivered: {resp.status}")
    except Exception as exc:
        logger.error(f"Notification webhook failed: {exc}")

def notify(alert: dict) -> None:
    if not should_notify(alert.get("severity", "")):
        return
    send_email(alert)
    send_webhook(alert)
```

- [ ] **Step 3: Hook notify into file_writer**

In `app/alerts/file_writer.py`, after the `fh.write(...)` line and before `fh.flush()`:

```python
from app.notifications.sender import notify
notify(alert)
```

Keep it inside the `try` block but before flush/fsync — notifications are best-effort.

- [ ] **Step 4: Add POST /notifications/test endpoint**

Add to `app/alerts/router.py` (or create a new `app/notifications/router.py` mounted at `/notifications`). Use a separate router for clarity:

New file `app/notifications/router.py`:
```python
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional
from app.auth import AuthUser, require_admin
from app.notifications.sender import send_email, send_webhook

router = APIRouter(prefix="/notifications", tags=["notifications"])

class TestBody(BaseModel):
    channel: str = "all"  # email | webhook | all

@router.post("/test")
def test_notification(body: TestBody, _: AuthUser = Depends(require_admin)):
    alert = {
        "alert_id": str(uuid.uuid4()),
        "rule_name": "test-notification",
        "severity": "high",
        "triggered_at": datetime.now(timezone.utc).isoformat(),
        "source_ip": "1.2.3.4",
        "summary": "This is a TinySIEM notification test.",
        "mitre_tactic": "Test",
        "mitre_technique": "T0000",
    }
    result = {}
    if body.channel in ("email", "all"):
        try:
            send_email(alert)
            result["email"] = "sent"
        except Exception as e:
            result["email"] = f"error: {e}"
    if body.channel in ("webhook", "all"):
        try:
            send_webhook(alert)
            result["webhook"] = "sent"
        except Exception as e:
            result["webhook"] = f"error: {e}"
    return result

@router.get("/config")
def get_notification_config(_: AuthUser = Depends(require_admin)):
    from app.config import settings
    return {
        "email_enabled": bool(settings.tinysiem_smtp_host and settings.tinysiem_smtp_to),
        "webhook_enabled": bool(settings.tinysiem_webhook_url),
        "min_severity": settings.tinysiem_notify_min_sev,
        "smtp_host": settings.tinysiem_smtp_host,
        "smtp_port": settings.tinysiem_smtp_port,
        "smtp_from": settings.tinysiem_smtp_from,
        "smtp_to": settings.tinysiem_smtp_to,
        "smtp_tls": settings.tinysiem_smtp_tls,
    }
```

Wire in `app/main.py`:
```python
from app.notifications.router import router as notifications_router
app.include_router(notifications_router)
```

- [ ] **Step 5: Add Notifications section to configuration.html**

Add a "Notifications" card section showing:
- Email: enabled/disabled badge + smtp_host/smtp_to details
- Webhook: enabled/disabled badge + URL (masked after first 20 chars)
- Min severity: current value
- "Test Email" button → POST /notifications/test {channel: "email"}
- "Test Webhook" button → POST /notifications/test {channel: "webhook"}
- Test result appears below buttons

- [ ] **Step 6: Write test_notifications.py**

Tests:
1. `test_should_notify_high_severity` — should_notify("high") when min=high → True
2. `test_should_notify_low_excluded` — should_notify("low") when min=high → False
3. `test_send_email_skipped_when_no_host` — send_email() with empty smtp_host does not raise
4. `test_send_webhook_skipped_when_no_url` — send_webhook() with empty webhook_url does not raise
5. `test_notify_calls_nothing_below_min_sev` — notify() with low severity, min=high → no network calls
6. `test_notifications_test_endpoint_requires_admin` — 403 for analyst
7. `test_notifications_test_endpoint_skipped` — POST /notifications/test returns result when not configured
8. `test_notifications_config_endpoint` — GET /notifications/config returns expected structure

---

## Task 3: Log retention

**Files new:**
- `app/retention/__init__.py`
- `app/retention/archiver.py`
- `app/retention/router.py`

**Files modified:**
- `app/config.py` — add retention env vars
- `app/main.py` — start retention thread in lifespan; include retention router
- `app/Dockerfile` — mkdir /app/data/archive
- `ui/configuration.html` — add Retention section
- `app/tests/test_retention.py` — new test file

- [ ] **Step 1: Add retention env vars to config.py**

```python
tinysiem_retention_days: int = 30
tinysiem_archive_path: str = "/app/data/archive"
tinysiem_archive_chunk_mb: int = 500
```

- [ ] **Step 2: Create app/retention/archiver.py**

```python
import gzip
import json
import logging
import os
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from app.config import settings
from app.storage import duckdb_store

logger = logging.getLogger(__name__)
_last_run: dict = {"time": None, "archived": 0}


def archive_old_events() -> dict:
    cutoff = datetime.utcnow() - timedelta(days=settings.tinysiem_retention_days)
    archive_dir = Path(settings.tinysiem_archive_path)
    archive_dir.mkdir(parents=True, exist_ok=True)
    chunk_bytes = settings.tinysiem_archive_chunk_mb * 1024 * 1024
    total_archived = 0
    files_written = []
    batch_size = 5000

    while True:
        rows = duckdb_store.query_events_for_archive(cutoff, limit=batch_size)
        if not rows:
            break

        seq = len(list(archive_dir.glob("*.jsonl.gz"))) + 1
        date_str = cutoff.strftime("%Y-%m-%d")
        out_path = archive_dir / f"archive-{date_str}-{seq:03d}.jsonl.gz"

        ids_to_delete = []
        byte_count = 0
        with gzip.open(out_path, "wt", encoding="utf-8") as gz:
            for row in rows:
                line = json.dumps(row) + "\n"
                gz.write(line)
                byte_count += len(line.encode())
                ids_to_delete.append(row["id"])
                if byte_count >= chunk_bytes:
                    break

        duckdb_store.delete_events_by_ids(ids_to_delete)
        total_archived += len(ids_to_delete)
        files_written.append(str(out_path.name))
        logger.info(f"Archived {len(ids_to_delete)} events to {out_path.name}")

        if len(ids_to_delete) < batch_size:
            break

    _last_run["time"] = datetime.utcnow().isoformat()
    _last_run["archived"] = total_archived
    return {"archived": total_archived, "files": files_written}


def get_retention_status() -> dict:
    archive_dir = Path(settings.tinysiem_archive_path)
    files = []
    if archive_dir.exists():
        for f in sorted(archive_dir.glob("*.jsonl.gz")):
            stat = f.stat()
            files.append({
                "name": f.name,
                "size_mb": round(stat.st_size / (1024 * 1024), 2),
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            })
    return {
        "online_events": duckdb_store.count_all_events(),
        "retention_days": settings.tinysiem_retention_days,
        "archive_path": str(archive_dir),
        "archive_files": files,
        "last_run": _last_run.get("time"),
        "last_archived": _last_run.get("archived", 0),
    }


def _retention_loop() -> None:
    while True:
        time.sleep(6 * 3600)  # run every 6 hours
        try:
            archive_old_events()
        except Exception as exc:
            logger.error(f"Retention archiver error: {exc}")


def start_retention_thread() -> None:
    t = threading.Thread(target=_retention_loop, daemon=True, name="retention-archiver")
    t.start()
    logger.info("Retention archiver thread started")
```

- [ ] **Step 3: Add DuckDB helpers for archiver**

In `app/storage/duckdb_store.py`, add:

```python
def query_events_for_archive(cutoff: datetime, limit: int = 5000) -> list[dict]:
    with _lock:
        rows = _conn.execute(
            "SELECT id, source, ingested_at, event_time, source_ip, method, uri, "
            "status_code, response_size, user_agent, referer, raw, extra "
            "FROM events WHERE ingested_at < ? ORDER BY ingested_at LIMIT ?",
            [cutoff, limit]
        ).fetchall()
    cols = ["id", "source", "ingested_at", "event_time", "source_ip", "method",
            "uri", "status_code", "response_size", "user_agent", "referer", "raw", "extra"]
    return [dict(zip(cols, row)) for row in rows]

def delete_events_by_ids(ids: list[str]) -> int:
    if not ids:
        return 0
    placeholders = ",".join("?" * len(ids))
    with _lock:
        _conn.execute(f"DELETE FROM events WHERE id IN ({placeholders})", ids)
    return len(ids)

def count_all_events() -> int:
    with _lock:
        return _conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
```

- [ ] **Step 4: Create app/retention/router.py**

```python
from fastapi import APIRouter, Depends
from app.auth import AuthUser, require_admin
from app.retention.archiver import archive_old_events, get_retention_status

router = APIRouter(prefix="/retention", tags=["retention"])

@router.get("/status")
def retention_status(_: AuthUser = Depends(require_admin)):
    return get_retention_status()

@router.post("/run")
def run_retention(_: AuthUser = Depends(require_admin)):
    result = archive_old_events()
    return result
```

- [ ] **Step 5: Wire into main.py and Dockerfile**

In `main.py` lifespan:
```python
from app.retention.archiver import start_retention_thread
from app.retention.router import router as retention_router
# in lifespan:
start_retention_thread()
# after include_router calls:
app.include_router(retention_router)
```

In `app/Dockerfile`, add `mkdir -p /app/data/archive` to the data dir creation line.

- [ ] **Step 6: Add Retention section to configuration.html**

Add card showing:
- Retention window: N days
- Online events: count
- Last archive run: timestamp + events archived
- Archive files: table (name, size_mb, created)
- "Archive Now" button → POST /retention/run → refresh section

- [ ] **Step 7: Write test_retention.py**

Tests (use tmp dir fixture for archive_path):
1. `test_retention_status_returns_structure` — GET /retention/status returns expected keys
2. `test_retention_status_requires_admin` — 403 for analyst
3. `test_run_retention_no_old_events` — POST /retention/run with no old events returns archived=0
4. `test_run_retention_archives_old_events` — seed old events, run, check archived count
5. `test_archived_events_deleted_from_duckdb` — after archive run, events no longer in DB
6. `test_archive_file_created` — gzip file exists after run
7. `test_run_retention_requires_admin` — 403 for analyst
8. `test_count_all_events` — count_all_events() matches inserted count

---

## Task 4: Scheduled reports

**Files new:**
- `app/reports/__init__.py`
- `app/reports/generator.py`
- `app/reports/router.py`

**Files modified:**
- `app/config.py` — add report env vars
- `app/main.py` — start report scheduler; include reports router
- `ui/configuration.html` — add Reports section
- `app/tests/test_reports.py` — new test file

- [ ] **Step 1: Add report env vars to config.py**

```python
tinysiem_report_schedule: str = "disabled"   # disabled | daily | weekly
tinysiem_report_email: str = ""              # comma-separated recipients
tinysiem_report_hour: int = 8               # hour to send (0-23)
```

- [ ] **Step 2: Create app/reports/generator.py**

```python
import html
import json
import logging
from datetime import datetime, timedelta
from app.alerts.router import _read_all_alerts
from app.storage import duckdb_store

logger = logging.getLogger(__name__)


def generate_report(period: str = "daily") -> dict:
    now = datetime.utcnow()
    if period == "weekly":
        window_start = now - timedelta(days=7)
    else:
        window_start = now - timedelta(days=1)

    alerts = _read_all_alerts()
    window_alerts = [a for a in alerts if _parse_dt(a.get("triggered_at")) >= window_start]

    sev_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    rule_counts: dict[str, int] = {}
    for a in window_alerts:
        s = (a.get("severity") or "unknown").lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1
        st = a.get("status", "open")
        status_counts[st] = status_counts.get(st, 0) + 1
        rn = a.get("rule_name") or "unknown"
        rule_counts[rn] = rule_counts.get(rn, 0) + 1

    top_rules = sorted(rule_counts.items(), key=lambda x: -x[1])[:10]

    # Top source IPs from events
    facets = duckdb_store.get_event_facets(start=window_start)
    top_ips = facets.get("source_ip", [])[:10]

    # Event count
    total_events = duckdb_store.count_events_in_window_range(window_start, now)

    recent_critical = sorted(
        [a for a in window_alerts if (a.get("severity") or "").lower() in ("critical", "high")],
        key=lambda a: a.get("triggered_at", ""),
        reverse=True,
    )[:5]

    return {
        "period": period,
        "generated_at": now.isoformat(),
        "window_start": window_start.isoformat(),
        "window_end": now.isoformat(),
        "summary": {
            "total_events": total_events,
            "total_alerts": len(window_alerts),
            "alerts_by_severity": sev_counts,
            "alerts_by_status": status_counts,
        },
        "top_source_ips": [{"ip": v["value"], "count": v["count"]} for v in top_ips],
        "top_rules": [{"rule": r, "count": c} for r, c in top_rules],
        "recent_high_critical_alerts": recent_critical,
    }


def _parse_dt(ts):
    if not ts:
        return datetime.min
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
    except (ValueError, AttributeError):
        return datetime.min


def render_html(report: dict) -> str:
    esc = html.escape
    period_label = "Daily" if report["period"] == "daily" else "Weekly"
    s = report["summary"]
    rows_ips = "".join(
        f"<tr><td>{esc(str(x['ip']))}</td><td>{esc(str(x['count']))}</td></tr>"
        for x in report["top_source_ips"]
    )
    rows_rules = "".join(
        f"<tr><td>{esc(str(x['rule']))}</td><td>{esc(str(x['count']))}</td></tr>"
        for x in report["top_rules"]
    )
    rows_alerts = "".join(
        f"<tr><td>{esc(str(a.get('triggered_at','')))}</td>"
        f"<td>{esc(str(a.get('severity','')))}</td>"
        f"<td>{esc(str(a.get('rule_name','')))}</td>"
        f"<td>{esc(str(a.get('source_ip','')))}</td></tr>"
        for a in report["recent_high_critical_alerts"]
    )
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>TinySIEM {esc(period_label)} Report</title>
<style>
  body {{ font-family: sans-serif; max-width: 900px; margin: 40px auto; color: #1f2937; }}
  h1 {{ color: #111827; }} h2 {{ color: #374151; border-bottom: 1px solid #e5e7eb; padding-bottom: 4px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 12px 0; }}
  th, td {{ border: 1px solid #e5e7eb; padding: 8px 12px; text-align: left; }}
  th {{ background: #f9fafb; font-weight: 600; }}
  .stat {{ display: inline-block; background: #f3f4f6; border-radius: 8px;
           padding: 12px 24px; margin: 8px; text-align: center; }}
  .stat-num {{ font-size: 28px; font-weight: 700; }}
  .stat-lbl {{ font-size: 13px; color: #6b7280; }}
</style></head>
<body>
<h1>TinySIEM {esc(period_label)} Report</h1>
<p>Generated: {esc(report['generated_at'])} UTC &nbsp;|&nbsp;
   Window: {esc(report['window_start'])} → {esc(report['window_end'])}</p>
<h2>Summary</h2>
<div>
  <div class="stat"><div class="stat-num">{esc(str(s['total_events']))}</div><div class="stat-lbl">Events</div></div>
  <div class="stat"><div class="stat-num">{esc(str(s['total_alerts']))}</div><div class="stat-lbl">Alerts</div></div>
  <div class="stat"><div class="stat-num">{esc(str(s['alerts_by_severity'].get('critical', 0)))}</div><div class="stat-lbl">Critical</div></div>
  <div class="stat"><div class="stat-num">{esc(str(s['alerts_by_severity'].get('high', 0)))}</div><div class="stat-lbl">High</div></div>
  <div class="stat"><div class="stat-num">{esc(str(s['alerts_by_status'].get('open', 0)))}</div><div class="stat-lbl">Open</div></div>
  <div class="stat"><div class="stat-num">{esc(str(s['alerts_by_status'].get('resolved', 0)))}</div><div class="stat-lbl">Resolved</div></div>
</div>
<h2>Top Source IPs</h2>
<table><tr><th>IP</th><th>Event Count</th></tr>{rows_ips or '<tr><td colspan="2">No data</td></tr>'}</table>
<h2>Top Rules Triggered</h2>
<table><tr><th>Rule</th><th>Alert Count</th></tr>{rows_rules or '<tr><td colspan="2">No data</td></tr>'}</table>
<h2>Recent High / Critical Alerts</h2>
<table><tr><th>Triggered At</th><th>Severity</th><th>Rule</th><th>Source IP</th></tr>
{rows_alerts or '<tr><td colspan="4">No high/critical alerts in this window</td></tr>'}</table>
</body></html>"""


def _send_report_email(period: str) -> None:
    from app.config import settings
    if not settings.tinysiem_report_email or not settings.tinysiem_smtp_host:
        return
    try:
        report = generate_report(period)
        body = render_html(report)
        import smtplib, ssl
        from email.mime.text import MIMEText
        subject = f"[TinySIEM] {period.capitalize()} Report — {report['generated_at'][:10]}"
        msg = MIMEText(body, "html")
        msg["Subject"] = subject
        msg["From"] = settings.tinysiem_smtp_from or settings.tinysiem_smtp_user
        msg["To"] = settings.tinysiem_report_email
        recipients = [r.strip() for r in settings.tinysiem_report_email.split(",") if r.strip()]
        if settings.tinysiem_smtp_tls:
            ctx = ssl.create_default_context()
            with smtplib.SMTP(settings.tinysiem_smtp_host, settings.tinysiem_smtp_port) as s:
                s.starttls(context=ctx)
                if settings.tinysiem_smtp_user:
                    s.login(settings.tinysiem_smtp_user, settings.tinysiem_smtp_pass)
                s.sendmail(msg["From"], recipients, msg.as_string())
        else:
            with smtplib.SMTP(settings.tinysiem_smtp_host, settings.tinysiem_smtp_port) as s:
                if settings.tinysiem_smtp_user:
                    s.login(settings.tinysiem_smtp_user, settings.tinysiem_smtp_pass)
                s.sendmail(msg["From"], recipients, msg.as_string())
    except Exception as exc:
        logger.error(f"Report email failed: {exc}")


def start_report_scheduler() -> None:
    import time, threading
    from app.config import settings
    schedule = settings.tinysiem_report_schedule
    if schedule == "disabled":
        return
    period = "weekly" if schedule == "weekly" else "daily"
    interval = 7 * 24 * 3600 if period == "weekly" else 24 * 3600

    def _loop():
        # First run at the configured hour
        import time as _time
        now = datetime.utcnow()
        target_hour = settings.tinysiem_report_hour
        seconds_until = (target_hour - now.hour) * 3600 - now.minute * 60 - now.second
        if seconds_until < 0:
            seconds_until += 24 * 3600
        _time.sleep(seconds_until)
        while True:
            _send_report_email(period)
            _time.sleep(interval)

    t = threading.Thread(target=_loop, daemon=True, name="report-scheduler")
    t.start()
    logger.info(f"Report scheduler started: {schedule} at hour {settings.tinysiem_report_hour}")
```

- [ ] **Step 3: Add count_events_in_window_range to duckdb_store**

```python
def count_events_in_window_range(start: datetime, end: datetime) -> int:
    s = start.replace(tzinfo=None) if start.tzinfo else start
    e = end.replace(tzinfo=None) if end.tzinfo else end
    with _lock:
        return _conn.execute(
            "SELECT COUNT(*) FROM events WHERE ingested_at >= ? AND ingested_at <= ?",
            [s, e]
        ).fetchone()[0]
```

- [ ] **Step 4: Create app/reports/router.py**

```python
from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse
from app.auth import AuthUser, require_analyst, require_admin
from app.reports.generator import generate_report, render_html, _send_report_email

router = APIRouter(prefix="/reports", tags=["reports"])

@router.get("/generate")
def report_generate(
    period: str = Query("daily", pattern="^(daily|weekly)$"),
    _: AuthUser = Depends(require_analyst),
):
    return generate_report(period)

@router.get("/download")
def report_download(
    period: str = Query("daily", pattern="^(daily|weekly)$"),
    _: AuthUser = Depends(require_analyst),
):
    report = generate_report(period)
    html_content = render_html(report)
    filename = f"tinysiem-{period}-report-{report['generated_at'][:10]}.html"
    return HTMLResponse(
        content=html_content,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

@router.post("/send")
def report_send(
    period: str = Query("daily", pattern="^(daily|weekly)$"),
    _: AuthUser = Depends(require_admin),
):
    _send_report_email(period)
    return {"status": "sent"}
```

- [ ] **Step 5: Wire into main.py**

```python
from app.reports.router import router as reports_router
from app.reports.generator import start_report_scheduler
# in lifespan:
start_report_scheduler()
# after include_router calls:
app.include_router(reports_router)
```

- [ ] **Step 6: Add Reports section to configuration.html**

Add card showing:
- Schedule: current value (disabled/daily/weekly)
- Report email: configured address
- Report hour: N UTC
- "Download Daily Report" button → GET /reports/download?period=daily
- "Download Weekly Report" button → GET /reports/download?period=weekly
- "Send Report Now (Email)" button → POST /reports/send (admin only)

- [ ] **Step 7: Write test_reports.py**

Tests:
1. `test_generate_report_returns_structure` — GET /reports/generate returns expected keys
2. `test_generate_report_daily` — period=daily returns 24h window
3. `test_generate_report_weekly` — period=weekly returns 7d window
4. `test_generate_report_requires_auth` — 401 without token
5. `test_download_report` — GET /reports/download returns HTML content-type + attachment header
6. `test_send_report_requires_admin` — 403 for analyst on POST /reports/send

- [ ] **Step 8: Final rebuild and full test run**

```bash
docker-compose up --build -d
docker-compose exec -w /app tinysiem pytest tests/ -v
```

Expected: 65 existing + 10 triage + 8 notification + 8 retention + 6 report = 97 tests.

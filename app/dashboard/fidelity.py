"""In-process telemetry + DB-backed snapshot for the Detection Fidelity view.

Hot-path counters (``record_event``/``record_alert``) are O(1) appends to
per-source deques, guarded by a single lock — zero I/O so the ingest path
stays fast.

The snapshot() function returns a consistent shape for any of three windows
(60s / 1h / 24h):

  - window == 60  → in-memory rolling deques (live pulse, no DB hit)
  - window > 60   → DB-backed ``COUNT(*)`` over events (in-memory would
                    undercount because deques only hold the last ~window
                    entries; in-memory is per-process and lost on restart)

Alert counting is DB/file based for ALL windows: we scan the alerts JSONL
file once per snapshot and filter by ``triggered_at`` within the window.
File reads are wrapped in try/except so they never crash the endpoint.

Parse-failure counters are in-memory only — they reflect only the recent
process lifetime and are surfaced via the live 60s pulse.

This module deliberately does NOT query the database on the ingest path —
counting events here keeps the existing chokepoints (``insert_event`` and
``write_alert``) free of extra DB round-trips, which would matter at high
throughput.
"""
import json
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from app.config import settings

_lock = threading.Lock()
_event_ts: dict[str, deque] = {}
_alert_ts: deque = deque()
_parse_fail: dict[str, int] = {}

_ALLOWED_WINDOWS = (60, 3600, 86400)
_WINDOW_LABELS = {60: "1m", 3600: "1h", 86400: "24h"}


def _now() -> float:
    return time.monotonic()


def record_event(source: Optional[str]) -> None:
    """Called once per ingested event. O(1)."""
    if not source:
        source = ""
    ts = _now()
    with _lock:
        dq = _event_ts.get(source)
        if dq is None:
            dq = deque()
            _event_ts[source] = dq
        dq.append(ts)


def record_alert() -> None:
    """Called once per written alert. O(1)."""
    with _lock:
        _alert_ts.append(_now())


def record_parse_failure(source: Optional[str]) -> None:
    """Optional counter — only incremented where ingest detects a rejection.

    The hook in ``ingest/pipeline.py`` calls this when ``process_line`` returns
    ``None`` (no decoder match / parse fail). Kept here so the dashboard can
    surface a red status dot when a source is silently failing to parse.
    """
    if not source:
        source = ""
    with _lock:
        _parse_fail[source] = _parse_fail.get(source, 0) + 1


def _prune(dq: deque, cutoff: float) -> None:
    while dq and dq[0] < cutoff:
        dq.popleft()


def _events_in_memory(window_seconds: int) -> dict[str, int]:
    """{source: count} from the in-memory rolling deques (live 60s pulse)."""
    cutoff = _now() - window_seconds
    out: dict[str, int] = {}
    with _lock:
        for src, dq in _event_ts.items():
            _prune(dq, cutoff)
            out[src] = len(dq)
    return out


def _events_in_db(window_seconds: int) -> dict[str, int]:
    """{source: count} from the events table for the last ``window_seconds``.

    Uses ``epoch()`` on both sides so the comparison is timezone-safe
    (DuckDB ``current_timestamp`` is server-local; ``ingested_at`` is
    stored as naive UTC — comparing raw would yield an 8h drift).
    """
    from app.storage import duckdb_store
    conn = duckdb_store._get_conn()
    with duckdb_store._lock:
        rows = conn.execute(
            "SELECT source, COUNT(*) FROM events "
            "WHERE epoch(ingested_at) >= epoch(current_timestamp) - ? "
            "GROUP BY source",
            [window_seconds],
        ).fetchall()
    return {(r[0] or "(unknown)"): r[1] for r in rows}


def _alert_stats(window_seconds: int) -> dict:
    """Scan the alerts JSONL file ONCE and return window-scoped stats.

    Returns ``{"count", "by_rule", "recent"}``:
      - ``count``   — number of alerts whose ``triggered_at`` is in the window
      - ``by_rule`` — ``{rule_name: count}`` for alerts in the window
      - ``recent``  — the last ≤10 in-window alerts, newest first (the file is
                      append-only chronological, so keep the tail and reverse)

    Any read/parse error returns the empty shape so this can never crash the
    endpoint.
    """
    empty = {"count": 0, "by_rule": {}, "recent": []}
    try:
        path = Path(settings.tinysiem_alerts_path)
        if not path.exists():
            return empty
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=window_seconds)
        count = 0
        by_rule: dict[str, int] = {}
        recent: list[dict] = []
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ts = rec.get("triggered_at")
                if not ts:
                    continue
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except ValueError:
                    continue
                if dt < cutoff:
                    continue
                count += 1
                rule = rec.get("rule_name") or "(unknown)"
                by_rule[rule] = by_rule.get(rule, 0) + 1
                recent.append({
                    "alert_id": rec.get("alert_id"),
                    "rule_name": rule,
                    "severity": rec.get("severity"),
                    "triggered_at": rec.get("triggered_at"),
                    "source_ip": rec.get("source_ip"),
                    "summary": rec.get("summary"),
                })
                if len(recent) > 10:
                    recent.pop(0)
        recent.reverse()
        return {"count": count, "by_rule": by_rule, "recent": recent}
    except Exception:
        return empty


def _events_rate_for_window(events: int, window_seconds: int) -> tuple[float, str]:
    """Normalize an event count + window into a (rate, unit) pair."""
    if window_seconds == 60:
        return round(events / 60.0, 2), "eps"
    if window_seconds == 3600:
        return round(float(events), 2), "events/hr"
    if window_seconds == 86400:
        return round(float(events), 2), "events/day"
    return 0.0, "eps"


def _alerts_rate_for_window(alerts: int, window_seconds: int) -> tuple[float, str]:
    """Normalize an alert count + window into a (rate, unit) pair."""
    if window_seconds == 60:
        return round(float(alerts), 2), "alerts/min"
    if window_seconds == 3600:
        return round(float(alerts), 2), "alerts/hr"
    if window_seconds == 86400:
        return round(float(alerts), 2), "alerts/day"
    return 0.0, "alerts/min"


def snapshot(window_seconds: int = 60) -> dict:
    """Return the fidelity snapshot for ``window_seconds``.

    The router validates the window is one of ``(60, 3600, 86400)``.
    Returns a dict with the keys documented in the Detection Fidelity spec.
    """
    if window_seconds == 60:
        counts = _events_in_memory(window_seconds)
    else:
        counts = _events_in_db(window_seconds)

    # parse-fail counts: in-memory only. For DB-backed windows we still report
    # the live pulse values (failures are rare and the 60s window shows them).
    with _lock:
        parse_fails = dict(_parse_fail)

    sources: list[dict] = []
    total_events = 0
    for src, count in counts.items():
        total_events += count
        name = src or "(unknown)"
        rate, _unit = _events_rate_for_window(count, window_seconds)
        sources.append({
            "name": name,
            "events": count,
            "rate": rate,
            "parse_fail_count": parse_fails.get(src, 0),
        })
    sources.sort(key=lambda s: s["name"])

    alert_stats = _alert_stats(window_seconds)
    alerts_in_window = alert_stats["count"]
    events_rate, events_unit = _events_rate_for_window(total_events, window_seconds)
    alerts_rate, alerts_unit = _alerts_rate_for_window(alerts_in_window, window_seconds)

    top_rules = [
        {"rule_name": name, "count": cnt}
        for name, cnt in sorted(
            alert_stats["by_rule"].items(), key=lambda kv: (-kv[1], kv[0])
        )[:5]
    ]

    return {
        "window_seconds": window_seconds,
        "window_label": _WINDOW_LABELS.get(window_seconds, f"{window_seconds}s"),
        "totals": {
            "events": total_events,
            "events_rate": events_rate,
            "events_rate_unit": events_unit,
            "alerts": alerts_in_window,
            "alerts_rate": alerts_rate,
            "alerts_rate_unit": alerts_unit,
        },
        "sources": sources,
        "top_rules": top_rules,
        "recent_alerts": alert_stats["recent"],
    }


def reset() -> None:
    """Clear all in-memory state. Intended for tests only."""
    with _lock:
        _event_ts.clear()
        _alert_ts.clear()
        _parse_fail.clear()

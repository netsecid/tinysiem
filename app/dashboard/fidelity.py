"""In-process telemetry for the Detection Fidelity view.

Zero-I/O on the hot path: ``record_event``/``record_alert`` are O(1) appends to
per-source deques, guarded by a single lock. ``snapshot()`` prunes entries older
than ``window_seconds`` and returns EPS per source, total EPS, and alerts/min.

This module deliberately does NOT query the database on the ingest path —
counting events here keeps the existing chokepoints (``insert_event`` and
``write_alert``) free of extra DB round-trips, which would matter at high
throughput.
"""
import threading
import time
from collections import deque
from typing import Optional

_lock = threading.Lock()
_event_ts: dict[str, deque] = {}
_alert_ts: deque = deque()
_parse_fail: dict[str, int] = {}

_DEFAULT_WINDOW = 60


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


def snapshot(window_seconds: int = _DEFAULT_WINDOW) -> dict:
    """Return a per-source EPS / total EPS / alerts-per-minute view.

    No DB queries — purely in-memory arithmetic over the rolling windows.
    """
    cutoff = _now() - window_seconds
    sources = []
    total_events = 0
    with _lock:
        all_sources = set(_event_ts.keys()) | set(_parse_fail.keys())
        for src in all_sources:
            dq = _event_ts.get(src)
            if dq is not None:
                _prune(dq, cutoff)
                count = len(dq)
            else:
                count = 0
            total_events += count
            eps = count / window_seconds if window_seconds > 0 else 0.0
            sources.append({
                "name": src or "(unknown)",
                "eps": round(eps, 2),
                "event_count_window": count,
                "parse_fail_count": _parse_fail.get(src, 0),
            })
        _prune(_alert_ts, cutoff)
        alerts_in_window = len(_alert_ts)
    alerts_per_min = alerts_in_window * 60.0 / window_seconds if window_seconds > 0 else 0.0
    sources.sort(key=lambda s: s["name"])
    return {
        "window_seconds": window_seconds,
        "total_eps": round(total_events / window_seconds, 2) if window_seconds > 0 else 0.0,
        "total_events_window": total_events,
        "alerts_per_min": round(alerts_per_min, 2),
        "alerts_in_window": alerts_in_window,
        "sources": sources,
    }


def reset() -> None:
    """Clear all in-memory state. Intended for tests only."""
    with _lock:
        _event_ts.clear()
        _alert_ts.clear()
        _parse_fail.clear()

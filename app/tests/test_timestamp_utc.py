"""Regression: every API timestamp carries an explicit UTC marker ("Z").

Without the marker, browsers parse naive ISO strings as *local* time — e.g.
02:11 UTC rendered as 02:11 WIB for an analyst in Jakarta, 8 hours off.
The source of truth stays UTC; the UI converts to browser-local time on
render (see fmtT/fmtTime in the UI files).
"""

import uuid
from datetime import datetime, timedelta, timezone

from app.storage import duckdb_store


def _insert_event(source_ip: str = "192.0.2.1") -> str:
    event_id = str(uuid.uuid4())
    duckdb_store.insert_event({
        "id": event_id,
        "source": "test_ts",
        "ingested_at": datetime.now(timezone.utc),
        "event_time": datetime(2026, 8, 10, 2, 11, 49, 123000, tzinfo=timezone.utc),
        "source_ip": source_ip, "method": "GET", "uri": "/", "status_code": 200,
        "response_size": 100, "user_agent": "t", "referer": None,
        "raw": "ts-test", "extra": {},
    })
    return event_id


def test_events_query_timestamps_have_utc_marker():
    event_id = _insert_event()
    result = duckdb_store.query_events(source="test_ts", limit=10)
    ev = next(e for e in result["events"] if e["id"] == event_id)
    assert ev["ingested_at"].endswith("Z")
    assert ev["event_time"] == "2026-08-10T02:11:49.123000Z"


def test_event_full_timestamps_have_utc_marker():
    event_id = _insert_event()
    ev = duckdb_store.get_event_full(event_id)
    assert ev["ingested_at"].endswith("Z")
    assert ev["event_time"].endswith("Z")


def test_ip_summary_timestamps_have_utc_marker():
    ip = f"192.0.2.{uuid.uuid4().int % 200 + 1}"
    _insert_event(ip)
    summary = duckdb_store.get_ip_summary(
        ip, datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2027, 1, 1, tzinfo=timezone.utc),
    )
    assert summary["first_seen"].endswith("Z")
    assert summary["last_seen"].endswith("Z")


def test_time_range_filter_is_timezone_agnostic():
    """A tz-aware UTC window must match events inserted at the same instant —
    the naive-UTC storage comparison must not drift with server/browser tz."""
    event_id = _insert_event()
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=5)
    end = now + timedelta(minutes=5)
    result = duckdb_store.query_events(source="test_ts", start=start, end=end, limit=10)
    ids = {e["id"] for e in result["events"]}
    assert event_id in ids

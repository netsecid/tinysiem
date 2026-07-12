import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.storage import duckdb_store


def _insert(source: str, status_code: int, ts: datetime) -> str:
    event_id = str(uuid.uuid4())
    duckdb_store.insert_event({
        "id": event_id,
        "source": source,
        "ingested_at": ts,
        "event_time": None,
        "source_ip": "10.0.0.1",
        "method": "GET",
        "uri": "/x",
        "status_code": status_code,
        "response_size": 100,
        "user_agent": "test",
        "referer": None,
        "raw": f"{source} {status_code}",
        "extra": {},
    })
    return event_id


def test_query_events_matching_counts_and_samples():
    source = f"backtest-fm-{uuid.uuid4().hex[:8]}"
    now = datetime.utcnow()
    _insert(source, 404, now - timedelta(hours=1))
    _insert(source, 404, now - timedelta(hours=2))
    _insert(source, 200, now - timedelta(hours=1))  # non-matching, must be excluded

    result = duckdb_store.query_events_matching(
        "status_code", "eq", 404, source, now - timedelta(days=1), now + timedelta(minutes=1),
    )
    assert result["total"] == 2
    assert len(result["samples"]) == 2
    assert all(s["status_code"] == 404 for s in result["samples"])
    assert sum(d["count"] for d in result["per_day"]) == 2


def test_query_events_matching_rejects_disallowed_field():
    import pytest
    with pytest.raises(ValueError):
        duckdb_store.query_events_matching(
            "raw", "eq", "x", None, datetime.utcnow() - timedelta(days=1), datetime.utcnow(),
        )


def test_query_events_windowed_counts_would_fire():
    source = f"backtest-th-{uuid.uuid4().hex[:8]}"
    now = datetime.utcnow()
    # The bucketing in query_events_windowed_counts is
    # floor(epoch(ingested_at) / window_seconds) — an absolute-UTC-epoch-aligned
    # bucket, NOT anchored to this test's timestamps. With window_seconds=60,
    # bucket boundaries fall exactly on the top of every UTC minute (epoch=0 is
    # itself minute-aligned, and 60 evenly divides every subsequent minute
    # boundary). To guarantee our 3 events land in the SAME bucket no matter what
    # wall-clock second the test happens to run at, we explicitly zero out the
    # seconds/microseconds of `base` (snapping it to the top of a minute) and then
    # offset all 3 events by a small fixed amount (+5s/+10s/+15s) that is well
    # within a single 60s bucket. Since 5, 10, 15 are all < 60, floor((minute_top
    # + offset)/60) is identical for all three regardless of which minute it is —
    # there is no wall-clock second at which they could straddle a bucket boundary.
    base = (now - timedelta(hours=1)).replace(second=0, microsecond=0) + timedelta(seconds=5)
    _insert(source, 401, base)
    _insert(source, 401, base + timedelta(seconds=5))
    _insert(source, 401, base + timedelta(seconds=10))

    result = duckdb_store.query_events_windowed_counts(
        "status_code", "eq", 401, source,
        now - timedelta(days=1), now + timedelta(minutes=1),
        window_seconds=60, threshold_count=3,
    )
    assert result["would_fire_count"] >= 1
    assert len(result["samples"]) <= 20


def test_query_events_matching_contains_is_case_sensitive():
    """Backtest `contains` must match the live rule engine's case-sensitive
    `str(rule_value) in str(event_value)` semantics, not SQL ILIKE."""
    source = f"backtest-cs-{uuid.uuid4().hex[:8]}"
    now = datetime.utcnow()
    event_id = str(uuid.uuid4())
    duckdb_store.insert_event({
        "id": event_id,
        "source": source,
        "ingested_at": now - timedelta(hours=1),
        "event_time": None,
        "source_ip": "10.0.0.1",
        "method": "GET",
        "uri": "/x",
        "status_code": 200,
        "response_size": 100,
        "user_agent": "Mozilla/5.0 Admin-Agent",
        "referer": None,
        "raw": f"{source} 200",
        "extra": {},
    })

    # Lowercase "admin" should NOT match "Admin-Agent" under case-sensitive contains.
    result = duckdb_store.query_events_matching(
        "user_agent", "contains", "admin", source,
        now - timedelta(days=1), now + timedelta(minutes=1),
    )
    assert result["total"] == 0

    # The exact-case substring should still match.
    result_match = duckdb_store.query_events_matching(
        "user_agent", "contains", "Admin", source,
        now - timedelta(days=1), now + timedelta(minutes=1),
    )
    assert result_match["total"] == 1


def test_query_events_matching_numeric_operator_on_numeric_field():
    """gt/gte/lt/lte must still work correctly for the genuinely numeric columns."""
    source = f"backtest-num-{uuid.uuid4().hex[:8]}"
    now = datetime.utcnow()
    _insert(source, 500, now - timedelta(hours=1))
    _insert(source, 200, now - timedelta(hours=1))

    result = duckdb_store.query_events_matching(
        "status_code", "gte", 400, source,
        now - timedelta(days=1), now + timedelta(minutes=1),
    )
    assert result["total"] == 1
    assert result["samples"][0]["status_code"] == 500


def test_query_events_matching_numeric_operator_rejects_non_numeric_field():
    """gt/gte/lt/lte on a VARCHAR field (e.g. source_ip, uri) would silently do a
    lexicographic string comparison in SQL, diverging from the live rule engine's
    float()-based comparison (which returns False for non-numeric values). The
    backtest must fail closed instead of reporting a misleading count."""
    now = datetime.utcnow()
    with pytest.raises(ValueError):
        duckdb_store.query_events_matching(
            "source_ip", "gt", "10.0.0.1", None,
            now - timedelta(days=1), now,
        )
    with pytest.raises(ValueError):
        duckdb_store.query_events_windowed_counts(
            "uri", "lt", "/z", None,
            now - timedelta(days=1), now,
            window_seconds=60, threshold_count=1,
        )

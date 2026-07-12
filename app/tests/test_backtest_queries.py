import uuid
from datetime import datetime, timedelta, timezone

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
    # 3 matching events within the same ~60s window → should count as 1 firing window
    base = now - timedelta(hours=1)
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

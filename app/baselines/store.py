from datetime import datetime
from typing import Optional

from app.storage.duckdb_store import _get_conn, _lock  # noqa: PLC2701

_BASELINE_COLS = ["source", "hour_of_day", "day_of_week", "mean", "std_dev", "m2", "sample_count", "last_updated"]
_VIOLATION_COLS = [
    "violation_id", "source", "detected_at", "hour_of_day", "day_of_week",
    "observed_count", "expected_mean", "expected_std", "z_score", "severity", "acknowledged",
]
_DOW_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


def get_baseline(source: str, hour: int, dow: int) -> Optional[dict]:
    with _lock:
        row = _get_conn().execute(
            "SELECT source, hour_of_day, day_of_week, mean, std_dev, m2, sample_count, last_updated "
            "FROM baselines WHERE source=? AND hour_of_day=? AND day_of_week=?",
            [source, hour, dow],
        ).fetchone()
    if not row:
        return None
    return dict(zip(_BASELINE_COLS, row))


def upsert_baseline(
    source: str, hour: int, dow: int,
    mean: float, std_dev: float, m2: float,
    sample_count: int, last_updated: datetime,
) -> None:
    with _lock:
        _get_conn().execute(
            """INSERT INTO baselines (source, hour_of_day, day_of_week, mean, std_dev, m2, sample_count, last_updated)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT (source, hour_of_day, day_of_week) DO UPDATE SET
                   mean = excluded.mean, std_dev = excluded.std_dev, m2 = excluded.m2,
                   sample_count = excluded.sample_count, last_updated = excluded.last_updated""",
            [source, hour, dow, mean, std_dev, m2, sample_count, last_updated],
        )


def delete_baselines_for_source(source: str) -> int:
    with _lock:
        count = _get_conn().execute(
            "SELECT COUNT(*) FROM baselines WHERE source=?", [source]
        ).fetchone()[0]
        _get_conn().execute("DELETE FROM baselines WHERE source=?", [source])
    return count


def list_baselines(
    source: Optional[str] = None,
    hour_of_day: Optional[int] = None,
    day_of_week: Optional[int] = None,
) -> list[dict]:
    conditions, params = [], []
    if source:
        conditions.append("source = ?")
        params.append(source)
    if hour_of_day is not None:
        conditions.append("hour_of_day = ?")
        params.append(hour_of_day)
    if day_of_week is not None:
        conditions.append("day_of_week = ?")
        params.append(day_of_week)
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    with _lock:
        rows = _get_conn().execute(
            f"SELECT source, hour_of_day, day_of_week, mean, std_dev, m2, sample_count, last_updated "
            f"FROM baselines {where} ORDER BY source, hour_of_day, day_of_week",
            params,
        ).fetchall()
    result = []
    for row in rows:
        d = dict(zip(_BASELINE_COLS, row))
        d.pop("m2", None)
        if d.get("last_updated") and hasattr(d["last_updated"], "isoformat"):
            d["last_updated"] = d["last_updated"].isoformat() + "Z"
        result.append(d)
    return result


def insert_violation(v: dict) -> str:
    import uuid
    vid = str(uuid.uuid4())
    dt = v["detected_at"]
    if hasattr(dt, "tzinfo") and dt.tzinfo:
        dt = dt.replace(tzinfo=None)
    with _lock:
        _get_conn().execute(
            "INSERT INTO baseline_violations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, FALSE)",
            [vid, v["source"], dt, v["hour_of_day"], v["day_of_week"],
             v["observed_count"], v["expected_mean"], v["expected_std"],
             v["z_score"], v["severity"]],
        )
    return vid


def query_violations(
    source: Optional[str] = None,
    severity: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    conditions, params = [], []
    if source:
        conditions.append("source = ?")
        params.append(source)
    if severity:
        conditions.append("severity = ?")
        params.append(severity)
    if acknowledged is not None:
        conditions.append("acknowledged = ?")
        params.append(acknowledged)
    if start:
        s = start.replace(tzinfo=None) if start.tzinfo else start
        conditions.append("detected_at >= ?")
        params.append(s)
    if end:
        e = end.replace(tzinfo=None) if end.tzinfo else end
        conditions.append("detected_at <= ?")
        params.append(e)
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    with _lock:
        total = _get_conn().execute(
            f"SELECT COUNT(*) FROM baseline_violations {where}", params
        ).fetchone()[0]
        rows = _get_conn().execute(
            f"SELECT {','.join(_VIOLATION_COLS)} FROM baseline_violations {where} "
            "ORDER BY detected_at DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
    items = []
    for row in rows:
        d = dict(zip(_VIOLATION_COLS, row))
        if d.get("detected_at") and hasattr(d["detected_at"], "isoformat"):
            d["detected_at"] = d["detected_at"].isoformat() + "Z"
        d["summary"] = (
            f"{d['source']} traffic at {_DOW_NAMES[d['day_of_week']]} {d['hour_of_day']:02d}:00 "
            f"was {d['observed_count']:.0f} events "
            f"(expected {d['expected_mean']:.0f} ± {d['expected_std']:.0f}, z={d['z_score']:.1f})"
        )
        items.append(d)
    return {"total": total, "violations": items}


def acknowledge_violation(violation_id: str) -> bool:
    with _lock:
        conn = _get_conn()
        if not conn.execute(
            "SELECT 1 FROM baseline_violations WHERE violation_id=?", [violation_id]
        ).fetchone():
            return False
        conn.execute(
            "UPDATE baseline_violations SET acknowledged=TRUE WHERE violation_id=?",
            [violation_id],
        )
    return True

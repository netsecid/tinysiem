import asyncio
import json
import logging
import math
import uuid
from datetime import datetime, timezone
from pathlib import Path

from app.config import settings

logger = logging.getLogger(__name__)

_DOW_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


def _z_severity(z: float) -> str:
    if z >= 7.0:
        return "critical"
    if z >= 5.0:
        return "high"
    if z >= 4.0:
        return "medium"
    return "low"


def _write_baseline_alert(violation_id: str, severity: str, source: str, summary: str) -> None:
    path = Path(settings.tinysiem_alerts_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    alert = {
        "alert_id": str(uuid.uuid4()),
        "triggered_at": datetime.now(timezone.utc).isoformat(),
        "rule_name": "smart_baseline",
        "severity": severity,
        "mitre_tactic": "Discovery",
        "mitre_technique": None,
        "event_id": violation_id,
        "source_ip": None,
        "source": source,
        "summary": summary,
    }
    try:
        with open(path, "a") as fh:
            fh.write(json.dumps(alert) + "\n")
        from app.notifications.sender import notify
        notify(alert)
    except Exception as exc:
        logger.error(f"Failed to write baseline alert: {exc}")


def _run_once_sync() -> None:
    from app.baselines import store as baseline_store
    from app.storage import duckdb_store

    now = datetime.utcnow()
    hour = now.hour
    dow = now.weekday()  # 0=Monday

    sources = duckdb_store.get_event_sources()
    window = settings.tinysiem_baseline_interval_minutes * 60

    for source in sources:
        try:
            observed = float(duckdb_store.count_events_in_window("source", source, window))
        except Exception as exc:
            logger.error(f"Baseline: failed to count events for {source!r}: {exc}")
            continue

        existing = baseline_store.get_baseline(source, hour, dow)

        if existing and existing["sample_count"] >= settings.tinysiem_baseline_min_samples:
            std_floor = max(existing["std_dev"], 1.0)
            z = (observed - existing["mean"]) / std_floor
            if z >= settings.tinysiem_baseline_z_threshold:
                severity = _z_severity(z)
                summary = (
                    f"{source} traffic at {_DOW_NAMES[dow]} {hour:02d}:00 was "
                    f"{observed:.0f} events (expected {existing['mean']:.0f} "
                    f"± {existing['std_dev']:.0f}, z={z:.1f})"
                )
                violation = {
                    "source": source,
                    "detected_at": now,
                    "hour_of_day": hour,
                    "day_of_week": dow,
                    "observed_count": observed,
                    "expected_mean": existing["mean"],
                    "expected_std": existing["std_dev"],
                    "z_score": z,
                    "severity": severity,
                }
                vid = baseline_store.insert_violation(violation)
                _write_baseline_alert(vid, severity, source, summary)
                logger.info(f"Baseline violation: source={source!r} z={z:.1f} sev={severity}")

        # Welford's online update
        if existing:
            n = existing["sample_count"] + 1
            m2 = existing.get("m2") or 0.0
            delta = observed - existing["mean"]
            new_mean = existing["mean"] + delta / n
            delta2 = observed - new_mean
            new_m2 = m2 + delta * delta2
            new_std = math.sqrt(new_m2 / n) if n > 1 else 0.0
            baseline_store.upsert_baseline(source, hour, dow, new_mean, new_std, new_m2, n, now)
        else:
            baseline_store.upsert_baseline(source, hour, dow, float(observed), 0.0, 0.0, 1, now)


async def run_once() -> None:
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _run_once_sync)

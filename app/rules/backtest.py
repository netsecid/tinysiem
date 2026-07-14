from datetime import datetime, timedelta, timezone

from fastapi import HTTPException

from app.storage import duckdb_store


def run_backtest(rule: dict, days: int) -> dict:
    condition = rule.get("condition", {})
    ctype = condition.get("type")
    if ctype == "correlation":
        return {"supported": False, "reason": "correlation rules cannot be backtested"}

    field = condition.get("field")
    operator = condition.get("operator", "eq")
    value = condition.get("value")
    rule_source = rule.get("source")
    source = rule_source if rule_source and rule_source != "*" else None

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    from app.rules import engine as rule_engine
    exclude = rule_engine._exception_pairs(rule.get("name", ""))

    try:
        if ctype == "field_match":
            result = duckdb_store.query_events_matching(
                field, operator, value, source, start, end, exclude=exclude,
            )
            return {
                "supported": True,
                "condition_type": "field_match",
                "would_fire_count": result["total"],
                "per_day": result["per_day"],
                "samples": result["samples"],
            }
        if ctype == "threshold":
            threshold_count = condition.get("threshold_count", 1)
            window_seconds = condition.get("window_seconds", 60)
            result = duckdb_store.query_events_windowed_counts(
                field, operator, value, source, start, end, window_seconds, threshold_count,
                exclude=exclude,
            )
            return {
                "supported": True,
                "condition_type": "threshold",
                "would_fire_count": result["would_fire_count"],
                "per_day": result["per_day"],
                "samples": result["samples"],
            }
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    return {"supported": False, "reason": f"unknown condition type '{ctype}'"}

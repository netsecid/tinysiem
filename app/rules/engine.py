import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

from app.alerts import file_writer
from app.storage import duckdb_store

logger = logging.getLogger(__name__)

_rules: list[dict] = []

# Correlation state: {rule_name: {capture_value: {step, triggered_at, first_event_id}}}
_corr_state: dict[str, dict[str, dict]] = {}
_corr_lock = threading.Lock()

# Suppression state (independent of correlation state above): tracks per
# (rule_name, source_ip) how long to withhold repeated alerts, and how many
# firings were suppressed in the meantime.
_suppression_until: dict[tuple[str, str], float] = {}
_suppressed_counts: dict[tuple[str, str], int] = {}
_suppression_lock = threading.Lock()

# Rule exceptions cache (E5): {rule_name: [{"field":..., "value":...}, ...]}
_exceptions: dict[str, list[dict]] = {}
_exceptions_lock = threading.Lock()


def load_exceptions() -> None:
    global _exceptions
    from app.rules import exceptions_store
    rows = exceptions_store.get_all_exceptions()
    grouped: dict[str, list[dict]] = {}
    for row in rows:
        grouped.setdefault(row["rule_name"], []).append({"field": row["field"], "value": row["value"]})
    with _exceptions_lock:
        _exceptions = grouped


def _is_excepted(rule_name: str, event: dict) -> bool:
    with _exceptions_lock:
        rule_exceptions = _exceptions.get(rule_name, [])
    for exc in rule_exceptions:
        if str(event.get(exc["field"])) == str(exc["value"]):
            return True
    return False


def _exception_pairs(rule_name: str) -> list[tuple[str, str]]:
    with _exceptions_lock:
        rule_exceptions = _exceptions.get(rule_name, [])
    return [(exc["field"], exc["value"]) for exc in rule_exceptions]


def _suppress_key(rule: dict, event: dict) -> tuple[str, str]:
    return (rule.get("name", ""), str(event.get("source_ip") or ""))


def _default_suppress_seconds(rule: dict) -> int:
    explicit = rule.get("suppress_seconds")
    if explicit is not None:
        return int(explicit)
    ctype = rule.get("condition", {}).get("type")
    return 300 if ctype == "threshold" else 0


def _maybe_fire(rule: dict, event: dict) -> None:
    suppress_seconds = _default_suppress_seconds(rule)
    if suppress_seconds <= 0:
        file_writer.write_alert(rule, event)
        return

    key = _suppress_key(rule, event)
    now = time.monotonic()
    with _suppression_lock:
        until = _suppression_until.get(key, 0.0)
        if now < until:
            _suppressed_counts[key] = _suppressed_counts.get(key, 0) + 1
            return
        suppressed_count = _suppressed_counts.pop(key, 0)
        _suppression_until[key] = now + suppress_seconds
    file_writer.write_alert(rule, event, suppressed_count=suppressed_count)


def reset_suppression_state() -> None:
    with _suppression_lock:
        _suppression_until.clear()
        _suppressed_counts.clear()


def load_rules(rules_dir: Optional[Path] = None) -> None:
    global _rules
    if rules_dir is None:
        rules_dir = Path(__file__).parent / "rules"

    _rules = []
    for yaml_file in sorted(rules_dir.glob("*.yaml")):
        try:
            with open(yaml_file) as f:
                rule = yaml.safe_load(f)
            _rules.append(rule)
            logger.info(f"Loaded rule '{rule.get('name')}'")
        except Exception as exc:
            logger.warning(f"Failed to load rule {yaml_file}: {exc}")

    custom_dir = rules_dir / "custom"
    if custom_dir.exists():
        for yaml_file in sorted(custom_dir.glob("*.yaml")):
            try:
                with open(yaml_file) as f:
                    rule = yaml.safe_load(f)
                _rules.append(rule)
                logger.info(f"Loaded custom rule '{rule.get('name')}'")
            except Exception as exc:
                logger.warning(f"Failed to load custom rule {yaml_file}: {exc}")


def reset_corr_state() -> None:
    with _corr_lock:
        _corr_state.clear()


def get_loaded_rules() -> list[dict]:
    """Read-only accessor for currently loaded rules. Used by /dashboard/fidelity
    to report the engine's rules-loaded count without re-reading YAML files per
    request."""
    return list(_rules)


def loaded_rules_count() -> int:
    return len(_rules)


def evaluate(event: dict) -> None:
    source = event.get("source")
    for rule in _rules:
        rule_name = rule.get("name", "")
        if _is_excepted(rule_name, event):
            continue
        ctype = rule.get("condition", {}).get("type")
        try:
            if ctype == "correlation":
                _evaluate_correlation(rule, event)
            elif rule.get("source") == source:
                _evaluate_rule(rule, event)
        except Exception as exc:
            logger.warning(f"Rule '{rule.get('name')}' evaluation error: {exc}")


def _evaluate_rule(rule: dict, event: dict) -> None:
    condition = rule.get("condition", {})
    ctype = condition.get("type")
    field = condition.get("field")
    value = condition.get("value")
    operator = condition.get("operator", "eq")

    if ctype == "field_match":
        triggered = _check_operator(event.get(field), operator, value)

    elif ctype == "threshold":
        # The triggering event must itself match field/value — otherwise an unrelated
        # event (of the right source) re-evaluates a stale aggregate count and fires
        # using its own id/source_ip, misattributing the alert.
        if not _check_operator(event.get(field), operator, value):
            return
        threshold_count = condition.get("threshold_count", 1)
        window_seconds = condition.get("window_seconds", 60)
        rule_source = rule.get("source")
        scope_source = rule_source if rule_source and rule_source != "*" else None
        exclude = _exception_pairs(rule.get("name", ""))
        count = duckdb_store.count_events_in_window(
            field, value, window_seconds, source=scope_source, exclude=exclude,
        )
        triggered = count >= threshold_count

    else:
        logger.warning(f"Unknown condition type '{ctype}' in rule '{rule.get('name')}'")
        return

    if triggered:
        _maybe_fire(rule, event)


def _check_step(event: dict, step_spec: dict) -> bool:
    step_source = step_spec.get("source")
    if step_source and step_source != "*" and event.get("source") != step_source:
        return False
    field = step_spec.get("field")
    value = step_spec.get("value")
    operator = step_spec.get("operator", "eq")
    if field:
        return _check_operator(event.get(field), operator, value)
    return True


def _cleanup_corr(rule_name: str, window: int) -> None:
    now = datetime.now(timezone.utc)
    if rule_name in _corr_state:
        _corr_state[rule_name] = {
            k: v for k, v in _corr_state[rule_name].items()
            if (now - v["triggered_at"]).total_seconds() <= window
        }


def _evaluate_correlation(rule: dict, event: dict) -> None:
    cond = rule.get("condition", {})
    steps = cond.get("steps", [])
    if len(steps) < 2:
        return
    capture_field = cond.get("capture_field")
    window = cond.get("window_seconds", 300)
    rule_name = rule.get("name")

    capture_value = str(event.get(capture_field, "")) if capture_field else None
    if not capture_value:
        return

    with _corr_lock:
        _cleanup_corr(rule_name, window)
        state = _corr_state.setdefault(rule_name, {})
        entry = state.get(capture_value)

        if entry is None:
            if _check_step(event, steps[0]):
                state[capture_value] = {
                    "step": 0,
                    "triggered_at": datetime.now(timezone.utc),
                    "first_event_id": event.get("id"),
                }
        else:
            next_step = entry["step"] + 1
            if next_step < len(steps) and _check_step(event, steps[next_step]):
                if next_step == len(steps) - 1:
                    del state[capture_value]
                    _maybe_fire(rule, event)
                else:
                    entry["step"] = next_step


def _check_operator(event_value, operator: str, rule_value) -> bool:
    if event_value is None:
        return False
    try:
        if operator == "eq":
            return str(event_value) == str(rule_value)
        if operator == "neq":
            return str(event_value) != str(rule_value)
        if operator == "gt":
            return float(event_value) > float(rule_value)
        if operator == "gte":
            return float(event_value) >= float(rule_value)
        if operator == "lt":
            return float(event_value) < float(rule_value)
        if operator == "lte":
            return float(event_value) <= float(rule_value)
        if operator == "contains":
            return str(rule_value) in str(event_value)
    except (TypeError, ValueError):
        return False

    logger.warning(f"Unknown operator '{operator}'")
    return False

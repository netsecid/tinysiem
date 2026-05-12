import logging
from pathlib import Path
from typing import Optional

import yaml

from app.alerts import file_writer
from app.storage import duckdb_store

logger = logging.getLogger(__name__)

_rules: list[dict] = []


def load_rules(rules_dir: Optional[Path] = None) -> None:
    global _rules
    if rules_dir is None:
        rules_dir = Path(__file__).parent / "rules"

    _rules = []
    for yaml_file in rules_dir.glob("*.yaml"):
        try:
            with open(yaml_file) as f:
                rule = yaml.safe_load(f)
            _rules.append(rule)
            logger.info(f"Loaded rule '{rule.get('name')}'")
        except Exception as exc:
            logger.warning(f"Failed to load rule {yaml_file}: {exc}")


def evaluate(event: dict) -> None:
    source = event.get("source")
    for rule in _rules:
        if rule.get("source") != source:
            continue
        try:
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
        threshold_count = condition.get("threshold_count", 1)
        window_seconds = condition.get("window_seconds", 60)
        count = duckdb_store.count_events_in_window(field, value, window_seconds)
        triggered = count >= threshold_count

    else:
        logger.warning(f"Unknown condition type '{ctype}' in rule '{rule.get('name')}'")
        return

    if triggered:
        file_writer.write_alert(rule, event)


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

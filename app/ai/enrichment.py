import json
import logging
import time
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

_SCHEMA_BLOCK = (
    "id VARCHAR, source VARCHAR, ingested_at TIMESTAMP, event_time TIMESTAMP, "
    "source_ip VARCHAR, method VARCHAR, uri VARCHAR, status_code INTEGER, "
    "response_size INTEGER, user_agent VARCHAR, referer VARCHAR, raw VARCHAR, extra JSON"
)

_DECODERS_DIR = Path(__file__).parent.parent / "decoder" / "decoders"
_RULES_DIR = Path(__file__).parent.parent / "rules" / "rules"


def build_generation_context() -> str:
    from app.storage import duckdb_store
    sources = duckdb_store.get_event_sources()

    parsers = []
    for d in [_DECODERS_DIR, _DECODERS_DIR / "custom"]:
        if d.exists():
            for f in sorted(d.glob("*.yaml")):
                try:
                    data = yaml.safe_load(f.read_text())
                    parsers.append(f"{data.get('name', f.stem)} ({data.get('type','?')}, {data.get('source','?')})")
                except Exception:
                    pass

    rules = []
    for d in [_RULES_DIR, _RULES_DIR / "custom"]:
        if d.exists():
            for f in sorted(d.glob("*.yaml")):
                try:
                    data = yaml.safe_load(f.read_text())
                    cond_type = (data.get("condition") or {}).get("type", "?")
                    rules.append(f"{data.get('name', f.stem)} ({cond_type}, {data.get('source','?')})")
                except Exception:
                    pass

    ctx = "<context>\n"
    ctx += f"Active log sources: {', '.join(sources) if sources else 'none'}\n"
    ctx += f"Existing parsers: {', '.join(parsers) if parsers else 'none'}\n"
    ctx += f"Existing rules: {', '.join(rules) if rules else 'none'}\n"
    ctx += f"DuckDB schema (events table): {_SCHEMA_BLOCK}\n"
    ctx += "Normalized field names: source_ip, method, uri, status_code, response_size, user_agent, referer\n"
    ctx += "</context>\n\n"
    return ctx


def _read_alert_by_id(alert_id: str) -> Optional[dict]:
    from app.config import settings
    path = Path(settings.tinysiem_alerts_path)
    if not path.exists():
        return None
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                a = json.loads(line)
                if a.get("alert_id") == alert_id:
                    return a
            except json.JSONDecodeError:
                continue
    return None


def _get_rule_yaml(rule_name: str) -> Optional[str]:
    for d in [_RULES_DIR, _RULES_DIR / "custom"]:
        if d.exists():
            f = d / f"{rule_name}.yaml"
            if f.exists():
                return f.read_text()
    return None


def explain_alert(alert_id: str, actor: str) -> dict:
    from app.ai.claude import _get_client, _log_ai_call
    from app.storage import duckdb_store

    alert = _read_alert_by_id(alert_id)
    if not alert:
        raise ValueError(f"Alert {alert_id!r} not found")

    event = None
    if alert.get("event_id"):
        event = duckdb_store.get_event_by_id(alert["event_id"])

    rule_yaml = _get_rule_yaml(alert.get("rule_name", ""))

    parts = [f"Alert:\n{json.dumps(alert, indent=2, default=str)}"]
    if event:
        raw_truncated = (event.get("raw") or "")[:2000]
        parts.append(f"\nOriginating event (raw truncated to 2000 chars):\n{raw_truncated}")
        fields = {k: v for k, v in event.items() if k != "raw" and v is not None}
        parts.append(f"\nParsed event fields:\n{json.dumps(fields, indent=2, default=str)}")
    if rule_yaml:
        parts.append(f"\nRule YAML that fired:\n{rule_yaml}")

    prompt = "\n".join(parts)

    system_prompt = (
        "You are a security analyst assistant for TinySIEM. "
        "Given an alert and its originating event, explain:\n"
        "1. What triggered this alert and what the attacker behavior pattern means\n"
        "2. The most likely MITRE ATT&CK mapping (confirm or refine what's already tagged)\n"
        "3. A recommended immediate action for the analyst\n"
        "Be concise and practical. No markdown headers. Plain paragraphs."
    )

    client = _get_client()
    start = time.time()
    try:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            system=system_prompt,
            messages=[{"role": "user", "content": prompt}],
        )
        explanation = response.content[0].text.strip()
        duration_ms = int((time.time() - start) * 1000)
        _log_ai_call("explain_alert", actor, prompt, explanation, duration_ms, success=True)
        return {
            "explanation": explanation,
            "model": "claude-sonnet-4-6",
            "prompt_tokens": response.usage.input_tokens,
            "completion_tokens": response.usage.output_tokens,
            "duration_ms": duration_ms,
        }
    except Exception as exc:
        duration_ms = int((time.time() - start) * 1000)
        _log_ai_call("explain_alert", actor, prompt, "", duration_ms, success=False, error=str(exc))
        raise


def analyze_events(event_ids: list[str], question: str, actor: str) -> dict:
    from app.ai.claude import _get_client, _log_ai_call
    from app.storage import duckdb_store

    events = duckdb_store.get_events_by_ids(event_ids)
    if not events:
        raise ValueError("No events found for the given IDs")

    event_blocks = []
    for ev in events:
        raw = (ev.get("raw") or "")[:500]
        fields = {k: v for k, v in ev.items() if k != "raw" and v is not None}
        event_blocks.append(
            f"Event {ev.get('id','?')}:\n"
            f"  Fields: {json.dumps(fields, default=str)}\n"
            f"  Raw (truncated): {raw}"
        )

    prompt = f"Question: {question[:2000]}\n\nEvents ({len(events)} total):\n\n" + "\n\n".join(event_blocks)

    system_prompt = (
        "You are a security analyst assistant for TinySIEM. "
        "Analyze the provided events and answer the analyst's question. "
        "Focus on patterns, attacker behavior, and actionable recommendations. "
        "Be concise and practical."
    )

    client = _get_client()
    start = time.time()
    try:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1500,
            system=system_prompt,
            messages=[{"role": "user", "content": prompt}],
        )
        analysis = response.content[0].text.strip()
        duration_ms = int((time.time() - start) * 1000)
        _log_ai_call("analyze_events", actor, prompt, analysis, duration_ms, success=True)
        return {
            "analysis": analysis,
            "model": "claude-sonnet-4-6",
            "prompt_tokens": response.usage.input_tokens,
            "completion_tokens": response.usage.output_tokens,
            "duration_ms": duration_ms,
        }
    except Exception as exc:
        duration_ms = int((time.time() - start) * 1000)
        _log_ai_call("analyze_events", actor, prompt, "", duration_ms, success=False, error=str(exc))
        raise

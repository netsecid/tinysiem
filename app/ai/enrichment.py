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
    from app.ai.claude import _log_ai_call
    from app.ai.provider_factory import get_active_provider
    from app.storage import duckdb_store

    # Eagerly resolve the provider so callers get 503 before any DB work
    provider = get_active_provider()

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

    start = time.time()
    try:
        result = provider.chat(system=system_prompt, user=prompt, max_tokens=1024)
        duration_ms = int((time.time() - start) * 1000)
        _log_ai_call("explain_alert", actor, prompt, result.text, duration_ms, success=True, model=provider.model)
        return {
            "explanation": result.text,
            "model": provider.model,
            "prompt_tokens": result.prompt_tokens,
            "completion_tokens": result.completion_tokens,
            "duration_ms": duration_ms,
        }
    except Exception as exc:
        duration_ms = int((time.time() - start) * 1000)
        _log_ai_call("explain_alert", actor, prompt, "", duration_ms, success=False, model=provider.model, error=str(exc))
        raise


def _get_rule_resolution_stats(rule_name: str, days: int = 90) -> dict:
    """Return resolution breakdown for a rule's alerts over the past N days."""
    from app.config import settings as cfg
    from datetime import datetime, timedelta, timezone
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    path = Path(cfg.tinysiem_alerts_path)
    if not path.exists():
        return {"total": 0, "resolutions": {}}
    alert_ids = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                a = json.loads(line)
                if a.get("rule_name") == rule_name:
                    ts = a.get("triggered_at", "")
                    try:
                        fired = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        if fired >= cutoff:
                            alert_ids.append(a["alert_id"])
                    except Exception:
                        pass
            except json.JSONDecodeError:
                continue
    if not alert_ids:
        return {"total": 0, "resolutions": {}}
    from app.storage.duckdb_store import _get_conn, _lock
    placeholders = ",".join("?" * len(alert_ids))
    with _lock:
        rows = _get_conn().execute(
            f"""SELECT c.resolution, COUNT(*) FROM case_alerts ca
                JOIN cases c ON ca.case_id = c.case_id
                WHERE ca.alert_id IN ({placeholders}) AND c.resolution IS NOT NULL
                GROUP BY c.resolution""",
            alert_ids,
        ).fetchall()
    resolutions = {r[0]: r[1] for r in rows}
    return {"total": len(alert_ids), "resolutions": resolutions}


def generate_playbook(rule: dict, actor: str) -> dict:
    from app.ai.claude import _log_ai_call
    from app.ai.provider_factory import get_active_provider
    from app.storage import duckdb_store

    # Eagerly resolve the provider so callers get 503 before any DB work
    provider = get_active_provider()

    sources = duckdb_store.get_event_sources()
    rule_name = rule.get("name", "")
    history = _get_rule_resolution_stats(rule_name)

    # Gather active integration types
    from app.storage.duckdb_store import _get_conn, _lock
    try:
        with _lock:
            int_rows = _get_conn().execute(
                "SELECT integration_type FROM integrations WHERE enabled = TRUE"
            ).fetchall()
        integration_types = [r[0] for r in int_rows]
    except Exception:
        integration_types = []

    existing_playbook = rule.get("playbook")
    parts = [
        f"Rule YAML:\n{json.dumps(rule, indent=2, default=str)}",
        f"\nActive log sources in this SIEM: {', '.join(sources) or 'none'}",
        f"\nActive integrations: {', '.join(integration_types) or 'none'}",
        f"\nAlert history for this rule (last 90 days): {json.dumps(history, indent=2)}",
    ]
    if existing_playbook:
        parts.append(f"\nExisting playbook (refine this rather than replacing): {json.dumps(existing_playbook, indent=2)}")

    prompt = "\n".join(parts)
    system_prompt = (
        "You are a security operations expert writing triage playbooks for a SIEM. "
        "Given a detection rule and context about this organisation's environment, "
        "produce a structured JSON playbook with this exact shape:\n"
        '{"summary": "one sentence", "steps": [{"id": "snake_case_slug", "name": "Step label", '
        '"action": "lookup_threat_intel|query_events|check_baseline|update_severity|block_ip|notify|other", '
        '"auto": false, "notes": "optional analyst guidance"}]}\n'
        "Rules: ids must be unique snake_case; 3–7 steps; tailor steps to the active sources and integrations; "
        "if resolution history shows high false_positive rate, include a false-positive triage step early. "
        "Return ONLY the JSON object — no markdown, no explanation."
    )

    start = time.time()
    try:
        result = provider.chat(system=system_prompt, user=prompt, max_tokens=1024)
        duration_ms = int((time.time() - start) * 1000)
        playbook = json.loads(result.text)
        _log_ai_call("generate_playbook", actor, prompt, result.text, duration_ms, success=True, model=provider.model)
        return {
            "playbook": playbook,
            "model": provider.model,
            "prompt_tokens": result.prompt_tokens,
            "completion_tokens": result.completion_tokens,
        }
    except Exception as exc:
        duration_ms = int((time.time() - start) * 1000)
        _log_ai_call("generate_playbook", actor, prompt, "", duration_ms, success=False, model=provider.model, error=str(exc))
        raise


def refine_playbook(case_id: str, alert_id: str, actor: str) -> dict:
    from app.ai.claude import _log_ai_call
    from app.ai.provider_factory import get_active_provider
    from app.storage import duckdb_store
    from app.cases import store as case_store

    # Eagerly resolve the provider so callers get 503 before any DB work
    provider = get_active_provider()

    alert = _read_alert_by_id(alert_id)
    if not alert:
        raise ValueError(f"Alert {alert_id!r} not found")

    event = None
    if alert.get("event_id"):
        event = duckdb_store.get_event_by_id(alert["event_id"])

    completed = case_store.get_completed_steps(case_id)
    completed_ids = [c["step_id"] for c in completed if c["rule_name"] == alert.get("rule_name")]
    playbook = alert.get("playbook", {})

    parts = [
        f"Alert:\n{json.dumps(alert, indent=2, default=str)}",
        f"\nPlaybook steps:\n{json.dumps(playbook.get('steps', []), indent=2)}",
        f"\nSteps already completed: {completed_ids or 'none'}",
    ]
    if event:
        raw_truncated = (event.get("raw") or "")[:2000]
        fields = {k: v for k, v in event.items() if k != "raw" and v is not None}
        parts.append(f"\nTriggering event fields:\n{json.dumps(fields, indent=2, default=str)}")
        parts.append(f"\nRaw log (truncated):\n{raw_truncated}")

    prompt = "\n".join(parts)
    system_prompt = (
        "You are a security analyst assistant. Given a specific alert, its triggering log, "
        "and the rule's generic playbook steps, write a concise situational note (3–5 sentences) "
        "that tells the analyst what to prioritise first and flags anything anomalous about THIS "
        "specific alert compared to the generic guidance. Be specific: name the IP, URI, count, "
        "or timestamp where relevant. Plain text only — no markdown, no bullet points."
    )

    start = time.time()
    try:
        result = provider.chat(system=system_prompt, user=prompt, max_tokens=512)
        duration_ms = int((time.time() - start) * 1000)
        _log_ai_call("playbook.refine", actor, prompt, result.text, duration_ms, success=True, model=provider.model)
        return {
            "refinement": result.text,
            "model": provider.model,
            "prompt_tokens": result.prompt_tokens,
            "completion_tokens": result.completion_tokens,
        }
    except Exception as exc:
        duration_ms = int((time.time() - start) * 1000)
        _log_ai_call("playbook.refine", actor, prompt, "", duration_ms, success=False, model=provider.model, error=str(exc))
        raise


def analyze_events(event_ids: list[str], question: str, actor: str) -> dict:
    from app.ai.claude import _log_ai_call
    from app.ai.provider_factory import get_active_provider
    from app.storage import duckdb_store

    # Eagerly resolve the provider so callers get 503 before any DB work
    provider = get_active_provider()

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

    start = time.time()
    try:
        result = provider.chat(system=system_prompt, user=prompt, max_tokens=1500)
        duration_ms = int((time.time() - start) * 1000)
        _log_ai_call("analyze_events", actor, prompt, result.text, duration_ms, success=True, model=provider.model)
        return {
            "analysis": result.text,
            "model": provider.model,
            "prompt_tokens": result.prompt_tokens,
            "completion_tokens": result.completion_tokens,
            "duration_ms": duration_ms,
        }
    except Exception as exc:
        duration_ms = int((time.time() - start) * 1000)
        _log_ai_call("analyze_events", actor, prompt, "", duration_ms, success=False, model=provider.model, error=str(exc))
        raise

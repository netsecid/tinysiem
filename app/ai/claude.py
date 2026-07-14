import logging
import time

logger = logging.getLogger(__name__)

_PARSER_SYSTEM_PROMPT = """\
You are a TinySIEM parser generator. Output ONLY valid YAML — no prose, no code fences, no explanation.

The decoder YAML format is:
  name: <kebab-case-name>      # e.g. nginx-access
  source: <source-name>        # matches the source field in ingest requests
  type: regex                  # regex | json | kv
  pattern: '<regex>'           # named capture groups used by fields mapping
  fields:                      # maps normalized field names to capture group names
    source_ip: <group_name>
    method: <group_name>
    uri: <group_name>
    status_code: <group_name>
    response_size: <group_name>
    user_agent: <group_name>
    referer: <group_name>
  timestamp_field: <field_key>   # key from fields: that holds the timestamp
  timestamp_format: '<strptime>' # e.g. '%d/%b/%Y:%H:%M:%S %z'

Rules:
- Use named capture groups (?P<name>...)
- Only include fields that are present in the sample
- The regex must match the full line from the start (use ^)
- Output the YAML and nothing else
"""

_RULE_SYSTEM_PROMPT = """\
You are a TinySIEM detection rule generator. Output ONLY valid YAML — no prose, no code fences.

The rule YAML format is:
  name: <kebab-case-name>       # e.g. nginx-http-404-spike
  severity: low|medium|high|critical
  source: <source-name>         # must match an existing parser's source field
  condition:
    type: threshold             # threshold: count of events in window
    field: <field_name>         # one of: source, source_ip, method, uri, status_code, response_size
    value: <match_value>
    operator: eq|neq|gt|gte|lt|lte|contains
    threshold_count: <int>      # fire when count >= this
    window_seconds: <int>
  # OR for single-event match:
  condition:
    type: field_match
    field: <field_name>
    value: <match_value>
    operator: eq|neq|gt|gte|lt|lte|contains
  mitre_tactic: "<tactic>"     # optional
  mitre_technique: "<T-code>"  # optional

Output the YAML and nothing else.
"""


def _log_ai_call(action: str, actor: str, prompt: str, result: str, duration_ms: int, success: bool, model: str = "", error: str = None) -> None:
    from app.audit import store as audit
    audit.log_event(
        "ai.call", action,
        status="success" if success else "error",
        actor=actor,
        resource_type="ai",
        detail={
            "model": model,
            "prompt_length": len(prompt),
            "prompt_preview": prompt[:500],
            "response_length": len(result) if result else 0,
            "response_preview": result[:1000] if result else None,
            "duration_ms": duration_ms,
        },
        duration_ms=duration_ms,
        error_msg=error,
    )


def generate_parser(log_sample: str, actor: str = "system") -> str:
    from app.ai.provider_factory import get_active_provider
    provider = get_active_provider()
    prompt = f"Generate a decoder YAML for this log sample:\n\n{log_sample}"
    start = time.time()
    try:
        result = provider.chat(system=_PARSER_SYSTEM_PROMPT, user=prompt, max_tokens=2048)
        duration_ms = int((time.time() - start) * 1000)
        _log_ai_call("generate_parser", actor, prompt, result.text, duration_ms, success=True, model=provider.model)
        return result.text
    except Exception as exc:
        duration_ms = int((time.time() - start) * 1000)
        _log_ai_call("generate_parser", actor, prompt, "", duration_ms, success=False, model=provider.model, error=str(exc))
        raise


def generate_rule(description: str, source: str, actor: str = "system") -> str:
    from app.ai.provider_factory import get_active_provider
    provider = get_active_provider()
    prompt = f"Source: {source}\n\nGenerate a detection rule for: {description}"
    start = time.time()
    try:
        result = provider.chat(system=_RULE_SYSTEM_PROMPT, user=prompt, max_tokens=1024)
        duration_ms = int((time.time() - start) * 1000)
        _log_ai_call("generate_rule", actor, prompt, result.text, duration_ms, success=True, model=provider.model)
        return result.text
    except Exception as exc:
        duration_ms = int((time.time() - start) * 1000)
        _log_ai_call("generate_rule", actor, prompt, "", duration_ms, success=False, model=provider.model, error=str(exc))
        raise

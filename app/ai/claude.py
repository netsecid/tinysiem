import logging

from app.config import settings

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


def _get_client():
    if not settings.tinysiem_claude_api_key:
        raise RuntimeError("TINYSIEM_CLAUDE_API_KEY not set")
    import anthropic
    return anthropic.Anthropic(api_key=settings.tinysiem_claude_api_key)


def generate_parser(log_sample: str) -> str:
    client = _get_client()
    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2048,
        system=_PARSER_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": f"Generate a decoder YAML for this log sample:\n\n{log_sample}"}],
    )
    return response.content[0].text.strip()


def generate_rule(description: str, source: str) -> str:
    client = _get_client()
    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        system=_RULE_SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": f"Source: {source}\n\nGenerate a detection rule for: {description}",
        }],
    )
    return response.content[0].text.strip()

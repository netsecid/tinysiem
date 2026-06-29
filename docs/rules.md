# Detection Rules

Rules tell TinySIEM when to fire an alert. Each rule is a YAML file in `app/rules/rules/`. They are loaded at startup and evaluated against every ingested event.

---

## YAML Format — Common Fields

```yaml
name: http-404-spike         # unique identifier (kebab-case)
severity: medium             # low | medium | high | critical
source: nginx                # must match a parser's source field; use "*" for all sources
mitre_tactic: "Discovery"    # optional
mitre_technique: "T1595"     # optional
condition:
  type: threshold            # threshold | field_match | correlation
  # ... condition-specific fields below
```

---

## Condition Type: `field_match`

Fires once on any event where the field matches the value. No counting, no window.

```yaml
name: nginx-http-500-error
severity: high
source: nginx
condition:
  type: field_match
  field: status_code         # any normalized field name
  value: 500
  operator: eq               # eq | neq | gt | gte | lt | lte | contains
mitre_tactic: "Impact"
mitre_technique: "T1499"
```

**Supported operators:**

| Operator | Meaning |
|---|---|
| `eq` | Equals (exact match) |
| `neq` | Not equals |
| `gt` / `gte` | Greater than / greater than or equal |
| `lt` / `lte` | Less than / less than or equal |
| `contains` | Substring match |

---

## Condition Type: `threshold`

Fires when a field-matched event occurs at least `threshold_count` times within `window_seconds`.

```yaml
name: http-404-spike
severity: medium
source: nginx
condition:
  type: threshold
  field: status_code
  value: 404
  operator: eq
  threshold_count: 10
  window_seconds: 60
mitre_tactic: "Discovery"
mitre_technique: "T1595"
```

The threshold counter is per `(rule_name, field_value)` pair — so 10 × 404s from any source triggers it, not per-IP.

**Fields eligible for threshold counting** (allowlist for SQL safety):
`source`, `source_ip`, `method`, `uri`, `status_code`, `response_size`

---

## Condition Type: `correlation`

Fires when a sequence of steps occurs from the same entity within a time window. Useful for multi-stage attack detection.

Set `source: "*"` to evaluate against events from any source.

```yaml
name: brute-force-then-success
severity: high
source: "*"
condition:
  type: correlation
  window_seconds: 300
  capture_field: source_ip    # the field that links steps together (e.g. same attacker IP)
  steps:
    - field: status_code
      value: 401
      operator: eq
      count: 5                 # must see at least 5 of these
    - field: status_code
      value: 200
      operator: eq
      count: 1                 # then at least 1 of these
mitre_tactic: "Credential Access"
mitre_technique: "T1110"
```

The correlation engine tracks state in memory. State is cleared on container restart. For production use, set a reasonable `window_seconds` to bound memory usage.

---

## Built-in Rules

| Rule | Type | Severity | Description |
|---|---|---|---|
| `http-404-spike` | threshold | medium | 10+ 404s in 60s |
| `nginx-http-500-error` | field_match | high | Any 500 response |
| `brute-force-then-success` | correlation | high | 5+ 401s followed by 200 from same IP in 5 min |

---

## Writing a Custom Rule

1. Create `app/rules/rules/custom/<name>.yaml`
2. Set a unique `name` that matches no existing rule
3. The rule is active on next ingested event — no rebuild needed

---

## AI-Assisted Generation

On the Rules page, click **Generate with AI**, describe the detection scenario in plain English, and TinySIEM will produce a working rule YAML. Requires `TINYSIEM_CLAUDE_API_KEY` to be set.

Example prompt: *"Alert when the same IP makes more than 20 POST requests to /login in 30 seconds"*

---

→ [Troubleshooting](troubleshooting.md) — common errors and fixes

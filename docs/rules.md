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

The threshold counter is scoped to the rule's own `source` (e.g. a rule with `source: nginx` only counts matching events from `nginx`) and is per `field_value`, not per-IP — so 10 × 404s from that source triggers it, regardless of which IP sent them. A rule with `source: "*"` counts matching events across all sources (no source scoping applied).

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

## Alert suppression

Add an optional `suppress_seconds` field at the rule's top level (a sibling of `condition`) to avoid repeated alerts for the same rule + source IP:

```yaml
name: my-rule
suppress_seconds: 300   # 0 disables suppression; omit to use the default
condition: ...
```

Default: `300` seconds for `threshold` rules, `0` (disabled) for `field_match` and `correlation` rules. Suppressed firings are counted and attached to the next emitted alert as `suppressed_count`.

---

## Self-Monitoring

Security-relevant audit events — failed logins, lockouts, and user/integration changes — are
mirrored into the detection pipeline as their own source, `tinysiem_internal`, alongside
whatever other logs TinySIEM ingests. This lets ordinary rules (like the built-in
`tinysiem-internal-brute-force`) alert on attacks against the SIEM itself.

Only a fixed allowlist of event types is fed through — `auth.login`, `auth.lockout`,
`user.create`/`update`/`delete`, `integration.create`/`update`/`delete` — not every audit
entry. Login outcomes map onto the existing `status_code` field so the standard threshold
engine can count them: `401` for a failed login, `200` for success, `429` for a lockout.

Threshold rules are scoped to their own `source`, so a rule with `source: tinysiem_internal`
only ever counts events from this internal feed — unrelated `401`s from a monitored
application (e.g. nginx) never contribute to it. Write your own rules against this source the
same way you'd write one for any other:

```yaml
name: my-internal-rule
source: tinysiem_internal
condition:
  type: threshold
  field: status_code
  value: 401
  operator: eq
  threshold_count: 3
  window_seconds: 120
```

---

## Built-in Rules

| Rule | Type | Severity | Description |
|---|---|---|---|
| `http-404-spike` | threshold | medium | 10+ 404s in 60s |
| `nginx-http-500-error` | field_match | high | Any 500 response |
| `brute-force-then-success` | correlation | high | 5+ 401s followed by 200 from same IP in 5 min |
| `tinysiem-internal-brute-force` | threshold | high | 5+ failed logins against TinySIEM itself in 5 min (source `tinysiem_internal`, `suppress_seconds: 900`) — see [Self-Monitoring](#self-monitoring) |

---

## Writing a Custom Rule

1. Create `app/rules/rules/custom/<name>.yaml` (or use the Rules page's create form, which does this over the API)
2. Set a unique `name` that matches no existing rule — **the YAML's `name:` field must exactly match the rule identity you create/update it under.** The server rejects a mismatch with a `422`, and rule lookups are keyed by this name, so a mismatched pair (e.g. a file whose internal `name:` doesn't match its filename) would otherwise be invisible to `GET /rules/{name}` even though the rule is loaded and active.
3. The rule is active on next ingested event — no rebuild needed

---

## Backtesting

Before trusting a threshold value or a new correlation window, click **Run Backtest** on the Rules page (or `POST /rules/{name}/backtest`, or `POST /rules/backtest` for a not-yet-saved draft) to answer "what would this rule, exactly as written, have fired on in the last N days?" against real historical events — without touching the live rule set or writing any alerts.

- `field_match` rules get an exact match count and sample events.
- `threshold` rules get fixed consecutive-window counts — an approximation of the live sliding window, close enough to sanity-check a threshold before deploying it, but not a byte-for-byte replay.
- `correlation` rules aren't backtestable yet (`{"supported": false}`) — the multi-step sequence logic isn't reproducible against a static historical window the same way.

The natural loop is: **generate (AI or by hand) → backtest → adjust the threshold → deploy.**

---

## Rule Exceptions

Instead of disabling a noisy rule entirely, add a per-rule exception for the specific field/value that's causing false positives — e.g. a monitoring probe that legitimately triggers a 404-spike rule. Exceptions require a `reason` (mandatory, for auditability) and apply to one of the same fields threshold rules can key on: `source`, `source_ip`, `method`, `uri`, `status_code`, `response_size`, `user_agent`, `referer`.

An excepted event is skipped for that rule entirely — including threshold counting — but is still ingested and searchable normally elsewhere. Manage exceptions from a rule's detail view on the Rules page, or via `GET`/`POST /rules/{name}/exceptions` and `DELETE /rules/{name}/exceptions/{id}`.

---

## MITRE ATT&CK Coverage

The Rules page's **MITRE ATT&CK Coverage** tab (`GET /rules/mitre-coverage`) shows all 14 MITRE Enterprise tactics with a technique/rule-count breakdown computed from your currently-loaded rules (built-in + custom) — a quick way to see which tactics you actually have detection coverage for versus which are still gaps, without manually cross-referencing every rule's `mitre_tactic`/`mitre_technique` tags yourself.

---

## Playbooks

A rule's YAML can carry an optional `playbook:` block — a structured list of response steps an analyst should work through when this rule fires (e.g. "check source IP reputation", "review affected account's recent activity", "escalate if X"). Playbooks can be hand-written directly in the rule YAML, or AI-generated (`POST /rules/{name}/playbook/generate`) from the rule's condition and MITRE tags.

When an alert fires and gets escalated into a case, the case's **Playbook** tab shows the rule's steps and lets the analyst check them off (`POST /cases/{case_id}/playbook/steps`) with an optional note per step — turning a static YAML checklist into a per-incident, per-analyst record of what was actually done. A playbook can also be **refined** for one specific case (`POST /cases/{case_id}/playbook/refine`) — the AI provider adjusts the generic steps using that alert's actual context (source IP, affected user, etc.) rather than leaving them generic.

---

## AI-Assisted Generation

On the Rules page, click **Generate with AI**, describe the detection scenario in plain English, and TinySIEM will produce a working rule YAML. Requires a provider to be configured under Settings → AI Config.

Example prompt: *"Alert when the same IP makes more than 20 POST requests to /login in 30 seconds"*

---

→ [Troubleshooting](troubleshooting.md) — common errors and fixes

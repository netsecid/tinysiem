# Playbook & Triage Design

**Date:** 2026-07-02  
**Status:** Approved for implementation  
**Target version:** v1.3

---

## Overview

Add structured triage playbooks to detection rules. Each rule optionally carries a `playbook:` block defining step-by-step investigation guidance with SOAR-ready action metadata. Playbooks are AI-generated (admin-reviewed), snapshotted into alerts at fire time for forensic accuracy, surfaced in a dedicated Case "Playbook" tab, and enriched at triage time by an optional AI situational refinement call.

---

## Goals

- Give analysts a consistent, rule-specific investigation checklist inside each case
- Preserve the playbook that was active when an alert fired (forensic audit trail)
- Enable future SOAR automation by defining structured step actions now
- Reduce cognitive load: AI generates the first draft, humans edit and own it
- Keep all playbook state version-controlled alongside the rule YAML in git

---

## Non-Goals

- SOAR action execution (steps are defined but not executed in this version)
- Playbook templates shared across multiple rules (one playbook per rule for now)
- Auto-case creation from alerts (cases remain manually created)
- Per-step SLA timers or escalation automation

---

## Rule YAML Schema Extension

`playbook:` is an optional top-level key. Its absence is valid — rules without playbooks work exactly as before.

```yaml
name: nginx-http-404-spike
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
playbook:
  summary: "Investigate potential path/resource enumeration from a single IP"
  steps:
    - id: check_ip_rep
      name: "Check source IP reputation"
      action: lookup_threat_intel
      auto: false
      notes: "Query GreyNoise or AbuseIPDB — known scanner? CDN egress? Tor exit?"
    - id: query_24h
      name: "Pull all events from this IP over 24h"
      action: query_events
      params:
        filter: "source_ip={source_ip}"
        window_seconds: 86400
      auto: true
    - id: check_baseline
      name: "Compare against baseline for this IP/hour bucket"
      action: check_baseline
      auto: true
    - id: escalate
      name: "Escalate to high if >3 distinct URIs probed"
      action: update_severity
      params:
        severity: high
      auto: false
      notes: "Pattern of distinct paths = enumeration; single path = fuzzing"
    - id: block_or_close
      name: "Block IP at WAF or close as false positive"
      action: block_ip
      auto: false
      notes: "If confirmed scanner: block. If Cloudflare/known CDN: close as false positive."
```

### Step field reference

| Field | Required | Description |
|---|---|---|
| `id` | yes | Unique slug within this playbook (snake_case) |
| `name` | yes | Human-readable step label |
| `action` | no | SOAR hook name (not executed yet — reserved for future runner) |
| `auto` | no | `true` = future SOAR runner may execute without analyst input |
| `params` | no | Key/value inputs for the action; `{source_ip}` interpolates from alert |
| `notes` | no | Analyst guidance, rendered below the step name |

### Validation rules (enforced at `PUT /rules/{name}`)

- Each step must have `id` and `name`
- `id` values must be unique within the playbook
- `playbook` is always optional — rules without it are valid

---

## Data Flow

```
Rule YAML (playbook: block, git-versioned)
  │
  ▼ write_alert() — snapshots rule["playbook"] into alert JSONL record
Alert JSONL  { alert_id, rule_name, severity, ..., "playbook": { summary, steps } }
  │
  ▼ analyst creates case, links alert
Case  →  GET /cases/{id}/playbook
           reads playbook from linked alert snapshot(s)
           merges with case_playbook_steps (completion state)
  │
  ▼ analyst works through steps, checks them off
case_playbook_steps  { id, case_id, rule_name, step_id, completed_by, completed_at, note }
  │
  ▼ optional: analyst clicks "AI Refinement"
POST /cases/{id}/playbook/refine  →  ephemeral situational note from Claude
```

The alert snapshot is the forensic record: it preserves the exact playbook guidance that was in effect at alert-fire time, independent of subsequent rule edits.

---

## Database

### New table: `case_playbook_steps`

```sql
CREATE TABLE case_playbook_steps (
    id           VARCHAR PRIMARY KEY,
    case_id      VARCHAR NOT NULL,
    rule_name    VARCHAR NOT NULL,
    step_id      VARCHAR NOT NULL,
    completed_by VARCHAR NOT NULL,
    completed_at TIMESTAMP NOT NULL,
    note         VARCHAR
)
-- No CREATE INDEX — DuckDB 1.1.3 UPDATE constraint applies
-- Use DELETE + INSERT pattern for any updates (e.g. editing a completion note)
```

One row = one completed step in one case. Unchecking deletes the row. `rule_name` scopes completions when a case links alerts from multiple different rules.

---

## API Endpoints

### Rules router (`app/rules/router.py`)

**`POST /rules/{name}/playbook/generate`** — admin only

Calls `generate_playbook(rule, actor)` and returns the suggested playbook as a dict. Does **not** auto-save. Admin reviews output in the UI, edits if needed, then saves via the existing `PUT /rules/{name}` with the full updated YAML.

```json
// Response
{
  "playbook": {
    "summary": "...",
    "steps": [ ... ]
  },
  "model": "claude-sonnet-4-6",
  "prompt_tokens": 812,
  "completion_tokens": 340
}
```

### Cases router (`app/cases/router.py`)

**`GET /cases/{id}/playbook`** — analyst+

Returns merged playbooks from all linked alerts plus current step completion state. If no linked alerts have a playbook, returns `{ "playbooks": [] }`.

```json
{
  "playbooks": [
    {
      "rule_name": "nginx-http-404-spike",
      "summary": "Investigate path enumeration from a single IP",
      "steps": [
        {
          "id": "check_ip_rep",
          "name": "Check source IP reputation",
          "action": "lookup_threat_intel",
          "auto": false,
          "notes": "Query GreyNoise or AbuseIPDB...",
          "completed": true,
          "completed_by": "analyst1",
          "completed_at": "2026-07-02T14:32:00Z",
          "completion_note": "Confirmed Shodan scanner"
        },
        {
          "id": "query_24h",
          "name": "Pull all events from this IP over 24h",
          "action": "query_events",
          "auto": true,
          "completed": false
        }
      ]
    }
  ]
}
```

**`POST /cases/{id}/playbook/steps`** — analyst+

Mark a step complete.

```json
// Request body
{
  "rule_name": "nginx-http-404-spike",
  "step_id": "check_ip_rep",
  "note": "Confirmed Shodan scanner"   // optional
}
```

Returns `201` with the created step record. Idempotent: if the step is already complete, returns the existing record with `200`.

**`DELETE /cases/{id}/playbook/steps/{step_id}?rule_name={rule_name}`** — analyst+

Uncheck a step. `step_id` here is the YAML slug (e.g. `check_ip_rep`), not the DB row UUID. `rule_name` query param is required to scope the deletion when multiple playbooks are active. Deletes the matching row from `case_playbook_steps`. Returns `204`.

**`POST /cases/{id}/playbook/refine`** — analyst+

AI situational refinement. Ephemeral — not stored, not cached.

```json
// Request body
{
  "alert_id": "uuid-of-the-alert-to-refine-against"
}
```

When a case has multiple linked alerts, the analyst selects which alert's event data to use as the refinement context. The playbook steps are always taken from that alert's snapshot.

```json
// Response
{
  "refinement": "The source IP 203.0.113.4 has hit 47 distinct URIs in the last 6 hours, well above the z-score baseline of 3.2 for this hour bucket. Steps check_ip_rep and query_24h should be prioritised — the URI pattern suggests automated enumeration targeting /wp-admin and /phpmyadmin, typical of opportunistic scanning rather than a targeted attack. If GreyNoise confirms scanner classification, closing as false positive is reasonable; otherwise escalate and block.",
  "model": "claude-sonnet-4-6",
  "prompt_tokens": 1104,
  "completion_tokens": 128
}
```

Logged to the `ai_calls` audit table (`event_type: "playbook.refine"`).

---

## AI Components (`app/ai/enrichment.py`)

### `generate_playbook(rule: dict, actor: str) -> dict`

Context assembled:

1. Rule YAML (detection logic, MITRE tactic/technique)
2. Active event sources (`duckdb_store.get_event_sources()`)
3. Active integrations (query `integrations` table — knows if AWS CloudTrail / Google Workspace is connected)
4. Case resolution history for this rule over the last 90 days: alert count + breakdown of `true_positive / false_positive / benign / undetermined`
5. Existing `playbook:` block if present (so AI refines rather than overwrites)

System prompt instructs Claude to produce a structured playbook with SOAR-ready step fields, tailored to the org's active sources and historical resolution patterns.

Returns `{ "playbook": { "summary": ..., "steps": [...] }, "model": ..., "prompt_tokens": N, "completion_tokens": N }`.

### `refine_playbook(case_id: str, alert_id: str, actor: str) -> dict`

Context assembled:

1. Alert record (rule_name, severity, source_ip, triggered_at, playbook snapshot)
2. Originating event (raw log truncated to 2000 chars, parsed fields) — same as `explain_alert`
3. Completed steps so far from `case_playbook_steps`
4. Baseline data for this source_ip if available

System prompt: *"Given the playbook steps and what is known about this specific alert, write a concise situational note (3–5 sentences) telling the analyst what to prioritise and flagging anything anomalous about this event compared to the generic playbook guidance. Be specific: name the IP, URI, count, or timestamp where relevant."*

Returns `{ "refinement": "...", "model": ..., "prompt_tokens": N, "completion_tokens": N }`.

---

## UI Changes

### Rules UI — "Generate Playbook" button

Location: rule detail panel in Configuration → Parsers & Rules (admin only, same auth gate as existing "Generate Rule" button).

Behaviour:
1. Admin clicks "Generate Playbook" on a rule that has a condition but no playbook (or to regenerate)
2. Spinner while `POST /rules/{name}/playbook/generate` runs
3. Result rendered in an editable textarea showing the playbook YAML block
4. Admin edits if needed → "Save" merges the playbook into the full rule YAML and calls `PUT /rules/{name}`
5. Existing playbook (if any) shown alongside so admin can compare before overwriting

### Case detail — "Playbook" tab

Location: third tab in the case detail panel, after Comments and Linked Alerts.

Behaviour:
- Tab badge shows completion count: "Playbook (2/5)" 
- Each playbook section is headed by its `rule_name`
- Steps render as a checklist: checkbox | step name | action badge (`auto` steps shown with a ⚡ icon) | notes (collapsed, expand on click)
- Checking a step calls `POST /cases/{id}/playbook/steps` — on success, shows `completed_by` + `completed_at` inline
- Unchecking calls `DELETE /cases/{id}/playbook/steps/{step_id}?rule_name=...`
- "AI Refinement" button at the top of the tab (one per playbook section if multiple rules). On click: calls `POST /cases/{id}/playbook/refine`, shows result in a highlighted panel above the steps. Ephemeral — dismissed on tab change.
- If case has no linked alerts with playbooks: tab shows "No playbook — link an alert from a rule that has a playbook, or add one via Configuration → Rules."

---

## Testing

- `test_playbook_generate` — POST generate returns valid playbook shape (mocked Claude)
- `test_playbook_step_complete` — POST step creates row; GET playbook shows completed=true
- `test_playbook_step_uncheck` — DELETE step removes row; GET playbook shows completed=false
- `test_playbook_step_idempotent` — POST same step twice returns 200 on second call
- `test_playbook_multi_rule` — case with two alerts from different rules returns two playbook sections, step completions scoped correctly by rule_name
- `test_alert_snapshot` — write_alert with a rule that has a playbook embeds playbook in the JSONL record
- `test_alert_snapshot_no_playbook` — write_alert with a rule without playbook omits the field (no KeyError)
- `test_playbook_refine` — POST refine returns refinement string (mocked Claude)
- `test_rule_validation_playbook` — step missing `id` or `name` returns 422; duplicate step ids return 422

---

## File Changelist

| File | Change |
|---|---|
| `app/rules/rules/*.yaml` | Add `playbook:` blocks to existing rules |
| `app/alerts/file_writer.py` | Snapshot `rule.get("playbook")` into alert record |
| `app/rules/router.py` | `POST /rules/{name}/playbook/generate` endpoint; playbook validation in `_validate_rule_yaml` |
| `app/cases/router.py` | `GET /cases/{id}/playbook`, `POST .../steps`, `DELETE .../steps/{step_id}`, `POST .../playbook/refine` |
| `app/cases/store.py` | `create_case_playbook_steps` table DDL; `complete_step`, `uncomplete_step`, `get_completed_steps` functions |
| `app/ai/enrichment.py` | `generate_playbook()`, `refine_playbook()` functions |
| `app/storage/duckdb_store.py` | Add `case_playbook_steps` table creation to DB init |
| `ui/cases.html` | Playbook tab with checklist UI, AI Refinement button |
| `ui/configuration.html` | "Generate Playbook" button in rule detail panel |
| `app/tests/test_playbook.py` | All new tests listed above |

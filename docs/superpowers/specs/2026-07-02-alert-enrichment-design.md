# Alert Enrichment & Case Escalation Design

**Date:** 2026-07-02  
**Status:** Approved for implementation  
**Target version:** v1.3

---

## Overview

The current alert detail modal shows metadata fields but is a dead end — the analyst cannot see the log(s) that triggered the alert, the rule condition that fired, or escalate the alert to a case without leaving the screen. This feature adds three things: a tabbed modal structure (Alert | Logs | Rule), a context-aware Logs tab that either shows the triggering event inline or redirects to a pre-filtered Events view, and footer escalation buttons that detect existing case linkage.

---

## Goals

- Let analysts judge alert validity without leaving the Alerts page
- Surface the exact log(s) that caused the alert to fire
- Show the rule condition in plain language so the analyst understands what triggered it
- Provide one-click escalation to a new case or an existing open case
- Show whether an alert is already linked to a case before the analyst acts

---

## Non-Goals

- Alert status workflow changes (open/acknowledged/closed triage fields already exist)
- Bulk escalation (one alert at a time for now)
- Inline event editing from the alert modal
- New case auto-creation without analyst confirmation

---

## Modal Tab Structure

The alert detail modal gains three tabs. Data is fetched lazily — each tab loads on first click, not on modal open.

```
┌─────────────────────────────────────────────────────────┐
│ nginx-http-404-spike               [MEDIUM]         [×] │
│ 2026-07-01 14:50:09                                     │
│                                                         │
│ [Alert] [Logs] [Rule]                                   │
│ ─────────────────────────────────────────────────────── │
│  (tab content)                                          │
│                                                         │
│                                                         │
│ ─────────────────────────────────────────────────────── │
│ [In case: Case-042 →]  [New Case]  [Add to Case]        │
│ [Copy as JSON]                                          │
└─────────────────────────────────────────────────────────┘
```

### Alert tab (current behaviour, unchanged)

All existing fields: `alert_id`, `triggered_at`, `rule_name`, `severity`, `mitre_tactic`, `mitre_technique`, `event_id`, `source_ip`, `status`, `notes`, `assigned_to`, `triage_updated_at`, `triage_updated_by`.

### Logs tab

Behaviour depends on the rule's condition type, determined from the Rule tab data (fetched first if not yet loaded):

**`field_match` rule** — single triggering event:
- Calls `GET /events/{event_id}` using the `event_id` from the alert record
- Renders raw log in a monospace `<pre>` block (full text, no truncation)
- Renders parsed fields below in the same key/value grid as the Alert tab
- If the event is not found (retention expired): shows "Event {event_id} is no longer in the database (may have been archived)"

**`threshold` or `correlation` rule** — window of events:
- Shows a context summary box:
  ```
  This rule fired on a window of events, not a single log.
  Condition: status_code = 404  ·  10+ hits in 60s  ·  source: nginx
  Time window: 2026-07-01 14:49:09 → 2026-07-01 14:50:09
  Source IP: 207.46.13.5
  ```
- "View triggering logs →" button constructs a client-side URL and navigates to:
  ```
  /ui/events.html?source_ip=207.46.13.5&status_code=404
                 &start=<triggered_at - window_seconds>
                 &end=<triggered_at>
  ```
  The Events page opens pre-filtered showing only the relevant window for that IP and condition. No new backend endpoint — URL construction is client-side from the alert record + rule condition data.

  **Condition field → Events URL param mapping** (client-side):

  | Rule `field` | Events param |
  |---|---|
  | `status_code` | `?status_code={value}` |
  | `source_ip` | `?source_ip={value}` |
  | `uri` | `?uri={value}` |
  | `method` | `?method={value}` |
  | anything else (`raw`, `user_agent`, etc.) | `?q={value}` (full-text fallback) |

**Loading state:** spinner while fetching. If `GET /events/{id}` returns 404, fall through to the "not in database" message. If `GET /rules/{name}` fails (rule deleted), show "Rule definition not available — rule may have been deleted after this alert fired."

### Rule tab

Fetched via `GET /rules/{rule_name}` (existing endpoint, analyst role).

Two sections:

**Human-readable condition summary** (always shown):

| Rule type | Rendered as |
|---|---|
| `field_match` | "Fires when `{field}` {operator} `{value}` on source `{source}`" |
| `threshold` | "Fires when `{field}` {operator} `{value}` appears {threshold_count}+ times in {window_seconds}s from the same source IP" |
| `correlation` | "Fires on a multi-step sequence: {step 1 description} → {step 2 description} within {window_seconds}s" |

MITRE tactic and technique shown as chips below the summary.

**Raw YAML** (collapsible, collapsed by default):
Full rule YAML in a `<pre>` block. Useful for admins who want to see the exact condition. Collapsed by default to keep the tab clean for analysts.

If the rule has a `playbook:` block, a "View Playbook →" chip links to the Rule's playbook section (relevant once playbook feature ships).

---

## Footer: Case Escalation

On modal open, the UI calls `GET /alerts/{alert_id}/cases` to check existing linkage. Footer renders accordingly:

**Not linked to any case:**
```
[Copy as JSON]                    [New Case]  [Add to Case]
```

**Already linked to one or more cases:**
```
[Copy as JSON]  [In case: Case-042 →]  [Add to another case]
```
The case title is a link that opens the case detail page. If linked to multiple cases, shows "In 3 cases →" with a dropdown listing them.

### "New Case" flow

1. Analyst clicks "New Case"
2. A mini-form appears inline below the footer (not a new page):
   - **Title**: pre-filled as `Alert: {rule_name} from {source_ip}` (editable)
   - **Severity**: pre-filled from alert severity (editable dropdown)
   - **Assignee**: empty (optional)
3. Analyst clicks "Create" → calls `POST /cases` with the form data
4. On success: calls `POST /cases/{new_id}/alerts` to link the alert automatically
5. Footer updates to show "In case: [new case title] →". A toast shows "Case created — [View Case]" with a link.

### "Add to Case" flow

1. Analyst clicks "Add to Case" (or "Add to another case")
2. An inline search dropdown appears: input field + list of open cases fetched from `GET /cases?status=open&limit=20`
3. Analyst types to filter by case title, selects one
4. Calls `POST /cases/{id}/alerts` with `{ "alert_ids": [alert_id] }`
5. Footer updates to reflect new linkage. Toast: "Alert linked to [Case Title]"

---

## New Backend Endpoints

### `GET /events/{event_id}` — analyst+

Added to `app/events/router.py`. Calls the existing `duckdb_store.get_event_by_id()` (already used by `enrichment.py`).

```json
// Response — 200
{
  "id": "897f8f07-0a4e-4711-aae2-9d8cb37553c4",
  "source": "nginx",
  "ingested_at": "2026-07-01T14:50:09Z",
  "event_time": "2026-07-01T14:50:09Z",
  "source_ip": "207.46.13.5",
  "method": "GET",
  "uri": "/admin/login",
  "status_code": 404,
  "response_size": 512,
  "user_agent": "Mozilla/5.0 (compatible; bingbot/2.0)",
  "referer": null,
  "raw": "207.46.13.5 - - [01/Jul/2026:14:50:09 +0000] \"GET /admin/login HTTP/1.1\" 404 512 \"-\" \"Mozilla/5.0 (compatible; bingbot/2.0)\"",
  "extra": null
}
// 404 if event_id not found
```

### `GET /alerts/{alert_id}/cases` — analyst+

Added to `app/alerts/router.py`. Calls a new `get_cases_for_alert(alert_id)` helper in `app/cases/store.py` that queries `case_alerts JOIN cases`.

```json
// Response — always 200 (empty list if not linked)
{
  "cases": [
    {
      "case_id": "abc-123",
      "title": "Scanning from 207.46.13.5",
      "status": "investigating",
      "severity": "medium",
      "linked_at": "2026-07-01T15:02:00Z"
    }
  ]
}
```

---

## Files Changed

| File | Change |
|---|---|
| `app/events/router.py` | Add `GET /events/{event_id}` — thin wrapper around existing `get_event_by_id()` |
| `app/alerts/router.py` | Add `GET /alerts/{alert_id}/cases` endpoint |
| `app/cases/store.py` | Add `get_cases_for_alert(alert_id) -> list[dict]` — queries `case_alerts JOIN cases` |
| `ui/alerts.html` | Tabbed modal (Alert \| Logs \| Rule), lazy fetch per tab, footer escalation with case linkage, inline New Case form, Add to Case search dropdown |

---

## Testing

- `test_get_event_by_id` — returns 200 with full event fields for known ID; 404 for unknown
- `test_get_alert_cases_linked` — alert linked to a case returns that case in the list
- `test_get_alert_cases_unlinked` — alert not in any case returns `{ "cases": [] }`
- `test_get_alert_cases_multi` — alert linked to two cases returns both
- `get_cases_for_alert` unit test — verifies JOIN query returns correct case fields

UI behaviour (manual verification):
- Logs tab: `field_match` alert → event raw log renders; `threshold` alert → context summary + redirect link with correct query params
- Rule tab: human-readable condition renders for each condition type; YAML block collapses/expands
- Footer: "New Case" creates case, links alert, updates footer; "Add to Case" search filters cases, links alert; existing linkage shows case title link

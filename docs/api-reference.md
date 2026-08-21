# API Reference

All endpoints except `GET /health` require a valid credential passed as `Authorization: Bearer <token>`.

Two token types are accepted:
- **API key** (`TINYSIEM_API_KEY` from `.env`) — as of v1.4, scoped to `/ingest/raw`, `/ingest/file`, and `/ingest/beats` only. It is rejected on every other endpoint (401). It does not carry a role — it's a fixed credential for machine-to-machine log shipping, not an `admin` identity. Humans or scripts needing any other endpoint must obtain a JWT via `POST /auth/login`.
- **JWT** (obtained from `POST /auth/login`) — for all UI and user-context flows. Encodes `sub` (user ID), `username`, `role`, and `exp`. An `admin`+ or `superadmin` JWT also works on the ingest endpoints above, in addition to the API key.

Role hierarchy: `analyst` < `admin` < `superadmin`. A higher role grants all lower-role access.

---

## Authentication

### `POST /auth/login`
Authenticate and receive a JWT. No auth required.

**Request:**
```json
{ "username": "admin", "password": "your-password" }
```

**Response:**
```json
{
  "access_token": "<jwt>",
  "token_type": "bearer",
  "username": "admin",
  "role": "superadmin",
  "expires_in": 86400,
  "must_change_password": false
}
```

JWT expiry defaults to 24 hours (`TINYSIEM_JWT_EXPIRY_HOURS`).

`must_change_password` is `true` when the account still has a forced password-change flag set (e.g. the initial superadmin created with the default `admin` password) — the client should route the user to change their password before allowing further use, since the account's current password is a known/default value until they do.

---

### `GET /auth/me`
Returns the currently authenticated user's profile. Requires `analyst` role.

**Response:**
```json
{ "user_id": "uuid", "username": "admin", "role": "superadmin" }
```

---

### `POST /auth/logout`
Revokes every existing token for the current user by bumping their `token_epoch` — any JWT issued before this call (including the one used to call it) stops working immediately. Requires `analyst` role.

**Response:**
```json
{ "status": "ok" }
```

---

### `POST /auth/change-password`
Change the current user's own password. Requires `analyst` role — this is one of the three endpoints still reachable while `must_change_password` is set (the others are `GET /auth/me` and this endpoint itself).

**Request:**
```json
{ "current_password": "old-password", "new_password": "a-new-12-char-or-longer-password" }
```

**Response:**
```json
{ "access_token": "<new jwt>", "token_type": "bearer" }
```

Returns a **new** token with the bumped `token_epoch` so the caller isn't logged out by their own password change. The old token stops working. Returns `401` if `current_password` is wrong, `422` if `new_password` is under 12 characters.

---

## Health

### `GET /health`
No auth required.

**Response:**
```json
{
  "status": "ok",
  "version": "0.9.0",
  "listeners": {
    "syslog_udp": { "enabled": true, "port": 5140 },
    "syslog_tcp": { "enabled": true, "port": 5141 },
    "beats_http": { "enabled": true, "path": "/ingest/beats" },
    "syslog_dropped": { "cidr": 0, "size": 0 }
  }
}
```

`syslog_dropped` counts messages rejected by `TINYSIEM_SYSLOG_ALLOW_CIDRS` (`cidr`) or `TINYSIEM_SYSLOG_MAX_BYTES` (`size`) since container start.

---

## Ingest

### `POST /ingest/raw`
Ingest a single log line. Accepts the API key or an `admin`+ JWT.

**Request:**
```json
{ "source": "nginx", "raw": "192.168.1.1 - - [01/Jul/2026:10:00:00 +0000] \"GET /api HTTP/1.1\" 200 512 \"-\" \"curl\"" }
```

**Response:**
```json
{ "status": "ok", "event_id": "<uuid>" }
```

Returns `422` if no decoder matches the source + raw combination.

---

### `POST /ingest/file`
Bulk ingest from an uploaded text file (one log line per line). Accepts the API key or an `admin`+ JWT.

**Query params:** `source` (required)

**Request:** `multipart/form-data` with field `file`.

**Response:**
```json
{ "status": "ok", "processed": 450, "failed": 2 }
```

---

### `POST /ingest/beats`
Beats-compatible bulk ingest (Elasticsearch ndjson format). Accepts Filebeat / Winlogbeat / Metricbeat output directly. Accepts the API key or an `admin`+ JWT.

Source resolved from: `fields.source` → `agent.type` → `"beats"`.

Returns `503` if `TINYSIEM_BEATS_ENABLED=false`.

---

## Events

### `GET /events`
Query stored events. Requires `analyst` role.

| Param | Type | Description |
|---|---|---|
| `source` | string | Exact match on source field |
| `source_ip` | string | Substring match on source IP |
| `status_code` | int | Exact HTTP status code |
| `status_min` / `status_max` | int | Status code range |
| `method` | string | HTTP method (case-insensitive) |
| `uri` | string | Substring match on URI |
| `q` | string | Full-text search on raw log line |
| `country_code` | string | Exact ISO 3166-1 alpha-2 country code (e.g. `ID`, `RU`) |
| `city` | string | Case-insensitive substring match on city |
| `asn` | int | Exact ASN |
| `response_size_min` / `response_size_max` | int | Response size range |
| `user_agent` / `referer` | string | Case-insensitive substring match |
| `start` / `end` | ISO 8601 | Time window on `ingested_at` |
| `limit` | int | Max results (default 100, max 1000) |
| `offset` | int | Pagination offset |
| `format` | string | Set to `csv` to stream a CSV instead of JSON — honors every filter above, capped at 10,000 rows, with `Content-Disposition: attachment` |

Note: `source_ip`, `uri`, `q`, `user_agent`, `referer`, and `city` use `LIKE`/`ILIKE` matching. SQL metacharacters (`%`, `_`) in filter values are escaped and treated literally. (The AI home search uses **exact** IP matching under the hood via the same query layer — see [AI](#ai).)

**Response:**
```json
{
  "total": 1024,
  "events": [
    {
      "id": "uuid",
      "source": "nginx",
      "ingested_at": "2026-07-01T10:00:00",
      "event_time": "2026-07-01T10:00:00",
      "source_ip": "10.0.0.1",
      "method": "GET",
      "uri": "/api/login",
      "status_code": 200,
      "response_size": 512,
      "user_agent": "Mozilla/5.0 ...",
      "raw": "<original log line>"
    }
  ]
}
```

---

### `GET /events/facets`
Returns value counts for sidebar facets. Accepts the same filter params as `GET /events`.

**Response:**
```json
{
  "source":      [{ "value": "nginx", "count": 1024 }],
  "method":      [{ "value": "GET", "count": 800 }],
  "status_class":[{ "value": "s2xx", "count": 700 }],
  "source_ip":   [{ "value": "10.0.0.1", "count": 50 }]
}
```

---

### `GET /events/histogram`
Time-bucketed event counts for the chart. Requires `analyst` role.

| Param | Type | Description |
|---|---|---|
| `start` / `end` | ISO 8601 | Time window (required) |
| `buckets` | int | Number of buckets, 10–200 (default 48) |

**Response:** `[{ "ts": 1751376000000, "count": 42 }, ...]`
`ts` is a Unix millisecond epoch for direct use by chart libraries.

---

## Alerts

### `GET /alerts`
Query alerts. Requires `analyst` role.

| Param | Type | Description |
|---|---|---|
| `severity` | string | `low`, `medium`, `high`, `critical` |
| `rule_name` | string | Exact match |
| `source_ip` | string | Substring match |
| `status` | string | Triage status: `open`, `investigating`, `resolved` |
| `mitre_tactic` | string | Substring match on MITRE ATT&CK tactic (e.g. `defense-evasion`, `credential-access`) |
| `mitre_technique` | string | Substring match on MITRE ATT&CK technique (e.g. `T1110`, `T1566`) |
| `q` | string | Full-text on rule name and summary |
| `start` / `end` | ISO 8601 | Window on `triggered_at` |
| `limit` / `offset` | int | Pagination |
| `format` | string | Set to `csv` to stream a CSV instead of JSON — honors every filter above, capped at 10,000 rows, with `Content-Disposition: attachment` |

**Response:**
```json
{
  "total": 12,
  "alerts": [
    {
      "alert_id": "uuid",
      "triggered_at": "2026-07-01T10:00:00Z",
      "rule_name": "http-404-spike",
      "severity": "medium",
      "mitre_tactic": "Discovery",
      "mitre_technique": "T1595",
      "event_id": "uuid",
      "source_ip": "10.0.0.1",
      "summary": "10 events matching status_code=404 in 60s",
      "suppressed_count": 0,
      "triage_status": "open",
      "notes": "",
      "assigned_to": ""
    }
  ]
}
```

`suppressed_count` is the number of times this rule fired for the same `(rule_name, source_ip)` and was suppressed before this alert was emitted — see [Rules → Alert suppression](rules.md#alert-suppression).

---

### `GET /alerts/facets`
Returns `{ severity: [...], rule_name: [...] }` counts. Same filters as `GET /alerts`.

### `PATCH /alerts/{alert_id}`
Update triage data. Requires `analyst` role.

```json
{ "triage_status": "investigating", "notes": "Confirmed brute force from 10.0.0.1", "assigned_to": "alice" }
```

### `GET /alerts/triage-summary`
Returns `{ open: N, investigating: N, resolved: N }`.

---

## Cases

Case management for multi-alert (and multi-event) incidents. `analyst` role can create, read, update, comment, and link/unlink alerts or events; `DELETE /cases/{case_id}` requires `admin`.

### `GET /cases/facets`
Facet counts (status, severity, assignee, resolution) for building filter UIs. Requires `analyst` role.

### `GET /cases`

| Param | Type | Description |
|---|---|---|
| `status` | string | `open`, `investigating`, `resolved` |
| `severity` | string | `low`, `medium`, `high`, `critical` |
| `assignee` | string | Username filter |
| `q` | string | Full-text on title and description |
| `start` / `end` | ISO datetime | Filter by `created_at` |
| `limit` / `offset` | int | Pagination |

**Response:**
```json
{
  "total": 3,
  "cases": [
    {
      "case_id": "uuid",
      "title": "Brute force attempt from 10.0.0.5",
      "description": "15 failed logins over 2 minutes",
      "severity": "high",
      "status": "investigating",
      "resolution": null,
      "assignee": "alice",
      "created_by": "admin",
      "created_at": "2026-07-01T10:00:00Z",
      "updated_at": "2026-07-01T10:05:00Z",
      "closed_at": null,
      "mitre_tactic": "Credential Access",
      "mitre_technique": "T1110",
      "tags": ["brute-force"]
    }
  ]
}
```

### `POST /cases`
Create a case. Requires `analyst` role. `alert_ids` is optional — pass initial alert IDs to link on creation (there's no equivalent `event_ids` param on create; link events afterward via `POST /cases/{case_id}/events`).

```json
{
  "title": "Suspicious exfiltration",
  "description": "Large outbound transfers to unknown IP",
  "severity": "critical",
  "assignee": "alice",
  "mitre_tactic": "Exfiltration",
  "mitre_technique": "T1041",
  "tags": ["exfil"],
  "alert_ids": ["uuid1"]
}
```

### `GET /cases/{case_id}`
Get a single case, hydrated with its full linked-alert and linked-event details (`alerts`, `linked_alert_ids`, `linked_event_ids`) and its comment/timeline history (`comments`). Requires `analyst` role.

### `PATCH /cases/{case_id}`
Update title, description, severity, status, assignee, MITRE tags, or tags. Requires `analyst` role. Closing a case (`status: "resolved"`) requires a `resolution` — one of `true_positive`, `false_positive`, `benign`, `undetermined`.

```json
{ "status": "resolved", "resolution": "false_positive" }
```

### `DELETE /cases/{case_id}`
Delete a case (and its links/comments/playbook steps). Requires `admin` role.

### Comments
- `POST /cases/{case_id}/comments` `{ "body": "..." }` — add a comment (analyst)
- `PUT /cases/{case_id}/comments/{comment_id}` `{ "body": "..." }` — edit your own comment (or any comment as admin+); system comments can't be edited
- `DELETE /cases/{case_id}/comments/{comment_id}` — same ownership rule as edit

System comments (e.g. "Alert X linked by admin") are inserted automatically on case creation and every link/unlink/status-change action, giving each case a readable audit timeline alongside the analyst's own notes.

### Linking alerts and events
- `POST /cases/{case_id}/alerts` `{ "alert_ids": ["uuid1", "uuid2"] }` → `{ "linked": [...] }` (analyst)
- `DELETE /cases/{case_id}/alerts/{alert_id}` (analyst)
- `POST /cases/{case_id}/events` `{ "event_ids": ["uuid1"] }` → `{ "linked": [...] }` (analyst)
- `DELETE /cases/{case_id}/events/{event_id}` (analyst)

Both the Events and Alerts UI pages expose "New Case" / "Add to Case" buttons on each row that call these endpoints directly — an analyst can escalate straight from a raw event or a fired alert without a separate case-creation step.

### Playbook
- `GET /cases/{case_id}/playbook` — completed steps for this case, cross-referenced against the rule's embedded `playbook:` YAML (analyst)
- `POST /cases/{case_id}/playbook/steps` `{ "rule_name", "step_id", "note" }` — mark a playbook step complete, with an optional note (analyst)
- `DELETE /cases/{case_id}/playbook/steps/{step_id}` — unmark a step (analyst)
- `POST /cases/{case_id}/playbook/refine` `{ "alert_id" }` — ask the configured AI provider to refine the rule's playbook using this specific alert's context (analyst; 503 if no AI provider is configured)

---

## Entities

### `GET /entities/ip/{value}`
Analyst+. Read-only composition of existing data for one IP: `first_seen`, `last_seen`,
`total_events`, `top_sources`/`top_methods`/`top_uris`/`top_status_codes` (facet-style),
`histogram` (hourly buckets over the last 7 days), `related_alerts` (up to 50, newest
first), `related_cases`. No new storage — this is a query composition endpoint.

---

## Watchlists

IOC watchlists match events against known-bad indicators at ingest time. A hit emits an
alert with `rule_name = "watchlist:<list_name>"`.

### `GET /watchlists`
Analyst+. Optional `?list_name=` filter. Returns `{entries: [...]}`.

### `POST /watchlists`
Admin+. Body: `{list_name, indicator_type, value, severity, note}`. `indicator_type` is
one of `ip`, `cidr`, `user_agent_substring`, `uri_substring`. Entry cap: 50,000.

### `PATCH /watchlists/{entry_id}?active=true|false`
Admin+. Toggles an entry active/inactive without deleting it.

### `DELETE /watchlists/{entry_id}`
Admin+.

### `POST /watchlists/bulk`
Admin+. Body: `{list_name, entries: [{indicator_type, value, severity, note}, ...]}`.
Returns `{created: [...], errors: [...]}` — partial success is not an error.

### `POST /watchlists/import`
Admin+. Multipart form upload (`file`) plus `?list_name=` query param. CSV columns:
`type,value,severity,note`. Returns `{created: [...], errors: [...]}`.

---

## Saved Searches

Owner-scoped — a user can only see and delete their own saved searches.

### `GET /searches?page=events|alerts`
Analyst+.

### `POST /searches`
Analyst+. Body: `{name, page, query_string}` where `query_string` is the exact
querystring produced by the Events/Alerts page's own filter-serialization (e.g.
`status_code=404&start=...&end=...`).

### `DELETE /searches/{search_id}`
Analyst+. 404 if the search isn't owned by the caller.

---

## Smart Baselines

Statistical anomaly detection. Requires `analyst` role for read; `admin` for delete.

### `GET /baselines`
List learned baseline buckets.

| Param | Type | Description |
|---|---|---|
| `source` | string | Filter by source |
| `hour_of_day` | int | 0–23 |
| `day_of_week` | int | 0–6 (0 = Monday) |

**Response:**
```json
{
  "baselines": [
    {
      "source": "nginx",
      "hour_of_day": 10,
      "day_of_week": 1,
      "mean": 120.5,
      "stddev": 18.2,
      "sample_count": 168,
      "last_updated": "2026-07-01T10:00:00Z"
    }
  ]
}
```

### `GET /baselines/violations`
List anomaly violations detected by the baseline engine.

| Param | Type | Description |
|---|---|---|
| `source` | string | Filter by source |
| `severity` | string | `low`, `medium`, `high`, `critical` |
| `acknowledged` | bool | Filter by acknowledged state |
| `start` / `end` | ISO 8601 | Time window |
| `limit` | int | Max 10 000 |
| `offset` | int | Pagination |

### `PATCH /baselines/violations/{violation_id}`
Acknowledge or un-acknowledge a violation. Requires `analyst` role.

```json
{ "acknowledged": true }
```

### `DELETE /baselines`
Clear all learned baselines for a source. Requires `admin` role.

**Query params:** `source` (required)

---

## API Integrations

Pull-based log polling from external services. Requires `admin` role.

### `GET /integrations/types`
List available integration types and their required config/credential fields.

**Response:**
```json
{
  "types": [
    {
      "integration_type": "aws_cloudtrail",
      "display_name": "AWS CloudTrail",
      "config_fields": ["region", "bucket"],
      "credential_fields": ["access_key_id", "secret_access_key"]
    },
    {
      "integration_type": "google_workspace",
      "display_name": "Google Workspace",
      "config_fields": ["customer_id", "application_name"],
      "credential_fields": ["service_account_json"]
    }
  ]
}
```

### `GET /integrations`
List all configured integrations (credentials masked to last 4 chars).

### `POST /integrations`
Create an integration. Credentials are encrypted at rest with Fernet.

```json
{
  "name": "prod-cloudtrail",
  "integration_type": "aws_cloudtrail",
  "schedule_minutes": 15,
  "config": { "region": "us-east-1", "bucket": "my-trail-bucket" },
  "credentials": { "access_key_id": "AKIA...", "secret_access_key": "..." }
}
```

Returns `503` if `TINYSIEM_MASTER_KEY` is not set.

### `GET /integrations/{integration_id}`
Get one integration. Credentials masked.

### `PATCH /integrations/{integration_id}`
Update name, schedule, or enabled state.

```json
{ "enabled": false }
```

### `DELETE /integrations/{integration_id}`
Delete an integration and all its run history.

### `POST /integrations/{integration_id}/trigger`
Manually trigger a poll immediately.

**Response:**
```json
{ "run_id": "uuid", "status": "triggered" }
```

### `GET /integrations/{integration_id}/runs`
Get run history for an integration.

| Param | Type | Description |
|---|---|---|
| `limit` | int | Default 50 |

**Response:**
```json
{
  "runs": [
    {
      "run_id": "uuid",
      "integration_id": "uuid",
      "triggered_at": "2026-07-01T10:00:00Z",
      "completed_at": "2026-07-01T10:00:05Z",
      "status": "ok",
      "events_pulled": 42,
      "events_ingested": 42,
      "error_message": null
    }
  ]
}
```

---

## Custom Dashboard

Per-user dashboard configuration. Requires `analyst` role.

### `GET /dashboard`
Get the current user's dashboard layout.

**Response:**
```json
{
  "widgets": [
    {
      "widget_id": "w1",
      "type": "event_volume",
      "title": "Event Volume (24h)",
      "config": { "hours": 24, "buckets": 48 }
    },
    {
      "widget_id": "w2",
      "type": "top_sources",
      "title": "Top Sources",
      "config": { "limit": 10 }
    }
  ]
}
```

Available `type` values: `event_volume`, `top_sources`, `top_ips`, `alert_severity`, `recent_alerts`, `case_status`, `baseline_health`.

### `PUT /dashboard`
Save the current user's dashboard layout. Body is the same shape as the `GET` response.

### `POST /dashboard/export/html`
Generate a static HTML snapshot of the dashboard for sharing or archiving.

**Response:** `text/html` content for download.

### `GET /dashboard/fidelity`
Executive "SOC pipeline" snapshot for the Detection Fidelity tab. Requires `analyst` role.

**Query params:**

| Param | Values | Default | Notes |
|---|---|---|---|
| `window` | `60`, `3600`, `86400` | `60` | Rolling window for all volume metrics. `60` = in-memory live pulse; `3600`/`86400` = DB-backed `COUNT` over the events table (in-memory counters reset on server restart, so long windows are DB-derived). Invalid values → `422`. |

**Response:**
```json
{
  "window_seconds": 3600,
  "window_label": "1h",
  "generated_at": "2026-08-21T08:00:00Z",
  "totals": {
    "events": 726,
    "events_rate": 726.0,
    "events_rate_unit": "events/hr",
    "alerts": 29,
    "alerts_rate": 29.0,
    "alerts_rate_unit": "alerts/hr"
  },
  "sources": [{"name": "sshd", "events": 137, "rate": 137.0, "status": "active", "parse_fail_count": 0}],
  "engine": {"rules_loaded": 9},
  "top_rules": [{"rule_name": "ssh-bruteforce", "count": 26}],
  "recent_alerts": [{"alert_id": "...", "rule_name": "ssh-bruteforce", "severity": "high", "triggered_at": "...Z", "source_ip": "203.0.113.7", "summary": "..."}],
  "outcomes": {
    "cases_open": 0,
    "cases_investigating": 1,
    "resolved": {"true_positive": 1, "false_positive": 0, "benign": 0, "undetermined": 0},
    "total_resolved": 1,
    "fidelity_pct": 100.0,
    "scope": "all_time"
  }
}
```

- `totals` — combined volume for the window: `events` count, `events_rate` + `events_rate_unit` (unit adapts: `eps` / `events/hr` / `events/day`), `alerts` count (from the alerts JSONL `triggered_at`), `alerts_rate` + `alerts_rate_unit` (`alerts/min` / `alerts/hr` / `alerts/day`).
- `sources[].events` / `sources[].rate` — per-source count and rate for the window; `sources[].status` — `active` / `stale` / `silent` (same logic as `GET /sources`); `sources[].parse_fail_count` — in-memory counter (live 60s pulse only).
- `engine.rules_loaded` — count of loaded rules.
- `top_rules` — top 5 rules by alert count within the window, descending (`[{"rule_name", "count"}]`).
- `recent_alerts` — last ≤10 alerts within the window, newest first (`alert_id`, `rule_name`, `severity`, `triggered_at`, `source_ip`, `summary`). Empty array when the window has no alerts (e.g. `window=60` on a quiet minute).
- `outcomes.scope` — always `all_time`: `fidelity_pct` is a detection-quality KPI and is intentionally **not** windowed. `fidelity_pct` = `100 × true_positive / (true_positive + false_positive + benign)` over **resolved** cases only; `undetermined` excluded from the denominator; `null` when no resolved cases exist (never `0`). The UI dims the KPI + shows a `low sample` tag while the denominator is < 10.

---

## Sources

### `GET /sources`
Per-source event counts and last-seen timestamps. Requires `analyst` role.

**Response:**
```json
{
  "sources": [
    {
      "source": "nginx",
      "total_events": 15234,
      "events_1h": 142,
      "events_24h": 3820,
      "last_seen": "2026-07-01T10:00:00Z",
      "status": "active"
    }
  ]
}
```

---

## Parsers

All parser endpoints require `admin` role.

| Method | Path | Description |
|---|---|---|
| `GET` | `/parsers` | List all parsers (built-in + custom) |
| `POST` | `/parsers` | Create a custom parser from YAML |
| `GET` | `/parsers/{name}` | Get parser YAML by name |
| `PUT` | `/parsers/{name}` | Update parser YAML |
| `DELETE` | `/parsers/{name}` | Delete custom parser |
| `POST` | `/parsers/{name}/test` | Test parser against a log sample |
| `POST` | `/parsers/generate` | AI-generate parser YAML from a log sample |

**Test request:**
```json
{ "raw": "192.168.1.1 - - [01/Jul/2026:10:00:00 +0000] \"GET /api HTTP/1.1\" 200 512" }
```

**Test response:**
```json
{
  "matched": true,
  "fields": { "source_ip": "192.168.1.1", "method": "GET", "status_code": 200 }
}
```

**Generate request:**
```json
{ "sample": "192.168.1.1 - - [01/Jul/2026:10:00:00 +0000] \"GET /api HTTP/1.1\" 200 512", "description": "nginx access log" }
```

Returns `503` if no AI provider is configured (see Settings → AI Config).

---

## Rules

`GET /rules`, `GET /rules/{name}`, and `GET /rules/mitre-coverage` require `analyst` role; every other endpoint requires `admin` role.

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/rules` | analyst | List all rules (built-in + custom) |
| `POST` | `/rules` | admin | Create a rule from YAML |
| `GET` | `/rules/{name}` | analyst | Get rule YAML by name |
| `PUT` | `/rules/{name}` | admin | Update rule YAML |
| `DELETE` | `/rules/{name}` | admin | Delete custom rule |
| `POST` | `/rules/generate` | admin | AI-generate rule YAML from a natural-language description |
| `POST` | `/rules/{name}/backtest` | admin | Backtest a saved rule against historical events (v1.5) |
| `POST` | `/rules/backtest` | admin | Backtest an unsaved (inline) rule (v1.5) |
| `GET` | `/rules/{name}/exceptions` | admin | List exceptions for a rule (v1.5) |
| `POST` | `/rules/{name}/exceptions` | admin | Add an exception (v1.5) |
| `DELETE` | `/rules/{name}/exceptions/{id}` | admin | Remove an exception (v1.5) |
| `GET` | `/rules/mitre-coverage` | analyst | MITRE ATT&CK tactic/technique coverage (v1.5) |

**Generate request:**
```json
{ "description": "Alert when the same IP fails login more than 5 times in 60 seconds" }
```

Returns `503` if no AI provider is configured (see Settings → AI Config).

### `POST /rules/{name}/backtest`
Admin+. Body: `{"days": 7}` (1–30). Runs the named rule's condition against historical
events. `field_match` → exact count + samples; `threshold` → fixed consecutive
windows of `window_seconds` (an approximation of the live sliding window, not an exact
replay); `correlation` → `{"supported": false}`.

### `POST /rules/backtest`
Admin+. Same as above but for an unsaved rule: body `{"yaml_text": "...", "days": 7}`.
Pairs with the AI rule generator: generate → backtest → deploy.

### `GET /rules/{name}/exceptions` / `POST` / `DELETE /rules/{name}/exceptions/{id}`
Admin+. `POST` body: `{field, value, reason}` — `field` limited to the same allowlist as
threshold-rule fields (`source`, `source_ip`, `method`, `uri`, `status_code`,
`response_size`, `user_agent`, `referer`); `reason` is mandatory. An excepted event is
skipped for that rule entirely (including threshold counting) but is still ingested and
searchable normally.

### `GET /rules/mitre-coverage`
Analyst+. Returns all 14 MITRE Enterprise tactics with technique/rule-count breakdowns
computed from currently-loaded rules (built-in + custom). Tactics with no matching rules
are included with an empty `techniques` list.

### `POST /rules/{name}/playbook/generate`
Admin+. Asks the configured AI provider to generate a structured `playbook:` block (response
steps) for the rule, based on its condition and MITRE tags. Returns the generated YAML for
review — nothing is saved until the caller writes it back via `PUT /rules/{name}`. `503` if
no AI provider is configured.

---

## AI

All AI features route through one configured provider (Settings → AI Config) — see
[Architecture → AI Layer](architecture.md#ai-layer-optional) for how the provider
abstraction works. Every endpoint below returns `503` if no provider is configured, and
`502` if the configured provider's API call itself fails.

### `GET /ai/config`
Admin+. Returns the current configuration with the API key redacted:
```json
{ "configured": true, "provider": "anthropic", "model": "claude-sonnet-4-6", "base_url": null, "has_api_key": true }
```

### `PUT /ai/config`
Admin+. Set the active provider.
```json
{ "provider": "anthropic", "model": "claude-sonnet-4-6", "base_url": null, "api_key": "sk-..." }
```
`provider` is one of `anthropic`, `openai`, `deepseek`, `custom`. `model` is a free-text field — the provider's model catalog changes faster than this doc could track, so check your provider's own documentation for the exact model name/ID to use. `base_url` is required for `custom` (any OpenAI-compatible endpoint, e.g. a local Ollama server); omit `api_key` to leave the currently-stored key unchanged.

### `POST /ai/config/test`
Admin+. Sends a trivial prompt to the configured provider and returns `{"success": true/false, "detail": "..."}` — use this after saving config to confirm the key/endpoint actually works before relying on it.

### `POST /ai/explain-alert`
Analyst+. `{ "alert_id": "uuid" }` → a plain-language explanation of why the alert fired and what to check next, using the alert's own fields and rule condition as context.

### `POST /ai/analyze-events`
Analyst+. `{ "event_ids": ["uuid1", "uuid2"], "question": "..." }` → answers a free-form question about a specific set of selected events (used by the Events page's multi-select "Explain with AI" flow).

### `POST /ai/search`
Analyst+. `{ "question": "show me critical alerts from the last 24 hours" }` → the Home page's natural-language search. Internally: one AI call extracts a structured `{target, filters, group_by}` intent, a real query runs against Events/Alerts/Cases, and a second AI call summarizes the real results — see [Architecture](architecture.md#ai-layer-optional) for the full sequence diagram.
```json
{
  "answer": "3 critical alerts fired in the last 24 hours, all from rule tinysiem-internal-brute-force...",
  "link": "/ui/alerts.html?severity=critical&start=...",
  "link_label": "View 3 alerts",
  "meta": {
    "target": "alerts",
    "count": 3,
    "filters": { "severity": "critical" },
    "group_by": null,
    "dropped": []
  }
}
```
The response is structured for the rich result card:
- `meta.filters` — the applied filters (display keys); `meta.dropped` — filters the question requested but that could not be applied, each with a `reason` (unsupported field, unparseable value, unknown country, …). The UI renders these as amber ⚠️ chips.
- For `events`: `table` (rank/IP/country/events — top source IPs with country enrichment), `breakdown` (status code distribution), and `country_breakdown` (country distribution of **all** matches).
- For `alerts`/`cases`: `breakdown` carries the severity / status distribution.
- Supported filters are registry-driven (`app/ai/filters.py`): events add `country_code` (names like "Indonesia" normalize to ISO codes), `city`, `asn`, `response_size_min/max`, `user_agent`, `referer`; `source_ip` is **exact** (CIDR / `a.b.c.x` degrade to a prefix match); alerts add `mitre_tactic` / `mitre_technique`.
- If the question isn't a search (a greeting, a general question), `link`/`link_label` are `null` and `answer` is a plain conversational reply.
- If the provider returns an empty response (e.g. a reasoning model starved of `max_tokens`), the endpoint returns `503` with an explanatory `detail` instead of a blank answer.

### `POST /parsers/generate` and `POST /rules/generate`
Covered under [Parsers](#parsers) and [Rules](#rules) above — both are AI-powered but scoped to their own resource, so they stay documented there rather than here.

### `POST /rules/{name}/playbook/generate` and `POST /cases/{case_id}/playbook/refine`
Covered under [Rules](#rules) and [Cases](#cases) above, for the same reason.

---

## Audit Log

Requires `admin` role.

### `GET /audit`

| Param | Type | Description |
|---|---|---|
| `event_type` | string | e.g. `auth.login`, `parser.create`, `ai.call` |
| `actor` | string | Username substring match |
| `resource_type` | string | e.g. `parser`, `rule`, `user`, `case` |
| `action` | string | e.g. `created`, `deleted`, `login` |
| `status` | string | `success`, `failure`, `error` |
| `q` | string | Full-text on actor, event_type, detail |
| `start` / `end` | ISO 8601 | Time window |
| `limit` / `offset` | int | Pagination (max 500) |

### `GET /audit/facets`
Returns `{ event_type: [...], actor: [...], status: [...] }` counts.

---

## Users

All user-management endpoints require `superadmin` role.

| Method | Path | Description |
|---|---|---|
| `GET` | `/users` | List all users |
| `POST` | `/users` | Create user (`201`) |
| `PUT` | `/users/{user_id}` | Update username, role, and/or password (all fields optional) |
| `DELETE` | `/users/{user_id}` | Delete user (`204`) |

There is no `GET /users/{id}` — use `GET /users` and filter client-side.

**Create request:**
```json
{ "username": "alice", "password": "a-12-char-or-longer-password", "role": "analyst" }
```

Valid roles: `analyst`, `admin`, `superadmin`. `password` must be 12+ characters (`422` otherwise). Returns `409` if the username already exists.

**Update request** (any subset of fields):
```json
{ "role": "admin" }
```

Updating a user via this endpoint — even just a role change — bumps that user's `token_epoch`, revoking all of their existing JWTs; they'll need to log in again. Returns `409` if the update would demote or delete the last remaining superadmin.

---

## System

### Retention

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/retention/status` | admin | Current policy, event count, archive file list |
| `POST` | `/retention/run` | admin | Manually archive events older than `TINYSIEM_RETENTION_DAYS` |

### Reports

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/reports/generate` | analyst | Aggregate report data as JSON |
| `GET` | `/reports/download` | analyst | Download HTML report (`?period=daily` or `weekly`) |
| `POST` | `/reports/send` | admin | Email the report (`?period=daily` or `weekly`) |

### Notifications

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/notifications/config` | admin | Current notification config |
| `POST` | `/notifications/test` | admin | Send test notification (`{ "channel": "email" \| "webhook" }`) |

### SBOM

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/sbom` | admin | Installed dependency inventory (`[{ "name": "fastapi", "version": "0.115.5" }, ...]`), generated from `pip freeze` at image build time |

### Backup

| Method | Path | Role | Description |
|---|---|---|---|
| `POST` | `/admin/backup` | superadmin | Streams a `tar.gz` (`application/gzip`) containing a Parquet export of the full DuckDB database, the alerts JSONL, and any custom rules/decoders |

See [Backup & Restore](backup.md) for the response shape and the manual restore procedure.

---

## SQL Sandbox

`POST /query/sql` — read-only DuckDB querying for analysts and AI agents. Requires `analyst` role.

| Param | Type | Description |
|---|---|---|
| `query` | string | Single SQL statement: `SELECT`/`WITH`/`SHOW`/`DESCRIBE`/`EXPLAIN`/`VALUES`. Multi-statement input (`;`) is rejected. |
| `params` | array | Optional positional parameters for `?` placeholders. |
| `max_rows` | int | Optional per-request row cap (1–10,000); still clamped to `TINYSIEM_SQL_MAX_ROWS`. |

**Request:**
```json
{ "query": "SELECT source, COUNT(*) AS n FROM events WHERE ingested_at >= ? GROUP BY source ORDER BY n DESC LIMIT 10", "params": ["2026-08-01 00:00:00"] }
```

**Response:**
```json
{ "columns": ["source", "n"], "rows": [["sshd", 1140000], ["fail2ban", 16100], ["ufw", 10900]], "total_rows": 3, "truncated": false, "duration_ms": 12 }
```

**Errors:** `422` for empty/disallowed/multi-statement queries, `429` when another query holds the
single-flight lock, `408` on timeout (`TINYSIEM_SQL_TIMEOUT_MS`, threaded — DuckDB 1.1.3 has no
statement timeout), `503` when `TINYSIEM_SQL_ENABLED=false`.

Safety model: statement allowlist, comments stripped *before* the keyword check, blocked-keyword
scan, row cap + 500-char cell truncation, and an audit entry (`query.sql`) per execution. Uses a
second, in-process DuckDB connection to the same file — it never contends with the writer (a
second *process* would hit the single-writer file lock, so this endpoint is the supported way to
run ad-hoc analysis while the server is up).

---

## GeoIP Lookup

### `GET /geoip/{ip}`
Analyst+. Look up enrichment data for a single IP. Requires `TINYSIEM_GEOIP_DB_PATH` configured.

**Response:**
```json
{ "ip": "45.153.34.161", "country_code": "NL", "country_name": "Netherlands", "city": "Amsterdam", "asn": "20473", "found": true }
```

`found: false` (with null geo fields) when the IP falls outside the database's ranges or no
database is configured.

---

## MCP Server

When `TINYSIEM_MCP_ENABLED=true`, a Model Context Protocol server is mounted at `/mcp/sse` (SSE transport). This enables Claude Desktop and other MCP clients to query TinySIEM directly.

**Authentication:** Bearer JWT required. Role must be `analyst` or above.

**Available tools:**

| Tool | Description |
|---|---|
| `list_events` | Search events (source, source_ip, q, limit) |
| `get_alerts` | Search alerts (severity, rule_name, limit) |
| `list_parsers` | List all loaded decoders (built-in and custom) |
| `list_rules` | List all loaded detection rules |
| `get_health` | Instance health and summary stats (event count, alert count) |
| `investigate_ip` | One-call IP pivot — first/last seen, histogram, top methods/URIs, related alerts and cases, geo lookup |
| `get_alert_context` | Full context for one alert — the alert, its triggering event, rule, and related events |
| `query_events_sql` | Run a read-only SQL query through the same sandbox as `POST /query/sql` |

---

→ [Troubleshooting](troubleshooting.md) — common errors and fixes

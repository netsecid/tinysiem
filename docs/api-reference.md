# API Reference

All endpoints except `GET /health` require a valid credential passed as `Authorization: Bearer <token>`.

Two token types are accepted:
- **API key** (`TINYSIEM_API_KEY` from `.env`) — for machine-to-machine ingest. Treated as `admin` role.
- **JWT** (obtained from `POST /auth/login`) — for all UI and user-context flows. Encodes `sub` (user ID), `username`, `role`, and `exp`.

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
  "expires_in": 86400
}
```

JWT expiry defaults to 24 hours (`TINYSIEM_JWT_EXPIRY_HOURS`).

---

### `GET /auth/me`
Returns the currently authenticated user's profile. Requires `analyst` role.

**Response:**
```json
{ "user_id": "uuid", "username": "admin", "role": "superadmin" }
```

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
    "beats_http": { "enabled": true, "path": "/ingest/beats" }
  }
}
```

---

## Ingest

### `POST /ingest/raw`
Ingest a single log line. Requires `admin` role.

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
Bulk ingest from an uploaded text file (one log line per line). Requires `admin` role.

**Query params:** `source` (required)

**Request:** `multipart/form-data` with field `file`.

**Response:**
```json
{ "status": "ok", "processed": 450, "failed": 2 }
```

---

### `POST /ingest/beats`
Beats-compatible bulk ingest (Elasticsearch ndjson format). Accepts Filebeat / Winlogbeat / Metricbeat output directly. Requires `admin` role.

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
| `start` / `end` | ISO 8601 | Time window on `ingested_at` |
| `limit` | int | Max results (default 100, max 1000) |
| `offset` | int | Pagination offset |

Note: `source_ip`, `uri`, and `q` use `LIKE`/`ILIKE` matching. SQL metacharacters (`%`, `_`) in filter values are escaped and treated literally.

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
| `q` | string | Full-text on rule name and summary |
| `start` / `end` | ISO 8601 | Window on `triggered_at` |
| `limit` / `offset` | int | Pagination |

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
      "triage_status": "open",
      "notes": "",
      "assigned_to": ""
    }
  ]
}
```

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

Case management for multi-alert incidents. Requires `analyst` role for read/update; `admin` for create/delete.

### `GET /cases`

| Param | Type | Description |
|---|---|---|
| `status` | string | `open`, `investigating`, `resolved` |
| `severity` | string | `low`, `medium`, `high`, `critical` |
| `assigned_to` | string | Username filter |
| `q` | string | Full-text on title and description |
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
      "assigned_to": "alice",
      "created_at": "2026-07-01T10:00:00Z",
      "updated_at": "2026-07-01T10:05:00Z",
      "alert_ids": ["uuid1", "uuid2"]
    }
  ]
}
```

### `POST /cases`
Create a case. Requires `admin` role.

```json
{
  "title": "Suspicious exfiltration",
  "description": "Large outbound transfers to unknown IP",
  "severity": "critical",
  "assigned_to": "alice",
  "alert_ids": ["uuid1"]
}
```

### `GET /cases/{case_id}`
Get a single case with full alert list. Requires `analyst` role.

### `PATCH /cases/{case_id}`
Update status, severity, notes, or assigned user. Requires `analyst` role.

```json
{ "status": "resolved", "description": "False positive — scheduled backup job" }
```

### `DELETE /cases/{case_id}`
Delete a case. Requires `admin` role.

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

Returns `503` if `TINYSIEM_CLAUDE_API_KEY` is not set.

---

## Rules

All rule endpoints require `admin` role.

| Method | Path | Description |
|---|---|---|
| `GET` | `/rules` | List all rules (built-in + custom) |
| `POST` | `/rules` | Create a rule from YAML |
| `GET` | `/rules/{name}` | Get rule YAML by name |
| `PUT` | `/rules/{name}` | Update rule YAML |
| `DELETE` | `/rules/{name}` | Delete custom rule |
| `POST` | `/rules/generate` | AI-generate rule YAML from a natural-language description |

**Generate request:**
```json
{ "description": "Alert when the same IP fails login more than 5 times in 60 seconds" }
```

Returns `503` if `TINYSIEM_CLAUDE_API_KEY` is not set.

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

Requires `superadmin` for create/delete; `admin` for list/get; `superadmin` for role changes.

| Method | Path | Description |
|---|---|---|
| `GET` | `/users` | List all users |
| `POST` | `/users` | Create user |
| `GET` | `/users/{username}` | Get user profile |
| `PUT` | `/users/{username}` | Update role or password |
| `DELETE` | `/users/{username}` | Delete user |

**Create request:**
```json
{ "username": "alice", "password": "strong-pass", "role": "analyst" }
```

Valid roles: `analyst`, `admin`, `superadmin`.

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

---

## MCP Server

When `TINYSIEM_MCP_ENABLED=true`, a Model Context Protocol server is mounted at `/mcp`. This enables Claude Desktop to query TinySIEM directly.

**Authentication:** Bearer JWT required. Role must be `analyst` or above.

**Available tools:**

| Tool | Description |
|---|---|
| `list_events` | Search events (source, source_ip, q, limit) |
| `get_alerts` | Search alerts (severity, rule_name, limit) |
| `list_cases` | List cases (status, limit) |
| `get_baselines` | Get baseline health for a source |
| `run_integration` | Manually trigger an integration poll (integration_id) |

---

→ [Troubleshooting](troubleshooting.md) — common errors and fixes

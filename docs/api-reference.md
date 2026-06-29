# API Reference

All endpoints except `GET /health` require a valid credential:
- **Bearer token endpoints** (`/ingest/*`, `/events/*`, `/alerts/*`, `/audit/*`, `/users/*`, etc.) — use `Authorization: Bearer <TINYSIEM_API_KEY>` for machine-to-machine, or a JWT obtained from `POST /auth/login` for UI/user flows.
- JWT is required for role-gated endpoints (admin, superadmin).

---

## Authentication

### `POST /auth/login`
Authenticate and receive a JWT.

**Request:**
```json
{ "username": "admin", "password": "your-password" }
```

**Response:**
```json
{ "access_token": "<jwt>", "token_type": "bearer" }
```

The JWT encodes `sub` (username), `role`, and `exp`. Default expiry: 24 hours (configurable via `TINYSIEM_JWT_EXPIRY_HOURS`).

---

## Health

### `GET /health`
No auth required.

**Response:**
```json
{
  "status": "ok",
  "version": "0.9.0",
  "events": 1024,
  "listeners": { "udp": true, "tcp": true }
}
```

---

## Ingest

### `POST /ingest/raw`
Ingest a single log line.

**Request:**
```json
{ "source": "nginx", "raw": "<log line>" }
```

**Response:**
```json
{ "id": "<uuid>", "source": "nginx", "decoded": true }
```

Returns `422` if the line cannot be decoded by any registered parser.

---

### `POST /ingest/file`
Bulk ingest from an uploaded file (one log line per line).

**Query params:** `source` (required)

**Request:** `multipart/form-data` with field `file`.

**Response:**
```json
{ "ingested": 450, "errors": 2, "total": 452 }
```

---

### `POST /ingest/beats`
Beats-compatible bulk ingest (Elasticsearch ndjson format). Accepts Filebeat, Winlogbeat, Metricbeat output directly.

Source is resolved from: `fields.source` → `agent.type` → `"beats"`.

---

## Events

### `GET /events`

| Param | Type | Description |
|---|---|---|
| `source` | string | Exact match on source field |
| `source_ip` | string | Substring match on source IP |
| `status_code` | int | Exact HTTP status code |
| `status_min` / `status_max` | int | Status code range |
| `method` | string | HTTP method (case-insensitive) |
| `uri` | string | Substring match on URI |
| `q` | string | Full-text search on raw log line |
| `start` / `end` | ISO 8601 | Time window |
| `limit` | int | Max results (default 100, max 1000) |
| `offset` | int | Pagination offset |

**Response:**
```json
{
  "total": 1024,
  "events": [
    {
      "id": "uuid",
      "source": "nginx",
      "ingested_at": "2026-06-29T10:00:00",
      "event_time": "2026-06-29T10:00:00",
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
Returns value counts for sidebar rendering. Accepts the same filter params as `GET /events`.

**Response:**
```json
{
  "source":   [{ "value": "nginx", "count": 1024 }],
  "method":   [{ "value": "GET", "count": 800 }],
  "status_class": [{ "value": "2xx", "count": 700 }],
  "source_ip": [{ "value": "10.0.0.1", "count": 50 }]
}
```

---

### `GET /events/histogram`
Time-bucketed event counts for sparkline charts.

| Param | Type | Description |
|---|---|---|
| `start` / `end` | ISO 8601 | Time window (required) |
| `buckets` | int | Number of buckets, 10–200 (default 48) |

**Response:** `[{ "ts": "2026-06-29T10:00:00", "count": 42 }, ...]`

---

## Alerts

### `GET /alerts`

| Param | Type | Description |
|---|---|---|
| `severity` | string | `low`, `medium`, `high`, `critical` |
| `rule_name` | string | Exact rule name match |
| `source_ip` | string | Substring match |
| `status` | string | Triage status: `open`, `investigating`, `resolved` |
| `q` | string | Full-text on rule name and summary |
| `start` / `end` | ISO 8601 | Time window on `triggered_at` |
| `limit` / `offset` | int | Pagination |

**Response:**
```json
{
  "total": 12,
  "alerts": [
    {
      "alert_id": "uuid",
      "triggered_at": "2026-06-29T10:00:00Z",
      "rule_name": "http-404-spike",
      "severity": "medium",
      "mitre_tactic": "Discovery",
      "mitre_technique": "T1595",
      "event_id": "uuid",
      "source_ip": "10.0.0.1",
      "summary": "10 events matching status_code=404 in 60s",
      "triage_status": "open"
    }
  ]
}
```

---

### `GET /alerts/facets`
Returns `{ severity: [...], rule_name: [...] }` counts.

### `PATCH /alerts/{alert_id}`
Update triage status. Requires `analyst` role or above.

```json
{ "triage_status": "investigating", "note": "Investigating source IP" }
```

### `GET /alerts/triage-summary`
Returns `{ open: N, investigating: N, resolved: N }`.

---

## Parsers

All parser endpoints require `admin` role.

| Method | Path | Description |
|---|---|---|
| `GET` | `/parsers` | List all parsers |
| `POST` | `/parsers` | Create parser from YAML |
| `GET` | `/parsers/{name}` | Get parser by name |
| `PUT` | `/parsers/{name}` | Update parser YAML |
| `DELETE` | `/parsers/{name}` | Delete parser |
| `POST` | `/parsers/{name}/test` | Test parser against a log sample |
| `POST` | `/parsers/generate` | AI-generate parser YAML from log sample |

---

## Rules

All rule endpoints require `admin` role.

| Method | Path | Description |
|---|---|---|
| `GET` | `/rules` | List all rules |
| `POST` | `/rules` | Create rule from YAML |
| `GET` | `/rules/{name}` | Get rule by name |
| `PUT` | `/rules/{name}` | Update rule YAML |
| `DELETE` | `/rules/{name}` | Delete rule |
| `POST` | `/rules/generate` | AI-generate rule YAML from description |

---

## Audit Log

Requires `admin` role.

### `GET /audit`

| Param | Type | Description |
|---|---|---|
| `event_type` | string | e.g. `auth.login`, `parser.create`, `ai.call` |
| `actor` | string | Username |
| `resource_type` | string | e.g. `parser`, `rule`, `user` |
| `action` | string | e.g. `created`, `deleted`, `login` |
| `status` | string | `success`, `failure`, `error` |
| `q` | string | Full-text on actor, event_type, detail |
| `start` / `end` | ISO 8601 | Time window |
| `limit` / `offset` | int | Pagination (max 500) |

### `GET /audit/facets`
Returns `{ event_type: [...], actor: [...], status: [...] }` counts.

---

## Users

Requires `superadmin` role for create/delete; `admin` for list/get.

| Method | Path | Description |
|---|---|---|
| `GET` | `/users` | List users |
| `POST` | `/users` | Create user |
| `GET` | `/users/{username}` | Get user |
| `PUT` | `/users/{username}` | Update role or password |
| `DELETE` | `/users/{username}` | Delete user |

---

## System

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/retention/status` | admin | Retention policy status |
| `POST` | `/retention/run` | admin | Manually run retention |
| `GET` | `/reports/generate` | analyst | Generate report data |
| `GET` | `/reports/download` | analyst | Download HTML report |
| `POST` | `/reports/send` | admin | Email report |
| `POST` | `/notifications/test` | admin | Send test notification |
| `GET` | `/notifications/config` | admin | Notification config |

---

→ [Troubleshooting](troubleshooting.md) — common errors and fixes

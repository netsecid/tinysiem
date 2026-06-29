# TinySIEM v0.8 Ecosystem — Design Spec

**Date:** 2026-06-29
**Version:** 0.8.0
**Phase:** 5 — Ecosystem

---

## Goal

Support real log sources and more sophisticated detection.

---

## Features

### 1. Built-in Decoders

Five YAML decoder files ship in `app/decoder/decoders/`:

| File | Source key | Format |
|---|---|---|
| `syslog-rfc3164.yaml` | `syslog_rfc3164` | `<priority>timestamp hostname process[pid]: message` |
| `syslog-rfc5424.yaml` | `syslog_rfc5424` | `<priority>1 timestamp hostname appname procid msgid - message` |
| `windows-event.yaml` | `windows_event` | Winlogbeat JSON (nested fields via dotted path) |
| `aws-cloudtrail.yaml` | `aws_cloudtrail` | CloudTrail JSON |
| `iptables.yaml` | `iptables` | key=value kernel log format |

**Decoder engine change:** add `_get_nested(data, dotted_key)` helper so JSON decoders can map nested fields like `winlog.event_id` via dotted-path notation. Backward-compatible with existing flat-key decoders.

---

### 2. Beats-Compatible HTTP Endpoint

`POST /ingest/beats` — accepts Elasticsearch bulk format (ndjson pairs):

```
{"index": {"_index": "filebeat-..."}}
{"@timestamp": "...", "message": "raw log", "fields": {"source": "nginx"}, ...}
```

- Source determination: `fields.source` → `agent.type` → `"beats"`
- Extracts `message` field as the raw log line
- Calls normal ingest pipeline (`decode → DuckDB → ChromaDB → rules`)
- Falls back to storing raw event without decoding if no decoder found
- Returns ES-compatible response: `{"items": [...], "errors": bool, "took": N}`
- Auth: Bearer token (same as `/ingest/raw`)

Controlled by `TINYSIEM_BEATS_ENABLED` (default: true).

---

### 3. Syslog UDP/TCP Listener

New module `app/listeners/syslog.py`. Runs inside the FastAPI asyncio event loop as background tasks (started in lifespan).

**Format detection:** checks if the raw line (after `<priority>`) starts with `"1 "` (RFC 5424 version field). Falls back to RFC 3164.

**UDP:** asyncio DatagramProtocol on port `TINYSIEM_SYSLOG_UDP_PORT` (default: 5140, 0 = disabled).

**TCP:** asyncio start_server on port `TINYSIEM_SYSLOG_TCP_PORT` (default: 5141, 0 = disabled). Line-framed (readline).

Dispatches lines to `pipeline.process_line()` via `run_in_executor` to avoid blocking the event loop.

**Exposed in `/health`:**
```json
{
  "status": "ok",
  "version": "0.8.0",
  "listeners": {
    "syslog_udp": {"enabled": true, "port": 5140},
    "syslog_tcp": {"enabled": true, "port": 5141},
    "beats_http": {"enabled": true, "path": "/ingest/beats"}
  }
}
```

**docker-compose.yml:** expose ports 5140 UDP and 5141 TCP on tinysiem service.

---

### 4. Correlation Rules

New `condition.type: correlation` in rule YAML. Tracks multi-step event sequences per-IP (or per any captured field) within a sliding window.

**YAML format:**
```yaml
name: brute-force-then-success
severity: high
source: "*"   # evaluated against all events
condition:
  type: correlation
  window_seconds: 300
  capture_field: source_ip   # field whose value links the steps
  steps:
    - source: nginx
      field: status_code
      value: "401"
      operator: eq
    - source: nginx
      field: status_code
      value: "200"
      operator: eq
mitre_tactic: "Credential Access"
mitre_technique: "T1110"
```

**State:** `_corr_state: dict[rule_name → dict[capture_value → {step, triggered_at, first_event_id}]]`, protected by `threading.Lock`.

**Evaluation:**
- Rules with `source: "*"` (or correlation type) are evaluated against every event regardless of source
- On each event: clean expired entries, then try to advance the sequence for `capture_value`
- Step 0 match: creates entry; last step match: fires alert and removes entry

**Sequence resets** after firing, allowing re-triggering.

---

## New Env Vars

```
TINYSIEM_SYSLOG_UDP_PORT   # default 5140 (0 = disabled)
TINYSIEM_SYSLOG_TCP_PORT   # default 5141 (0 = disabled)
TINYSIEM_BEATS_ENABLED     # default true
```

---

## New Files

```
app/decoder/decoders/syslog-rfc3164.yaml
app/decoder/decoders/syslog-rfc5424.yaml
app/decoder/decoders/windows-event.yaml
app/decoder/decoders/aws-cloudtrail.yaml
app/decoder/decoders/iptables.yaml
app/rules/rules/brute-force-then-success.yaml   (example correlation rule)
app/ingest/pipeline.py      (extracted process_line + strict=False fallback)
app/listeners/__init__.py
app/listeners/syslog.py
app/tests/test_builtin_decoders.py
app/tests/test_beats_ingest.py
app/tests/test_syslog_listener.py
app/tests/test_correlation_rules.py
```

## Modified Files

```
app/config.py               (version → 0.8.0, new env vars)
app/decoder/engine.py       (_get_nested, update _apply_fields + _parse_timestamp)
app/ingest/router.py        (use pipeline.process_line; add /ingest/beats)
app/rules/engine.py         (correlation type, _corr_state, reset_corr_state())
app/main.py                 (start syslog listeners in lifespan; extend /health)
docker-compose.yml          (expose 5140 UDP, 5141 TCP)
ui/configuration.html       (add LOG INGESTION section)
```

---

## Security Constraints

- Syslog listener is unauthenticated (standard for syslog protocol); runs on non-privileged ports (5140/5141)
- Beats endpoint requires the same Bearer token as all other ingest endpoints
- Correlation state held in-memory; no persistence across restarts (acceptable — window is minutes)
- No eval/exec; no new PyPI packages (asyncio is stdlib)

# Decoders

Decoders tell TinySIEM how to parse a raw log line into structured fields. Each decoder is a YAML file in `app/decoder/decoders/`. They are loaded at startup and hot-reloaded automatically.

---

## YAML Format

```yaml
name: nginx-access          # unique identifier (kebab-case)
source: nginx               # must match the `source` field sent on ingest
type: regex                 # regex | json | kv

# For type: regex
pattern: '^(?P<remote_addr>\S+) ...'   # named capture groups

# For type: json — no pattern needed, parses the line as JSON directly

# For type: kv — no pattern needed, parses key=value pairs

fields:                     # map normalized field names → capture group / JSON key
  source_ip:    remote_addr
  method:       request_method
  uri:          request_uri
  status_code:  status
  response_size: body_bytes_sent
  user_agent:   http_user_agent
  referer:      http_referer

timestamp_field: timestamp  # key from fields: (or capture group name) holding the timestamp
timestamp_format: '%d/%b/%Y:%H:%M:%S %z'   # strptime format string
```

**Normalized field names** (map your log fields to these):

| Field | Type | Description |
|---|---|---|
| `source_ip` | string | Client / source IP address |
| `method` | string | HTTP method |
| `uri` | string | Request URI |
| `status_code` | int | HTTP response status |
| `response_size` | int | Response body bytes |
| `user_agent` | string | User-Agent header |
| `referer` | string | Referer header |

Any unmapped capture groups are stored in the `extra` JSON column.

---

## Built-in Decoders

### nginx-access

Parses the default nginx combined log format.

```
source: nginx
type: regex
```

Example log line:
```
192.168.1.1 - - [29/Jun/2026:10:00:00 +0000] "GET /api/data HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
```

---

### syslog-rfc3164

Parses BSD syslog (RFC 3164) — the traditional format used by most network devices and Unix daemons.

```
source: syslog_rfc3164
type: regex
```

Example:
```
Jun 29 10:00:00 webserver sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2
```

---

### syslog-rfc5424

Parses IETF syslog (RFC 5424) — structured syslog with ISO 8601 timestamps.

```
source: syslog_rfc5424
type: regex
```

---

### windows-event

Parses Windows Event Log entries forwarded as JSON (e.g. via Winlogbeat).

```
source: windows_event
type: json
```

Uses dotted-path field resolution — e.g. `winlog.event_id` resolves nested JSON keys.

---

### aws-cloudtrail

Parses AWS CloudTrail event records forwarded as JSON.

```
source: aws_cloudtrail
type: json
```

---

### iptables

Parses Linux iptables/netfilter log lines.

```
source: iptables
type: regex
```

Example:
```
Jun 29 10:00:00 host kernel: [DROPPED] IN=eth0 SRC=1.2.3.4 DST=10.0.0.1 PROTO=TCP SPT=12345 DPT=22
```

---

### tinysiem-internal

Parses the self-monitoring feed — security-relevant audit events (failed logins, lockouts,
user/integration changes) that TinySIEM mirrors into its own detection pipeline. You won't
send this format yourself; it's generated internally. See [Rules → Self-Monitoring](rules.md#self-monitoring).

```
source: tinysiem_internal
type: json
```

---

## Writing a Custom Decoder

1. Create `app/decoder/decoders/custom/<name>.yaml`
2. Set a unique `name` and `source` value
3. Use named capture groups `(?P<name>...)` for regex type
4. Map captured field names to normalized field names under `fields:`
5. The decoder is active on next request — no rebuild needed

**Testing your decoder:** use the Parsers page in the UI → paste a log sample → click Test.

---

## AI-Assisted Generation

On the Parsers page, click **Generate with AI**, paste a log sample, and TinySIEM will produce a working decoder YAML using the Claude API. Requires `TINYSIEM_CLAUDE_API_KEY` to be set.

---

→ [Troubleshooting](troubleshooting.md) — common errors and fixes

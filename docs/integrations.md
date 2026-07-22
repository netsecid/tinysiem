# API Integrations

TinySIEM can pull logs from external services on a configurable schedule, or ingest an existing log/CSV file directly for a one-off investigation — both go through the same decoder → rule → alert pipeline as any other log source.

Scheduled pull integrations:
- [AWS CloudTrail](#aws-cloudtrail)
- [Google Workspace](#google-workspace)

Manual, one-shot ingestion:
- [Bulk File / CSV Upload](#bulk-file--csv-upload)

---

## Prerequisites

Integration credentials are encrypted at rest with Fernet. Before creating any integration, you must set `TINYSIEM_MASTER_KEY` in `.env`:

```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Add the output to `.env`:
```dotenv
TINYSIEM_MASTER_KEY=<generated key>
```

Then recreate the container to pick up the new variable:
```bash
docker-compose up -d
```

If the key is missing, all integration endpoints return `503 TINYSIEM_MASTER_KEY not set`.

---

## AWS CloudTrail

Pulls CloudTrail records from an **S3 bucket** or **CloudWatch Logs**. Events are ingested with `source: aws_cloudtrail`.

### 1. Choose a delivery method

**S3 bucket (recommended):** CloudTrail writes compressed JSON logs to S3. TinySIEM lists objects under `AWSLogs/` and reads any `.json.gz` files it finds on each poll.

**CloudWatch Logs:** CloudTrail can deliver to a log group. TinySIEM calls `filter_log_events` on the `/aws/cloudtrail` log group starting from the last cursor timestamp.

### 2. Create an IAM user or role

TinySIEM needs read-only access. Create an IAM policy with the minimum required permissions:

**For S3 delivery:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::YOUR-TRAIL-BUCKET",
        "arn:aws:s3:::YOUR-TRAIL-BUCKET/*"
      ]
    }
  ]
}
```

**For CloudWatch Logs delivery:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:FilterLogEvents",
        "logs:DescribeLogGroups"
      ],
      "Resource": "arn:aws:logs:*:*:log-group:/aws/cloudtrail:*"
    }
  ]
}
```

Attach the policy to a new IAM user and generate an **Access Key ID** and **Secret Access Key**.

### 3. Create the integration in TinySIEM

Via the UI: **Configuration → Integrations → + New Integration → AWS CloudTrail**

| Field | Value |
|---|---|
| Name | Any label (e.g. `prod-cloudtrail`) |
| Poll interval | How often to pull, in minutes (e.g. `15`) |
| **region** | AWS region of your trail (e.g. `us-east-1`) |
| **s3_bucket** | S3 bucket name for CloudTrail logs. Leave empty to use CloudWatch Logs instead. |
| **aws_access_key_id** | IAM access key ID |
| **aws_secret_access_key** | IAM secret access key |

Via the API:
```bash
curl -s -X POST http://localhost:8000/integrations \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "prod-cloudtrail",
    "integration_type": "aws_cloudtrail",
    "schedule_minutes": 15,
    "config": {
      "region": "us-east-1",
      "s3_bucket": "my-cloudtrail-bucket"
    },
    "credentials": {
      "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
      "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    }
  }'
```

### 4. Verify

Click **Trigger now** (or `POST /integrations/{id}/trigger`) and then check **Run History**. A successful run shows `status: ok` and an event count. If `status: error`, the `error_message` field contains the AWS error detail.

Check that events are arriving:
```bash
curl -s "http://localhost:8000/events?source=aws_cloudtrail&limit=5" \
  -H "Authorization: Bearer <jwt>"
```

### 5. Detection rules for CloudTrail

Create a rule in `app/rules/rules/custom/` targeting `source: aws_cloudtrail`. CloudTrail records are stored with the full JSON as `raw`. Use the `q` field filter or a custom decoder field for more specific matching.

Example rule — alert on root account usage:
```yaml
name: aws_root_login
severity: critical
source: aws_cloudtrail
condition:
  type: field_match
  field: raw
  operator: contains
  value: '"userIdentity":{"type":"Root"'
mitre_tactic: "Privilege Escalation"
mitre_technique: "T1078.004"
```

### Notes

- Each poll fetches up to 1 000 events. For high-volume trails with S3 delivery, TinySIEM will resume from the most recently modified object on the next poll.
- For CloudWatch Logs, TinySIEM uses the cursor (last event timestamp) to avoid re-processing old events.
- Credentials are stored encrypted; the API never returns the plaintext values — they are masked to `**...LAST4` on all read endpoints.

---

## Google Workspace

Pulls activity events from the **Google Workspace Admin SDK Reports API**. Events are ingested with `source: google_workspace_<application_name>` (e.g. `google_workspace_login`).

### 1. Create a Google Cloud project

1. Go to [console.cloud.google.com](https://console.cloud.google.com)
2. Create a new project (or use an existing one)
3. Enable the **Admin SDK API**: APIs & Services → Enable APIs → search "Admin SDK" → Enable

### 2. Create a service account

1. IAM & Admin → Service Accounts → **Create Service Account**
2. Give it a name (e.g. `tinysiem-reports`)
3. Skip role assignment at the project level (permissions are granted via domain delegation instead)
4. Click the service account → **Keys** tab → **Add Key → Create new key → JSON**
5. Download the JSON key file — you'll paste its contents into TinySIEM

### 3. Enable domain-wide delegation

The service account needs permission to impersonate an admin user to call the Reports API.

1. In the Google Cloud Console: IAM & Admin → Service Accounts → click your service account → **Details** tab → copy the **Client ID** (numeric, e.g. `123456789012345678901`)
2. In **Google Admin Console** ([admin.google.com](https://admin.google.com)):
   - Security → Access and data control → **API controls**
   - Manage Domain Wide Delegation → **Add new**
   - Client ID: paste the numeric client ID from step 1
   - OAuth scopes: `https://www.googleapis.com/auth/admin.reports.audit.readonly`
   - Authorise

### 4. Create the integration in TinySIEM

Via the UI: **Configuration → Integrations → + New Integration → Google Workspace**

| Field | Value |
|---|---|
| Name | Any label (e.g. `workspace-login`) |
| Poll interval | Minutes between polls (e.g. `15`) |
| **admin_email** | Email address of a Workspace admin user the service account will impersonate (e.g. `admin@yourcompany.com`) |
| **application_name** | Reports API application to pull: `login`, `admin`, `drive`, `calendar`, `token`, `groups`, `saml`, `chat`, `gcp`, `meet`, `jamboard`, `vault`, `rules`, `user_accounts`, `context_aware_access` |
| **service_account_json** | The full contents of the JSON key file downloaded in step 2 |

Via the API:
```bash
SA_JSON=$(cat /path/to/service-account-key.json | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))")

curl -s -X POST http://localhost:8000/integrations \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"workspace-login\",
    \"integration_type\": \"google_workspace\",
    \"schedule_minutes\": 15,
    \"config\": {
      \"admin_email\": \"admin@yourcompany.com\",
      \"application_name\": \"login\"
    },
    \"credentials\": {
      \"service_account_json\": $SA_JSON
    }
  }"
```

### 5. Verify

Click **Trigger now** and check **Run History**. If `status: error`, common causes:

| Error | Cause | Fix |
|---|---|---|
| `HttpError 403` | Domain-wide delegation not configured, or wrong Client ID | Re-check step 3; allow up to 10 minutes for Google to propagate |
| `HttpError 400` | Invalid `application_name` | Use one of the values listed in the field table above |
| `json.JSONDecodeError` | `service_account_json` was not valid JSON | Re-paste the full key file contents |
| `TransportError` | Network issue from inside the container | Check DNS from the container: `docker-compose exec tinysiem curl https://admin.googleapis.com` |

Check that events are arriving:
```bash
curl -s "http://localhost:8000/events?source=google_workspace_login&limit=5" \
  -H "Authorization: Bearer <jwt>"
```

### 6. Multiple application types

Create one integration per `application_name`. Each produces a distinct source name (`google_workspace_login`, `google_workspace_drive`, etc.), which you can target separately in detection rules and filters.

### 7. Detection rules for Google Workspace

Events are stored as raw JSON from the Reports API. Example rule — alert on admin role assignment:
```yaml
name: gws_admin_role_assigned
severity: high
source: google_workspace_admin
condition:
  type: field_match
  field: raw
  operator: contains
  value: '"name":"ASSIGN_ROLE"'
mitre_tactic: "Privilege Escalation"
mitre_technique: "T1078.004"
```

Example rule — alert on suspicious login:
```yaml
name: gws_suspicious_login
severity: medium
source: google_workspace_login
condition:
  type: field_match
  field: raw
  operator: contains
  value: '"name":"suspicious_login"'
mitre_tactic: "Initial Access"
mitre_technique: "T1078"
```

### Notes

- Each poll fetches up to 1 000 activity items per application. TinySIEM uses the most recent event timestamp as the cursor for the next poll to avoid duplicates.
- The Reports API can have up to a 1–2 hour delay before events appear. Set your poll interval to at least 15 minutes.
- The `service_account_json` credential is stored encrypted; the raw JSON key is never returned by the API.

---

## Bulk File / CSV Upload

Unlike the scheduled pull integrations above, this is a manual, one-shot way to load a log file you already have — e.g. an export from an EDR, a cloud provider, or an internal tool — into TinySIEM's search/filtering, typically for a forensic or incident-response investigation. There's no credential storage, scheduling, or run history involved: you run a script once against the file you have.

Any decoder-supported format works (`nginx`, `syslog`, JSON lines, key-value, or a custom decoder), but the common case is a CSV export with arbitrary column names, which is what this section walks through.

### 1. Define a decoder for your file's columns

If your file already matches a built-in decoder (e.g. plain nginx access logs), skip to step 2.

For a CSV with custom column names, add a `type: csv` decoder YAML under `app/decoder/decoders/custom/`. It reads column names from the file's own header row (line 1), so you only need to map your columns to TinySIEM's normalized fields — no code changes:

```yaml
# app/decoder/decoders/custom/my_custom_csv.yaml
name: my_custom_csv
source: my_custom_csv
type: csv
fields:
  source_ip: client_ip        # normalized field: your CSV's header name
  status_code: http_status
  uri: request_path
timestamp_field: event_time    # optional, must be a key in fields:
timestamp_format: '%Y-%m-%d %H:%M:%S'
```

Any CSV column not listed under `fields:` is still kept — it lands in the event's `extra` JSON rather than being dropped.

### 2. Restart to load the decoder

```bash
docker-compose restart tinysiem
```

### 3. Run the bulk ingest script

```bash
python scripts/ingest_file.py --source my_custom_csv --file evidence.csv --csv
```

| Flag | Default | Purpose |
|---|---|---|
| `--source` | *(required)* | Must match an existing decoder's `source` name. No format auto-detection — you're always explicit about which decoder applies. |
| `--file` | *(required)* | Path to the log/CSV file to upload. |
| `--csv` | off | Set this when the file has a header row (line 1) that should be treated as column names, per step 1. Omit for plain log files (nginx, syslog, JSON lines, ...). |
| `--endpoint` | `http://localhost:8000` | |
| `--batch-size` | `20000` lines | Uploads the file in bounded chunks rather than one giant request — safe for files well beyond this size. |
| `--api-key` | read from `.env` | Same `TINYSIEM_API_KEY` lookup as `scripts/ingest_test_logs.py`; override if ingesting against a different instance. |

The script streams the file line-by-line (it never loads the whole file into memory), retries a failed batch up to 3 times before giving up on it, and aborts immediately on an authentication error (401/403) rather than retrying.

### 4. Verify

The script prints a running `processed`/`failed` count and a final summary. Any row that didn't decode is written, with its original file line number and content, to `<file>.rejects.jsonl` next to the input file — nothing is silently dropped. If everything decoded cleanly, no rejects file is created.

Check that events landed:
```bash
curl -s "http://localhost:8000/events?source=my_custom_csv&limit=5" \
  -H "Authorization: Bearer <jwt>"
```

### Notes

- `type: csv` decoders only work through this upload path (`POST /ingest/file`) — they can't be used with `POST /ingest/raw` or the syslog/beats listeners, since decoding a CSV row requires the file's own header line for context.
- CSV values containing embedded newlines inside quotes aren't supported — each row must be a single line, since the file is split line-by-line before decoding.
- This isn't a registered integration: there's no run history, no stored credentials, and nothing to pause or delete afterward. Re-running the script against the same file re-ingests it (each row gets a new event id).

---

## Managing Integrations

### View run history

```bash
curl -s "http://localhost:8000/integrations/<id>/runs?limit=10" \
  -H "Authorization: Bearer <jwt>" | python3 -m json.tool
```

### Pause without deleting

```bash
curl -s -X PATCH "http://localhost:8000/integrations/<id>" \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'
```

### Manually trigger a poll

```bash
curl -s -X POST "http://localhost:8000/integrations/<id>/trigger" \
  -H "Authorization: Bearer <jwt>"
```

### Delete

```bash
curl -s -X DELETE "http://localhost:8000/integrations/<id>" \
  -H "Authorization: Bearer <jwt>"
```

Deletion removes the integration and all run history. Credentials are also purged from the database.

---

→ [API Reference — Integrations](api-reference.md#api-integrations) — full endpoint documentation  
→ [Troubleshooting — Integrations](troubleshooting.md#api-integrations) — common errors  
→ [Configuration](configuration.md#api-integrations) — TINYSIEM_MASTER_KEY setup

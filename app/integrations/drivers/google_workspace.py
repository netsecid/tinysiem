"""Google Workspace integration driver — pulls from Reports API."""
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)

integration_type = "google_workspace"
display_name = "Google Workspace"
credential_fields = ["service_account_json"]
config_fields = ["admin_email", "application_name"]


async def pull(
    config: dict,
    credentials: dict,
    cursor: Optional[str],
) -> tuple[list[dict], Optional[str]]:
    try:
        from googleapiclient.discovery import build
        from google.oauth2 import service_account
    except ImportError:
        raise RuntimeError(
            "google-api-python-client and google-auth are not installed. "
            "Add them to requirements.txt and rebuild."
        )

    admin_email = config.get("admin_email", "")
    app_name = config.get("application_name", "login")
    source_name = f"google_workspace_{app_name}"

    sa_info = json.loads(credentials.get("service_account_json", "{}"))
    scopes = ["https://www.googleapis.com/auth/admin.reports.audit.readonly"]
    creds = service_account.Credentials.from_service_account_info(sa_info, scopes=scopes)
    delegated = creds.with_subject(admin_email)

    service = build("admin", "reports_v1", credentials=delegated)

    start_time = cursor or (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    kwargs = {"userKey": "all", "applicationName": app_name, "startTime": start_time}
    resp = service.activities().list(**kwargs).execute()

    events: list[dict] = []
    new_cursor = start_time
    for item in resp.get("items", []):
        events.append({"source": source_name, "raw": json.dumps(item)})
        ts = item.get("id", {}).get("time", "")
        if ts > new_cursor:
            new_cursor = ts

    logger.info("google_workspace pulled %d events for app=%s", len(events), app_name)
    return events, new_cursor

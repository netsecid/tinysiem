"""AWS CloudTrail integration driver — pulls from S3 or CloudWatch Logs."""
import gzip
import json
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

integration_type = "aws_cloudtrail"
display_name = "AWS CloudTrail"
credential_fields = ["aws_access_key_id", "aws_secret_access_key"]
config_fields = ["region", "s3_bucket"]


async def pull(
    config: dict,
    credentials: dict,
    cursor: Optional[str],
) -> tuple[list[dict], Optional[str]]:
    try:
        import boto3
    except ImportError:
        raise RuntimeError("boto3 is not installed. Add boto3 to requirements.txt and rebuild.")

    region = config.get("region", "us-east-1")
    s3_bucket = config.get("s3_bucket", "")
    since_ts = cursor or (datetime.now(timezone.utc).isoformat())

    session = boto3.Session(
        aws_access_key_id=credentials.get("aws_access_key_id"),
        aws_secret_access_key=credentials.get("aws_secret_access_key"),
        region_name=region,
    )

    events: list[dict] = []
    new_cursor = since_ts

    if s3_bucket:
        s3 = session.client("s3")
        paginator = s3.get_paginator("list_objects_v2")
        pages = paginator.paginate(Bucket=s3_bucket, Prefix="AWSLogs/")
        for page in pages:
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if not key.endswith(".json.gz"):
                    continue
                body = s3.get_object(Bucket=s3_bucket, Key=key)["Body"].read()
                data = json.loads(gzip.decompress(body))
                for record in data.get("Records", []):
                    events.append({"source": "aws_cloudtrail", "raw": json.dumps(record)})
                if obj["LastModified"].isoformat() > new_cursor:
                    new_cursor = obj["LastModified"].isoformat()
            if len(events) >= 1000:
                break
    else:
        logs = session.client("logs")
        start_ms = int(datetime.fromisoformat(since_ts.replace("Z", "+00:00")).timestamp() * 1000)
        kwargs = {"logGroupName": "/aws/cloudtrail", "startTime": start_ms, "limit": 1000}
        resp = logs.filter_log_events(**kwargs)
        for ev in resp.get("events", []):
            events.append({"source": "aws_cloudtrail", "raw": ev.get("message", "")})
            new_cursor = str(ev.get("timestamp", start_ms))

    logger.info("aws_cloudtrail pulled %d events", len(events))
    return events, new_cursor

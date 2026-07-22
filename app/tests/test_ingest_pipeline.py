import uuid
from datetime import datetime, timezone

from app.ingest import pipeline


def test_store_and_evaluate_inserts_and_returns_event_id():
    event = {
        "id": str(uuid.uuid4()),
        "source": "nginx",
        "ingested_at": datetime.now(timezone.utc),
        "raw": "manually constructed event",
    }

    event_id = pipeline.store_and_evaluate(event)

    assert event_id == event["id"]


def test_process_line_still_returns_event_id():
    event_id = pipeline.process_line(
        "nginx",
        '192.168.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 42 "-" "curl/7.88.1"',
        strict=True,
    )
    assert event_id

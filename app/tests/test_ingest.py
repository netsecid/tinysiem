import pytest

VALID_LOG = (
    '192.168.1.1 - - [10/Oct/2023:13:55:36 +0000] '
    '"GET /api/v1/health HTTP/1.1" 200 42 "-" "curl/7.88.1"'
)


async def test_ingest_raw_returns_200(client, auth_headers):
    response = await client.post(
        "/ingest/raw",
        json={"source": "nginx", "raw": VALID_LOG},
        headers=auth_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "event_id" in body
    assert body["event_id"]  # non-empty UUID


async def test_ingest_raw_no_api_key_returns_401(client):
    response = await client.post(
        "/ingest/raw",
        json={"source": "nginx", "raw": VALID_LOG},
    )
    assert response.status_code == 401


async def test_ingest_raw_malformed_payload_returns_422(client, auth_headers):
    response = await client.post(
        "/ingest/raw",
        json={"invalid_field": "no source or raw"},
        headers=auth_headers,
    )
    assert response.status_code == 422


async def test_api_key_cannot_access_non_ingest_endpoints(client, auth_headers):
    resp = await client.get("/events", headers=auth_headers)
    assert resp.status_code == 401

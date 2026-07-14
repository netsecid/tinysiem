"""Tests for AI endpoints and enrichment context builder."""


async def test_explain_alert_no_key(client, analyst_headers):
    """Returns 503 when no ai_config row exists (default in test env)."""
    r = await client.post(
        "/ai/explain-alert",
        json={"alert_id": "nonexistent-id"},
        headers=analyst_headers,
    )
    assert r.status_code == 503
    assert "AI features require configuration" in r.json()["detail"]


async def test_explain_alert_requires_auth(client):
    r = await client.post("/ai/explain-alert", json={"alert_id": "any"})
    assert r.status_code == 401


async def test_analyze_events_no_key(client, analyst_headers):
    r = await client.post(
        "/ai/analyze-events",
        json={"event_ids": ["some-id"], "question": "What is happening?"},
        headers=analyst_headers,
    )
    assert r.status_code == 503


async def test_analyze_events_requires_auth(client):
    r = await client.post(
        "/ai/analyze-events",
        json={"event_ids": ["id1"], "question": "test"},
    )
    assert r.status_code == 401


async def test_analyze_events_too_many_ids(client, analyst_headers):
    many_ids = [str(i) for i in range(51)]
    r = await client.post(
        "/ai/analyze-events",
        json={"event_ids": many_ids, "question": "test"},
        headers=analyst_headers,
    )
    assert r.status_code == 422


async def test_analyze_events_empty_ids(client, analyst_headers):
    r = await client.post(
        "/ai/analyze-events",
        json={"event_ids": [], "question": "test"},
        headers=analyst_headers,
    )
    assert r.status_code == 422


def test_build_generation_context():
    from app.ai.enrichment import build_generation_context
    ctx = build_generation_context()
    assert "<context>" in ctx
    assert "Active log sources:" in ctx
    assert "Existing parsers:" in ctx
    assert "Existing rules:" in ctx
    assert "DuckDB schema" in ctx
    assert "</context>" in ctx

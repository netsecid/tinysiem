"""Tests for POST /ai/search."""
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _clear_ai_config():
    """See the identical fixture in test_ai_config_store.py for why this clears both
    before and after each test (this project's test suite shares one session-scoped
    DuckDB database across every test file)."""
    from app.storage.duckdb_store import _get_conn, _lock
    def _clear():
        with _lock:
            _get_conn().execute("DELETE FROM ai_config")
    _clear()
    yield
    _clear()


async def test_search_requires_auth(client):
    r = await client.post("/ai/search", json={"question": "show me alerts"})
    assert r.status_code == 401


async def test_search_unconfigured_returns_503(client, analyst_headers):
    r = await client.post("/ai/search", json={"question": "show me alerts"}, headers=analyst_headers)
    assert r.status_code == 503
    assert "AI features require configuration" in r.json()["detail"]


async def test_search_happy_path(client, analyst_headers):
    from app.ai import config_store
    config_store.save_ai_config(
        provider="anthropic", model="claude-sonnet-4-6",
        base_url=None, api_key="sk-ant-test", updated_by="admin",
    )
    mock_result = MagicMock()
    mock_result.text = '{"target": "alerts", "filters": {"severity": "critical"}}'
    mock_answer = MagicMock()
    mock_answer.text = "2 critical alerts found."

    with patch("app.ai.providers.anthropic_provider.AnthropicProvider.chat", side_effect=[mock_result, mock_answer]):
        with patch("app.ai.home_search._query_alerts", return_value=(2, {"severity_breakdown": {"critical": 2}})):
            r = await client.post("/ai/search", json={"question": "critical alerts"}, headers=analyst_headers)

    assert r.status_code == 200
    body = r.json()
    assert body["answer"] == "2 critical alerts found."
    assert body["link"] == "/ui/alerts.html?severity=critical"
    assert body["link_label"] == "View 2 alerts"


async def test_search_provider_error_returns_502(client, analyst_headers):
    from app.ai import config_store
    config_store.save_ai_config(
        provider="anthropic", model="claude-sonnet-4-6",
        base_url=None, api_key="sk-ant-test", updated_by="admin",
    )
    with patch("app.ai.providers.anthropic_provider.AnthropicProvider.chat", side_effect=Exception("rate limited")):
        r = await client.post("/ai/search", json={"question": "critical alerts"}, headers=analyst_headers)
    assert r.status_code == 502
    assert "AI provider error" in r.json()["detail"]


async def test_search_requires_question_field(client, analyst_headers):
    r = await client.post("/ai/search", json={}, headers=analyst_headers)
    assert r.status_code == 422

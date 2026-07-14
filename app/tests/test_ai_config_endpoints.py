"""Tests for GET/PUT /ai/config and POST /ai/config/test."""
import pytest
from unittest.mock import MagicMock, patch


@pytest.fixture(autouse=True)
def _clear_ai_config():
    """See the identical fixture in test_ai_config_store.py for why this clears both
    before and after each test (protects against cross-file pollution in both directions,
    since this project's test suite shares one session-scoped DuckDB database)."""
    from app.storage.duckdb_store import _get_conn, _lock
    def _clear():
        with _lock:
            _get_conn().execute("DELETE FROM ai_config")
    _clear()
    yield
    _clear()


async def test_get_ai_config_requires_auth(client):
    r = await client.get("/ai/config")
    assert r.status_code == 401


async def test_get_ai_config_requires_admin(client, analyst_headers):
    r = await client.get("/ai/config", headers=analyst_headers)
    assert r.status_code == 403


async def test_get_ai_config_unconfigured(client, admin_headers):
    r = await client.get("/ai/config", headers=admin_headers)
    assert r.status_code == 200
    assert r.json() == {"configured": False}


async def test_put_ai_config_requires_admin(client, analyst_headers):
    r = await client.put(
        "/ai/config",
        json={"provider": "anthropic", "model": "claude-sonnet-4-6", "api_key": "sk-ant-test"},
        headers=analyst_headers,
    )
    assert r.status_code == 403


async def test_put_ai_config_unknown_provider_rejected(client, admin_headers):
    r = await client.put(
        "/ai/config",
        json={"provider": "not-a-real-provider", "model": "whatever", "api_key": "x"},
        headers=admin_headers,
    )
    assert r.status_code == 422


async def test_put_ai_config_unknown_model_rejected(client, admin_headers):
    r = await client.put(
        "/ai/config",
        json={"provider": "anthropic", "model": "not-a-real-model", "api_key": "sk-ant-test"},
        headers=admin_headers,
    )
    assert r.status_code == 422


async def test_put_ai_config_missing_api_key_rejected_for_anthropic(client, admin_headers):
    r = await client.put(
        "/ai/config",
        json={"provider": "anthropic", "model": "claude-sonnet-4-6"},
        headers=admin_headers,
    )
    assert r.status_code == 422


async def test_put_ai_config_custom_requires_base_url(client, admin_headers):
    r = await client.put(
        "/ai/config",
        json={"provider": "custom", "model": "llama3.1"},
        headers=admin_headers,
    )
    assert r.status_code == 422


async def test_put_ai_config_custom_requires_model(client, admin_headers):
    r = await client.put(
        "/ai/config",
        json={"provider": "custom", "model": "", "base_url": "http://localhost:11434/v1"},
        headers=admin_headers,
    )
    assert r.status_code == 422


async def test_put_ai_config_custom_no_api_key_ok(client, admin_headers):
    r = await client.put(
        "/ai/config",
        json={"provider": "custom", "model": "llama3.1", "base_url": "http://localhost:11434/v1"},
        headers=admin_headers,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["configured"] is True
    assert body["provider"] == "custom"
    assert body["has_api_key"] is False


async def test_put_ai_config_success_then_get_reflects_it(client, admin_headers):
    r = await client.put(
        "/ai/config",
        json={"provider": "anthropic", "model": "claude-sonnet-4-6", "api_key": "sk-ant-test"},
        headers=admin_headers,
    )
    assert r.status_code == 200
    r2 = await client.get("/ai/config", headers=admin_headers)
    body = r2.json()
    assert body["configured"] is True
    assert body["provider"] == "anthropic"
    assert body["model"] == "claude-sonnet-4-6"
    assert body["has_api_key"] is True
    assert "api_key" not in body


async def test_put_ai_config_blank_api_key_keeps_existing(client, admin_headers):
    await client.put(
        "/ai/config",
        json={"provider": "anthropic", "model": "claude-sonnet-4-6", "api_key": "sk-ant-original"},
        headers=admin_headers,
    )
    r = await client.put(
        "/ai/config",
        json={"provider": "anthropic", "model": "claude-opus-4-8"},
        headers=admin_headers,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["model"] == "claude-opus-4-8"
    assert body["has_api_key"] is True


async def test_put_ai_config_switching_provider_clears_old_key(client, admin_headers):
    """Switching provider without a new key must not leak the previous provider's key."""
    await client.put(
        "/ai/config",
        json={"provider": "anthropic", "model": "claude-sonnet-4-6", "api_key": "sk-ant-original"},
        headers=admin_headers,
    )
    r = await client.put(
        "/ai/config",
        json={"provider": "custom", "model": "llama3.1", "base_url": "http://localhost:11434/v1"},
        headers=admin_headers,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["provider"] == "custom"
    assert body["has_api_key"] is False


async def test_put_ai_config_switching_to_key_requiring_provider_without_key_rejected(client, admin_headers):
    """A key stored under one provider must not satisfy the 'key already configured'
    check when switching to a DIFFERENT key-requiring provider — must be rejected with
    422, not silently saved keyless (which save_ai_config would otherwise do)."""
    await client.put(
        "/ai/config",
        json={"provider": "anthropic", "model": "claude-sonnet-4-6", "api_key": "sk-ant-original"},
        headers=admin_headers,
    )
    r = await client.put(
        "/ai/config",
        json={"provider": "openai", "model": "gpt-4o"},
        headers=admin_headers,
    )
    assert r.status_code == 422
    assert "api_key is required" in r.json()["detail"]


async def test_test_ai_config_requires_admin(client, analyst_headers):
    r = await client.post("/ai/config/test", headers=analyst_headers)
    assert r.status_code == 403


async def test_test_ai_config_unconfigured_returns_failure(client, admin_headers):
    r = await client.post("/ai/config/test", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is False
    assert "AI features require configuration" in body["detail"]


async def test_test_ai_config_success(client, admin_headers):
    await client.put(
        "/ai/config",
        json={"provider": "anthropic", "model": "claude-sonnet-4-6", "api_key": "sk-ant-test"},
        headers=admin_headers,
    )
    mock_result = MagicMock()
    mock_result.text = "OK"
    with patch("app.ai.providers.anthropic_provider.AnthropicProvider.chat", return_value=mock_result):
        r = await client.post("/ai/config/test", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is True
    assert body["detail"] == "OK"


async def test_put_ai_config_without_master_key_returns_503(client, admin_headers, monkeypatch):
    """When TINYSIEM_MASTER_KEY is unset, saving a config with an api_key must not leak
    an uncaught 500/traceback from crypto.encrypt() — it should be converted to a clean
    503, matching the pattern used by the integrations router."""
    from app.config import settings
    monkeypatch.setattr(settings, "tinysiem_master_key", "")
    r = await client.put(
        "/ai/config",
        json={"provider": "anthropic", "model": "claude-sonnet-4-6", "api_key": "sk-ant-test"},
        headers=admin_headers,
    )
    assert r.status_code == 503
    assert "TINYSIEM_MASTER_KEY" in r.json()["detail"]


async def test_test_ai_config_provider_error_returns_failure_not_exception(client, admin_headers):
    await client.put(
        "/ai/config",
        json={"provider": "anthropic", "model": "claude-sonnet-4-6", "api_key": "sk-ant-bad-key"},
        headers=admin_headers,
    )
    with patch("app.ai.providers.anthropic_provider.AnthropicProvider.chat", side_effect=Exception("invalid x-api-key")):
        r = await client.post("/ai/config/test", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is False
    assert "invalid x-api-key" in body["detail"]

"""Tests for app/ai/provider_factory.py."""
import pytest


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


def test_get_active_provider_raises_when_unconfigured():
    from app.ai.provider_factory import get_active_provider
    with pytest.raises(RuntimeError, match="AI features require configuration"):
        get_active_provider()


def test_get_active_provider_returns_anthropic_provider():
    from app.ai import config_store
    from app.ai.provider_factory import get_active_provider
    from app.ai.providers.anthropic_provider import AnthropicProvider

    config_store.save_ai_config(
        provider="anthropic", model="claude-sonnet-4-6",
        base_url=None, api_key="sk-ant-test", updated_by="admin",
    )
    provider = get_active_provider()
    assert isinstance(provider, AnthropicProvider)
    assert provider.model == "claude-sonnet-4-6"
    assert provider.api_key == "sk-ant-test"


def test_get_active_provider_returns_openai_compatible_for_named_preset():
    from app.ai import config_store
    from app.ai.provider_factory import get_active_provider
    from app.ai.providers.openai_compatible_provider import OpenAICompatibleProvider

    config_store.save_ai_config(
        provider="openai", model="gpt-4o",
        base_url=None, api_key="sk-openai-test", updated_by="admin",
    )
    provider = get_active_provider()
    assert isinstance(provider, OpenAICompatibleProvider)
    assert provider.base_url == "https://api.openai.com/v1"
    assert provider.model == "gpt-4o"


def test_get_active_provider_uses_stored_base_url_for_custom():
    from app.ai import config_store
    from app.ai.provider_factory import get_active_provider
    from app.ai.providers.openai_compatible_provider import OpenAICompatibleProvider

    config_store.save_ai_config(
        provider="custom", model="llama3.1",
        base_url="http://localhost:11434/v1", api_key=None, updated_by="admin",
    )
    provider = get_active_provider()
    assert isinstance(provider, OpenAICompatibleProvider)
    assert provider.base_url == "http://localhost:11434/v1"
    assert provider.api_key is None

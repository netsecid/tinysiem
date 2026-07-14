"""Tests for the ai_config table CRUD (app/ai/config_store.py)."""
import pytest


@pytest.fixture(autouse=True)
def _clear_ai_config():
    """This project's test suite shares one session-scoped DuckDB database across every
    test file (see app/tests/conftest.py). Clearing both before AND after each test here
    protects two directions at once: before, so a row left behind by test_provider_factory.py
    or test_ai_config_endpoints.py running first doesn't pollute this file's 'unconfigured'
    assertions; after, so existing files that assume AI is unconfigured by default
    (test_ai.py, test_parsers.py, test_rules_crud.py, test_playbook.py — none of which
    know about this table) aren't broken by a row this file's own last test left behind."""
    from app.storage.duckdb_store import _get_conn, _lock
    def _clear():
        with _lock:
            _get_conn().execute("DELETE FROM ai_config")
    _clear()
    yield
    _clear()


def test_get_ai_config_returns_none_when_unset():
    from app.ai import config_store
    assert config_store.get_ai_config() is None


def test_save_and_get_ai_config_roundtrip():
    from app.ai import config_store
    saved = config_store.save_ai_config(
        provider="anthropic", model="claude-sonnet-4-6",
        base_url=None, api_key="sk-ant-test-key", updated_by="admin",
    )
    assert saved["provider"] == "anthropic"
    assert saved["model"] == "claude-sonnet-4-6"
    assert saved["base_url"] is None
    assert saved["has_api_key"] is True
    assert saved["updated_by"] == "admin"

    fetched = config_store.get_ai_config()
    assert fetched["provider"] == "anthropic"
    assert fetched["has_api_key"] is True
    # The plaintext key is never present in the public view.
    assert "api_key" not in fetched
    assert "api_key_encrypted" not in fetched


def test_get_decrypted_api_key_roundtrips():
    from app.ai import config_store
    config_store.save_ai_config(
        provider="anthropic", model="claude-sonnet-4-6",
        base_url=None, api_key="sk-ant-secret-value", updated_by="admin",
    )
    assert config_store.get_decrypted_api_key() == "sk-ant-secret-value"


def test_get_decrypted_api_key_none_when_unset():
    from app.ai import config_store
    assert config_store.get_decrypted_api_key() is None


def test_save_ai_config_blank_api_key_leaves_existing_key_unchanged():
    from app.ai import config_store
    config_store.save_ai_config(
        provider="anthropic", model="claude-sonnet-4-6",
        base_url=None, api_key="sk-ant-original", updated_by="admin",
    )
    config_store.save_ai_config(
        provider="anthropic", model="claude-opus-4-8",
        base_url=None, api_key=None, updated_by="admin",
    )
    updated = config_store.get_ai_config()
    assert updated["model"] == "claude-opus-4-8"
    assert updated["has_api_key"] is True
    assert config_store.get_decrypted_api_key() == "sk-ant-original"


def test_save_ai_config_custom_provider_stores_base_url():
    from app.ai import config_store
    saved = config_store.save_ai_config(
        provider="custom", model="llama3.1",
        base_url="http://localhost:11434/v1", api_key=None, updated_by="admin",
    )
    assert saved["base_url"] == "http://localhost:11434/v1"
    assert saved["has_api_key"] is False


def test_save_ai_config_switching_provider_does_not_leak_old_key():
    """Switching provider without supplying a new key must NOT silently carry over
    the previous provider's key — 'blank means unchanged' only applies when staying
    on the same provider."""
    from app.ai import config_store
    config_store.save_ai_config(
        provider="anthropic", model="claude-sonnet-4-6",
        base_url=None, api_key="sk-ant-secret", updated_by="admin",
    )
    switched = config_store.save_ai_config(
        provider="custom", model="llama3.1",
        base_url="http://localhost:11434/v1", api_key=None, updated_by="admin",
    )
    assert switched["has_api_key"] is False
    assert config_store.get_decrypted_api_key() is None

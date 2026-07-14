"""Tests for app/ai/home_search.py."""
import json
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _clear_ai_config():
    """This project's test suite shares one session-scoped DuckDB database across every
    test file — clearing both before and after each test protects this file's tests from
    cross-file pollution regardless of execution order, matching the identical fixture in
    test_ai_config_store.py/test_provider_factory.py/test_ai_config_endpoints.py."""
    from app.storage.duckdb_store import _get_conn, _lock
    def _clear():
        with _lock:
            _get_conn().execute("DELETE FROM ai_config")
    _clear()
    yield
    _clear()


def _configure_ai():
    from app.ai import config_store
    config_store.save_ai_config(
        provider="anthropic", model="claude-sonnet-4-6",
        base_url=None, api_key="sk-ant-test", updated_by="admin",
    )


def test_extract_search_intent_valid_alerts_target():
    from app.ai.home_search import extract_search_intent
    _configure_ai()
    mock_result = MagicMock()
    mock_result.text = json.dumps({"target": "alerts", "filters": {"severity": "critical"}})
    with patch("app.ai.providers.anthropic_provider.AnthropicProvider.chat", return_value=mock_result):
        intent = extract_search_intent("show me critical alerts")
    assert intent == {"target": "alerts", "filters": {"severity": "critical"}}


def test_extract_search_intent_target_null_for_non_search_question():
    from app.ai.home_search import extract_search_intent
    _configure_ai()
    mock_result = MagicMock()
    mock_result.text = json.dumps({"target": None, "filters": {}})
    with patch("app.ai.providers.anthropic_provider.AnthropicProvider.chat", return_value=mock_result):
        intent = extract_search_intent("what is TinySIEM?")
    assert intent == {"target": None, "filters": {}}


def test_extract_search_intent_malformed_json_falls_back_to_null():
    from app.ai.home_search import extract_search_intent
    _configure_ai()
    mock_result = MagicMock()
    mock_result.text = "this is not valid JSON at all"
    with patch("app.ai.providers.anthropic_provider.AnthropicProvider.chat", return_value=mock_result):
        intent = extract_search_intent("show me events")
    assert intent == {"target": None, "filters": {}}


def test_extract_search_intent_unknown_target_falls_back_to_null():
    from app.ai.home_search import extract_search_intent
    _configure_ai()
    mock_result = MagicMock()
    mock_result.text = json.dumps({"target": "rules", "filters": {}})
    with patch("app.ai.providers.anthropic_provider.AnthropicProvider.chat", return_value=mock_result):
        intent = extract_search_intent("show me rules")
    assert intent == {"target": None, "filters": {}}


def test_extract_search_intent_drops_filter_keys_not_valid_for_target():
    """A filter key that doesn't belong to the target's allowed set (e.g. the AI
    hallucinates 'severity' for events, which has no such field) must be dropped
    rather than passed through to the query layer."""
    from app.ai.home_search import extract_search_intent
    _configure_ai()
    mock_result = MagicMock()
    mock_result.text = json.dumps({"target": "events", "filters": {"status_code": 404, "severity": "high"}})
    with patch("app.ai.providers.anthropic_provider.AnthropicProvider.chat", return_value=mock_result):
        intent = extract_search_intent("show me 404s")
    assert intent == {"target": "events", "filters": {"status_code": 404}}


def test_extract_search_intent_drops_empty_string_filter_values():
    from app.ai.home_search import extract_search_intent
    _configure_ai()
    mock_result = MagicMock()
    mock_result.text = json.dumps({"target": "alerts", "filters": {"severity": "", "rule_name": "brute-force"}})
    with patch("app.ai.providers.anthropic_provider.AnthropicProvider.chat", return_value=mock_result):
        intent = extract_search_intent("brute force alerts")
    assert intent == {"target": "alerts", "filters": {"rule_name": "brute-force"}}


def test_extract_search_intent_raises_when_ai_unconfigured():
    from app.ai.home_search import extract_search_intent
    with pytest.raises(RuntimeError, match="AI features require configuration"):
        extract_search_intent("show me alerts")

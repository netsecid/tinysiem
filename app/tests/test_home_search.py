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


def test_run_search_alerts_target_builds_link_and_answer():
    from app.ai import home_search
    _configure_ai()

    mock_intent_result = MagicMock()
    mock_intent_result.text = json.dumps({"target": "alerts", "filters": {"severity": "critical"}})
    mock_answer_result = MagicMock()
    mock_answer_result.text = "There are 2 critical alerts, both brute-force attempts from 192.168.1.50."

    with patch("app.ai.providers.anthropic_provider.AnthropicProvider.chat", side_effect=[mock_intent_result, mock_answer_result]):
        with patch("app.ai.home_search._query_alerts", return_value=(2, {"severity_breakdown": {"critical": 2}})):
            result = home_search.run_search("show me critical alerts", actor="analyst1")

    assert result["answer"] == "There are 2 critical alerts, both brute-force attempts from 192.168.1.50."
    assert result["link"] == "/ui/alerts.html?severity=critical"
    assert result["link_label"] == "View 2 alerts"


def test_run_search_events_target_builds_link_with_multiple_filters():
    from app.ai import home_search
    _configure_ai()

    mock_intent_result = MagicMock()
    mock_intent_result.text = json.dumps({"target": "events", "filters": {"status_code": 404, "method": "GET"}})
    mock_answer_result = MagicMock()
    mock_answer_result.text = "12 GET requests returned 404."

    with patch("app.ai.providers.anthropic_provider.AnthropicProvider.chat", side_effect=[mock_intent_result, mock_answer_result]):
        with patch("app.ai.home_search._query_events", return_value=(12, {"status_code_breakdown": {"404": 12}})):
            result = home_search.run_search("show me 404 GET requests", actor="analyst1")

    assert result["link"] == "/ui/events.html?status_code=404&method=GET"
    assert result["link_label"] == "View 12 events"


def test_run_search_cases_target_builds_link():
    from app.ai import home_search
    _configure_ai()

    mock_intent_result = MagicMock()
    mock_intent_result.text = json.dumps({"target": "cases", "filters": {"status": "open"}})
    mock_answer_result = MagicMock()
    mock_answer_result.text = "There are 3 open cases."

    with patch("app.ai.providers.anthropic_provider.AnthropicProvider.chat", side_effect=[mock_intent_result, mock_answer_result]):
        with patch("app.ai.home_search._query_cases", return_value=(3, {"status_breakdown": {"open": 3}})):
            result = home_search.run_search("open cases", actor="analyst1")

    assert result["link"] == "/ui/cases.html?status=open"
    assert result["link_label"] == "View 3 cases"


def test_run_search_zero_results_still_returns_link():
    from app.ai import home_search
    _configure_ai()

    mock_intent_result = MagicMock()
    mock_intent_result.text = json.dumps({"target": "alerts", "filters": {"severity": "critical"}})
    mock_answer_result = MagicMock()
    mock_answer_result.text = "No critical alerts found in that window."

    with patch("app.ai.providers.anthropic_provider.AnthropicProvider.chat", side_effect=[mock_intent_result, mock_answer_result]):
        with patch("app.ai.home_search._query_alerts", return_value=(0, {"severity_breakdown": {}})):
            result = home_search.run_search("critical alerts", actor="analyst1")

    assert result["link"] == "/ui/alerts.html?severity=critical"
    assert result["link_label"] == "View 0 alerts"


def test_run_search_null_target_skips_querying_and_returns_no_link():
    from app.ai import home_search
    _configure_ai()

    mock_intent_result = MagicMock()
    mock_intent_result.text = json.dumps({"target": None, "filters": {}})
    mock_answer_result = MagicMock()
    mock_answer_result.text = "TinySIEM is a tiny SIEM for learning and small deployments."

    with patch("app.ai.providers.anthropic_provider.AnthropicProvider.chat", side_effect=[mock_intent_result, mock_answer_result]):
        with patch("app.ai.home_search._query_events") as mock_qe, \
             patch("app.ai.home_search._query_alerts") as mock_qa, \
             patch("app.ai.home_search._query_cases") as mock_qc:
            result = home_search.run_search("what is TinySIEM?", actor="analyst1")
            mock_qe.assert_not_called()
            mock_qa.assert_not_called()
            mock_qc.assert_not_called()

    assert result["link"] is None
    assert result["link_label"] is None
    assert result["answer"] == "TinySIEM is a tiny SIEM for learning and small deployments."


def test_run_search_raises_when_ai_unconfigured():
    from app.ai import home_search
    with pytest.raises(RuntimeError, match="AI features require configuration"):
        home_search.run_search("show me alerts", actor="analyst1")

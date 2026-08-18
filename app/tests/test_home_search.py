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
    assert intent == {"target": "alerts", "filters": {"severity": "critical"}, "group_by": None}


def test_extract_search_intent_target_null_for_non_search_question():
    from app.ai.home_search import extract_search_intent
    _configure_ai()
    mock_result = MagicMock()
    mock_result.text = json.dumps({"target": None, "filters": {}, "group_by": None})
    with patch("app.ai.providers.anthropic_provider.AnthropicProvider.chat", return_value=mock_result):
        intent = extract_search_intent("what is TinySIEM?")
    assert intent == {"target": None, "filters": {}, "group_by": None}


def test_extract_search_intent_malformed_json_falls_back_to_null():
    from app.ai.home_search import extract_search_intent
    _configure_ai()
    mock_result = MagicMock()
    mock_result.text = "this is not valid JSON at all"
    with patch("app.ai.providers.anthropic_provider.AnthropicProvider.chat", return_value=mock_result):
        intent = extract_search_intent("show me events")
    assert intent == {"target": None, "filters": {}, "group_by": None}


def test_extract_search_intent_unknown_target_falls_back_to_null():
    from app.ai.home_search import extract_search_intent
    _configure_ai()
    mock_result = MagicMock()
    mock_result.text = json.dumps({"target": "rules", "filters": {}})
    with patch("app.ai.providers.anthropic_provider.AnthropicProvider.chat", return_value=mock_result):
        intent = extract_search_intent("show me rules")
    assert intent == {"target": None, "filters": {}, "group_by": None}


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
    assert intent == {"target": "events", "filters": {"status_code": 404}, "group_by": None}


def test_extract_search_intent_drops_empty_string_filter_values():
    from app.ai.home_search import extract_search_intent
    _configure_ai()
    mock_result = MagicMock()
    mock_result.text = json.dumps({"target": "alerts", "filters": {"severity": "", "rule_name": "brute-force"}})
    with patch("app.ai.providers.anthropic_provider.AnthropicProvider.chat", return_value=mock_result):
        intent = extract_search_intent("brute force alerts")
    assert intent == {"target": "alerts", "filters": {"rule_name": "brute-force"}, "group_by": None}


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
    mock_intent_result.text = json.dumps({"target": None, "filters": {}, "group_by": None})
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


def test_extract_search_intent_empty_provider_response_raises():
    """A provider that returns empty content (reasoning model burning its whole
    token budget) must raise loudly instead of silently falling back to null."""
    from app.ai.home_search import extract_search_intent
    _configure_ai()
    mock_result = MagicMock()
    mock_result.text = "   "
    with patch("app.ai.providers.anthropic_provider.AnthropicProvider.chat", return_value=mock_result):
        with pytest.raises(RuntimeError, match="empty response"):
            extract_search_intent("show me events")


def test_extract_search_intent_group_by_source_ip_passthrough():
    from app.ai.home_search import extract_search_intent
    _configure_ai()
    mock_result = MagicMock()
    mock_result.text = json.dumps(
        {"target": "events", "filters": {"method": "Failed password"}, "group_by": "source_ip"}
    )
    with patch("app.ai.providers.anthropic_provider.AnthropicProvider.chat", return_value=mock_result):
        intent = extract_search_intent("top 10 ip attacking")
    assert intent == {"target": "events", "filters": {"method": "Failed password"}, "group_by": "source_ip"}


def test_extract_search_intent_group_by_cleared_for_non_events_target():
    from app.ai.home_search import extract_search_intent
    _configure_ai()
    mock_result = MagicMock()
    mock_result.text = json.dumps(
        {"target": "alerts", "filters": {"severity": "high"}, "group_by": "source_ip"}
    )
    with patch("app.ai.providers.anthropic_provider.AnthropicProvider.chat", return_value=mock_result):
        intent = extract_search_intent("top 10 attacking ip in alerts")
    assert intent == {"target": "alerts", "filters": {"severity": "high"}, "group_by": None}


def test_extract_search_intent_invalid_group_by_cleared():
    from app.ai.home_search import extract_search_intent
    _configure_ai()
    mock_result = MagicMock()
    mock_result.text = json.dumps({"target": "events", "filters": {}, "group_by": "method"})
    with patch("app.ai.providers.anthropic_provider.AnthropicProvider.chat", return_value=mock_result):
        intent = extract_search_intent("top methods")
    assert intent == {"target": "events", "filters": {}, "group_by": None}


def test_run_search_group_by_source_ip_feeds_top_ips_into_summary_context():
    """A 'top N ip' question must surface the real GROUP BY source_ip results as
    context for the summary LLM — not just the event count."""
    from app.ai import home_search
    _configure_ai()

    mock_intent_result = MagicMock()
    mock_intent_result.text = json.dumps(
        {"target": "events", "filters": {"method": "Failed password"}, "group_by": "source_ip"}
    )
    mock_answer_result = MagicMock()
    mock_answer_result.text = "Top attacker: 45.153.34.161 with 500 events."

    with patch(
        "app.ai.providers.anthropic_provider.AnthropicProvider.chat",
        side_effect=[mock_intent_result, mock_answer_result],
    ) as mock_chat:
        with patch("app.ai.home_search._query_events", return_value=(1863, {"status_code_breakdown": {}})):
            with patch("app.ai.home_search._top_source_ips", return_value=[
                {"ip": "45.153.34.161", "count": 500},
                {"ip": "103.146.187.10", "count": 300},
            ]):
                result = home_search.run_search("top 10 ip attacking", actor="analyst1")

    assert result["answer"] == "Top attacker: 45.153.34.161 with 500 events."
    assert result["link"] == "/ui/events.html?method=Failed+password"
    assert result["link_label"] == "View 1863 events"

    summary_call_kwargs = mock_chat.call_args_list[1].kwargs
    summary_user = summary_call_kwargs["user"]
    assert "45.153.34.161: 500 events" in summary_user
    assert "103.146.187.10: 300 events" in summary_user


def test_run_search_empty_summary_response_raises():
    from app.ai import home_search
    _configure_ai()

    mock_intent_result = MagicMock()
    mock_intent_result.text = json.dumps({"target": "alerts", "filters": {"severity": "critical"}, "group_by": None})
    mock_empty = MagicMock()
    mock_empty.text = ""

    with patch(
        "app.ai.providers.anthropic_provider.AnthropicProvider.chat",
        side_effect=[mock_intent_result, mock_empty],
    ):
        with patch("app.ai.home_search._query_alerts", return_value=(2, {"severity_breakdown": {"critical": 2}})):
            with pytest.raises(RuntimeError, match="empty response"):
                home_search.run_search("critical alerts", actor="analyst1")

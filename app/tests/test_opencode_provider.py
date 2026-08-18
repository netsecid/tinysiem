"""Tests for app/ai/providers/opencode_provider.py — mocked at the httpx boundary."""

from unittest.mock import MagicMock, patch


def _fake_response(payload: dict):
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = payload
    return resp


def test_opencode_provider_chat_success():
    from app.ai.providers.opencode_provider import OpenCodeProvider

    session_payload = {"id": "ses_abc123", "title": "tinysiem-ai"}
    message_payload = {
        "info": {"tokens": {"input": 120, "output": 45}},
        "parts": [
            {"type": "step-start"},
            {"type": "reasoning", "text": "thinking..."},
            {"type": "text", "text": "  The top attacker is 1.2.3.4.  "},
            {"type": "step-finish"},
        ],
    }

    with patch("httpx.Client") as mock_cls:
        client = MagicMock()
        client.post.side_effect = [_fake_response(session_payload), _fake_response(message_payload)]
        mock_cls.return_value = client

        provider = OpenCodeProvider(serve_url="http://127.0.0.1:8099", model="opencode/deepseek-v4-flash-free")
        result = provider.chat(system="You are a classifier.", user="classify this", max_tokens=400)

    assert result.text == "The top attacker is 1.2.3.4."
    assert result.model == "opencode/deepseek-v4-flash-free"
    assert result.prompt_tokens == 120
    assert result.completion_tokens == 45

    calls = client.post.call_args_list
    assert calls[0].args[0] == "http://127.0.0.1:8099/session"
    assert calls[1].args[0] == "http://127.0.0.1:8099/session/ses_abc123/message"
    body = calls[1].kwargs["json"]
    assert body["providerID"] == "opencode"
    assert body["model"] == {"providerID": "opencode", "modelID": "deepseek-v4-flash-free"}
    assert body["parts"][0]["text"] == "System: You are a classifier.\n\nUser: classify this"


def test_opencode_provider_bare_model_defaults_to_opencode_provider():
    from app.ai.providers.opencode_provider import OpenCodeProvider

    with patch("httpx.Client"):
        provider = OpenCodeProvider(model="kimi-k3")
    provider_id, model_id = provider._split_model()
    assert (provider_id, model_id) == ("opencode", "kimi-k3")


def test_opencode_provider_go_model_keeps_provider_prefix():
    from app.ai.providers.opencode_provider import OpenCodeProvider

    with patch("httpx.Client"):
        provider = OpenCodeProvider(model="opencode-go/kimi-k3")
    provider_id, model_id = provider._split_model()
    assert (provider_id, model_id) == ("opencode-go", "kimi-k3")


def test_opencode_provider_no_text_parts_returns_empty():
    from app.ai.providers.opencode_provider import OpenCodeProvider

    with patch("httpx.Client") as mock_cls:
        client = MagicMock()
        client.post.side_effect = [
            _fake_response({"id": "ses_x"}),
            _fake_response({"info": {"tokens": {}}, "parts": [{"type": "reasoning", "text": "..."}]}),
        ]
        mock_cls.return_value = client

        provider = OpenCodeProvider(model="opencode/big-pickle")
        result = provider.chat(system="s", user="u", max_tokens=10)

    assert result.text == ""
    assert result.prompt_tokens == 0

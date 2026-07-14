"""Tests for app/ai/providers/ — provider implementations, mocked at the SDK boundary."""
from unittest.mock import MagicMock, patch


def test_anthropic_provider_chat_success():
    from app.ai.providers.anthropic_provider import AnthropicProvider

    mock_response = MagicMock()
    mock_response.content = [MagicMock(text="  Hello, analyst.  ")]
    mock_response.usage.input_tokens = 42
    mock_response.usage.output_tokens = 7

    with patch("anthropic.Anthropic") as mock_anthropic_cls:
        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response
        mock_anthropic_cls.return_value = mock_client

        provider = AnthropicProvider(api_key="sk-ant-test", model="claude-sonnet-4-6")
        result = provider.chat(system="You are helpful.", user="Hi", max_tokens=100)

        assert result.text == "Hello, analyst."
        assert result.model == "claude-sonnet-4-6"
        assert result.prompt_tokens == 42
        assert result.completion_tokens == 7
        mock_anthropic_cls.assert_called_once_with(api_key="sk-ant-test")
        mock_client.messages.create.assert_called_once_with(
            model="claude-sonnet-4-6",
            max_tokens=100,
            system="You are helpful.",
            messages=[{"role": "user", "content": "Hi"}],
        )


def test_anthropic_provider_exposes_model_attribute():
    from app.ai.providers.anthropic_provider import AnthropicProvider
    provider = AnthropicProvider(api_key="sk-ant-test", model="claude-opus-4-8")
    assert provider.model == "claude-opus-4-8"

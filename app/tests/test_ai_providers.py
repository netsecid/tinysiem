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


def test_openai_compatible_provider_chat_success():
    from app.ai.providers.openai_compatible_provider import OpenAICompatibleProvider

    mock_response = MagicMock()
    mock_response.choices = [MagicMock(message=MagicMock(content="  Sure, here you go.  "))]
    mock_response.usage.prompt_tokens = 15
    mock_response.usage.completion_tokens = 9

    with patch("openai.OpenAI") as mock_openai_cls:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai_cls.return_value = mock_client

        provider = OpenAICompatibleProvider(
            base_url="https://api.deepseek.com/v1", api_key="sk-deepseek-test", model="deepseek-chat",
        )
        result = provider.chat(system="You are helpful.", user="Hi", max_tokens=100)

        assert result.text == "Sure, here you go."
        assert result.model == "deepseek-chat"
        assert result.prompt_tokens == 15
        assert result.completion_tokens == 9
        mock_openai_cls.assert_called_once_with(base_url="https://api.deepseek.com/v1", api_key="sk-deepseek-test")
        mock_client.chat.completions.create.assert_called_once_with(
            model="deepseek-chat",
            max_tokens=100,
            messages=[
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "Hi"},
            ],
        )


def test_openai_compatible_provider_no_api_key_uses_placeholder():
    """A local Ollama server needs no real key — the SDK still requires a non-empty string."""
    from app.ai.providers.openai_compatible_provider import OpenAICompatibleProvider

    mock_response = MagicMock()
    mock_response.choices = [MagicMock(message=MagicMock(content="ok"))]
    mock_response.usage = None

    with patch("openai.OpenAI") as mock_openai_cls:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai_cls.return_value = mock_client

        provider = OpenAICompatibleProvider(
            base_url="http://localhost:11434/v1", api_key=None, model="llama3.1",
        )
        result = provider.chat(system="sys", user="hi", max_tokens=50)

        assert result.text == "ok"
        assert result.prompt_tokens == 0
        assert result.completion_tokens == 0
        mock_openai_cls.assert_called_once_with(base_url="http://localhost:11434/v1", api_key="not-needed")

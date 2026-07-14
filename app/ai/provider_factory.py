from app.ai.providers.anthropic_provider import AnthropicProvider
from app.ai.providers.base import AIProvider
from app.ai.providers.openai_compatible_provider import OpenAICompatibleProvider

PROVIDER_PRESETS = {
    "anthropic": {"base_url": None, "models": ["claude-sonnet-4-6", "claude-opus-4-8"]},
    "openai":    {"base_url": "https://api.openai.com/v1", "models": ["gpt-4o", "gpt-4o-mini"]},
    "deepseek":  {"base_url": "https://api.deepseek.com/v1", "models": ["deepseek-chat", "deepseek-reasoner"]},
    "custom":    {"base_url": None, "models": None},
}


def get_active_provider() -> AIProvider:
    from app.ai import config_store

    cfg = config_store.get_ai_config()
    if not cfg:
        raise RuntimeError("AI features require configuration in Settings → AI Config")

    provider_name = cfg["provider"]
    model = cfg["model"]
    api_key = config_store.get_decrypted_api_key()

    if provider_name == "anthropic":
        return AnthropicProvider(api_key=api_key, model=model)

    base_url = cfg["base_url"] or PROVIDER_PRESETS[provider_name]["base_url"]
    return OpenAICompatibleProvider(base_url=base_url, api_key=api_key, model=model)

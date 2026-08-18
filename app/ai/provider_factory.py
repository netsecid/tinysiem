from app.ai.providers.anthropic_provider import AnthropicProvider
from app.ai.providers.base import AIProvider
from app.ai.providers.opencode_provider import OpenCodeProvider
from app.ai.providers.openai_compatible_provider import OpenAICompatibleProvider

PROVIDER_PRESETS = {
    "anthropic": {"base_url": None},
    "openai":    {"base_url": "https://api.openai.com/v1"},
    "deepseek":  {"base_url": "https://api.deepseek.com/v1"},
    # Local `opencode serve` session protocol — no base_url (endpoint comes from
    # settings.tinysiem_opencode_serve_url), no api_key (loopback, subscription auth).
    "opencode":  {"base_url": None},
    "custom":    {"base_url": None},
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

    if provider_name == "opencode":
        from app.config import settings
        return OpenCodeProvider(
            serve_url=settings.tinysiem_opencode_serve_url,
            model=model,
        )

    base_url = cfg["base_url"] or PROVIDER_PRESETS[provider_name]["base_url"]
    return OpenAICompatibleProvider(base_url=base_url, api_key=api_key, model=model)

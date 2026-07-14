from app.ai.providers.base import ChatResult


class AnthropicProvider:
    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model = model

    def chat(self, system: str, user: str, max_tokens: int) -> ChatResult:
        import anthropic
        client = anthropic.Anthropic(api_key=self.api_key)
        response = client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return ChatResult(
            text=response.content[0].text.strip(),
            model=self.model,
            prompt_tokens=response.usage.input_tokens,
            completion_tokens=response.usage.output_tokens,
        )

from typing import Optional

from app.ai.providers.base import ChatResult


class OpenAICompatibleProvider:
    def __init__(self, base_url: str, api_key: Optional[str], model: str):
        self.base_url = base_url
        self.api_key = api_key
        self.model = model

    def chat(self, system: str, user: str, max_tokens: int) -> ChatResult:
        from openai import OpenAI
        client = OpenAI(base_url=self.base_url, api_key=self.api_key or "not-needed")
        response = client.chat.completions.create(
            model=self.model,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        choice = response.choices[0]
        usage = response.usage
        return ChatResult(
            text=choice.message.content.strip(),
            model=self.model,
            prompt_tokens=usage.prompt_tokens if usage else 0,
            completion_tokens=usage.completion_tokens if usage else 0,
        )

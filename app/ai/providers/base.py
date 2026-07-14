from dataclasses import dataclass
from typing import Protocol


@dataclass
class ChatResult:
    text: str
    model: str
    prompt_tokens: int
    completion_tokens: int


class AIProvider(Protocol):
    def chat(self, system: str, user: str, max_tokens: int) -> ChatResult: ...

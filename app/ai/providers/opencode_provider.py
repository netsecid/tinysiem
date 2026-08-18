"""OpenCode serve provider — routes chat completions through a local `opencode serve`.

Speaks the opencode headless-server session protocol (POST /session, then
POST /session/{id}/message) so TinySIEM's AI features ride on the OpenCode Go
subscription / free-tier credentials instead of a per-token API key. The serve
process must be running locally (see scripts/opencode-serve.service); the
default endpoint is http://127.0.0.1:8099 and is loopback-only.

Model ids follow the `opencode models` convention: "providerID/modelID", e.g.
"opencode/deepseek-v4-flash-free" (free tier, $0) or "opencode-go/kimi-k3"
(subscription). A bare id like "kimi-k3" is treated as provider "opencode".
"""

import json

import httpx

from app.ai.providers.base import ChatResult

DEFAULT_SERVE_URL = "http://127.0.0.1:8099"


class OpenCodeProvider:
    def __init__(self, serve_url: str = DEFAULT_SERVE_URL, model: str = "opencode/deepseek-v4-flash-free"):
        self.serve_url = serve_url.rstrip("/")
        self.model = model
        self._client = httpx.Client(timeout=180.0)

    def _split_model(self) -> tuple[str, str]:
        """Split "providerID/modelID" — bare ids default to the "opencode" provider."""
        if "/" in self.model:
            provider_id, model_id = self.model.split("/", 1)
            return provider_id, model_id
        return "opencode", self.model

    def _new_session(self) -> str:
        resp = self._client.post(f"{self.serve_url}/session", json={"title": "tinysiem-ai"})
        resp.raise_for_status()
        return resp.json()["id"]

    def _send(self, session_id: str, payload: dict) -> dict:
        resp = self._client.post(f"{self.serve_url}/session/{session_id}/message", json=payload)
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def _extract_text(data: dict) -> str:
        return "".join(
            p.get("text", "")
            for p in data.get("parts", [])
            if p.get("type") == "text"
        )

    def chat(self, system: str, user: str, max_tokens: int) -> ChatResult:
        provider_id, model_id = self._split_model()
        session_id = self._new_session()
        # The serve protocol takes user parts only — label the system prompt
        # inline so the model treats it as instructions (verified: extraction
        # returns clean JSON with this shape).
        payload = {
            "providerID": provider_id,
            "model": {"providerID": provider_id, "modelID": model_id},
            "parts": [{"type": "text", "text": f"System: {system}\n\nUser: {user}"}],
        }
        data = self._send(session_id, payload)
        text = self._extract_text(data)
        tokens = data.get("info", {}).get("tokens", {})
        return ChatResult(
            text=text.strip(),
            model=self.model,
            prompt_tokens=tokens.get("input", 0),
            completion_tokens=tokens.get("output", 0),
        )

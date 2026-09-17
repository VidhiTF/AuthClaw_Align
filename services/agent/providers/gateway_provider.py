from typing import Any, Dict, List, Optional, Tuple

import requests

from .base import BaseProvider
from services.quota_service import QuotaExceeded, QuotaUnavailable

DEFAULT_MODELS = {
    "openai": "gpt-4o-mini",
    "anthropic": "claude-3-5-sonnet-20241022",
    "cohere": "command-r",
    "azure_openai": "gpt-4o",
    "gemini": "gemini-2.5-flash-lite",
}


class GatewayProvider(BaseProvider):
    """Runs Agent model egress through the tenant-authenticated Go gateway."""

    def __init__(
        self,
        api_key: str,
        provider_name: str,
        model_name: Optional[str] = None,
        api_url: str = "http://gateway:8080",
        timeout: float = 35.0,
    ):
        provider = (provider_name or "").strip().lower().replace("-", "_")
        if provider not in DEFAULT_MODELS:
            raise ValueError(f"Unsupported gateway provider configured: {provider_name}")
        if not api_key:
            raise ValueError("AuthClaw gateway key is required for Agent provider egress.")
        self.api_key = api_key
        self.provider_name = provider
        self.model_name = model_name or DEFAULT_MODELS[provider]
        self.api_url = api_url.rstrip("/")
        self.timeout = timeout

    def _request(self, prompt: str, system_instruction: Optional[str], history: Optional[List[Dict[str, Any]]], kwargs: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        messages = []
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
        for item in history or []:
            messages.append({"role": item.get("role", "user"), "content": item.get("content", "")})
        messages.append({"role": "user", "content": prompt})

        if self.provider_name == "gemini":
            path = f"/v1/models/{self.model_name}:generateContent"
            payload = {"contents": [{"role": "user", "parts": [{"text": prompt}]}]}
        elif self.provider_name == "anthropic":
            path = "/v1/messages"
            payload = {"model": self.model_name, "max_tokens": int(kwargs.get("max_tokens", 1024)), "messages": messages}
        elif self.provider_name == "cohere":
            path = "/v2/chat"
            payload = {"model": self.model_name, "messages": messages}
        elif self.provider_name == "azure_openai":
            path = f"/openai/deployments/{self.model_name}/chat/completions"
            payload = {"model": self.model_name, "messages": messages}
        else:
            path = "/v1/chat/completions"
            payload = {"model": self.model_name, "messages": messages}

        if "temperature" in kwargs:
            payload["temperature"] = float(kwargs["temperature"])
        if "max_tokens" in kwargs and self.provider_name not in {"gemini", "anthropic"}:
            payload["max_tokens"] = int(kwargs["max_tokens"])
        return path, payload

    def generate(self, prompt: str, system_instruction: str = None, history: List[Dict[str, Any]] = None, **kwargs) -> str:
        path, payload = self._request(prompt, system_instruction, history, kwargs)
        response = requests.post(
            f"{self.api_url}{path}",
            json=payload,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "X-Provider": self.provider_name,
            },
            timeout=self.timeout,
        )
        if response.status_code == 429:
            raise QuotaExceeded("expensive_model")
        if response.status_code == 503:
            raise QuotaUnavailable("Gateway quota admission unavailable")
        if not response.ok:
            raise RuntimeError(f"AuthClaw gateway returned HTTP {response.status_code}: Provider unavailable")

        data = response.json()
        if self.provider_name == "gemini":
            return data["candidates"][0]["content"]["parts"][0]["text"]
        if self.provider_name == "anthropic":
            return "".join(part.get("text", "") for part in data.get("content", []) if part.get("type") == "text")
        if self.provider_name == "cohere":
            content = (data.get("message") or {}).get("content", [])
            return "".join(part.get("text", "") for part in content if part.get("type") in {None, "text"})
        return data["choices"][0]["message"]["content"]

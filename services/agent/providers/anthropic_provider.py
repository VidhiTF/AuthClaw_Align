import logging
from typing import Any, Dict, List

import requests

from .base import BaseProvider

logger = logging.getLogger("authclaw.providers.anthropic")


class AnthropicProvider(BaseProvider):
    def __init__(self, api_key: str = None, model_name: str = "claude-3-5-sonnet-20241022", api_url: str = None, timeout: float = 30.0):
        self.api_key = api_key
        self.model_name = model_name or "claude-3-5-sonnet-20241022"
        self.api_url = (api_url or "https://api.anthropic.com").rstrip("/")
        self.timeout = timeout
        if not self.api_key:
            raise ValueError("Anthropic provider credential is not configured.")

    def generate(self, prompt: str, system_instruction: str = None, history: List[Dict[str, Any]] = None, **kwargs) -> str:
        messages = []
        if history:
            for item in history:
                role = item.get("role", "user")
                if role not in ("user", "assistant"):
                    role = "user"
                messages.append({"role": role, "content": item.get("content", "")})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model_name,
            "max_tokens": int(kwargs.get("max_tokens", 1024)),
            "messages": messages,
        }
        if system_instruction:
            payload["system"] = system_instruction
        if "temperature" in kwargs:
            payload["temperature"] = float(kwargs["temperature"])

        response = requests.post(
            f"{self.api_url}/v1/messages",
            json=payload,
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        data = response.json()
        parts = data.get("content", [])
        return "".join(part.get("text", "") for part in parts if part.get("type") == "text")

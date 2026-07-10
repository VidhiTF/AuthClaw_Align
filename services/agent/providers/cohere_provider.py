import logging
from typing import Any, Dict, List

import requests

from .base import BaseProvider

logger = logging.getLogger("authclaw.providers.cohere")


class CohereProvider(BaseProvider):
    def __init__(self, api_key: str = None, model_name: str = "command-r-plus", api_url: str = None, timeout: float = 30.0):
        self.api_key = api_key
        self.model_name = model_name or "command-r-plus"
        self.api_url = (api_url or "https://api.cohere.com").rstrip("/")
        self.timeout = timeout
        if not self.api_key:
            raise ValueError("Cohere provider credential is not configured.")

    def generate(self, prompt: str, system_instruction: str = None, history: List[Dict[str, Any]] = None, **kwargs) -> str:
        messages = []
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
        if history:
            for item in history:
                role = item.get("role", "user")
                if role not in ("system", "user", "assistant"):
                    role = "user"
                messages.append({"role": role, "content": item.get("content", "")})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model_name,
            "messages": messages,
        }
        if "temperature" in kwargs:
            payload["temperature"] = float(kwargs["temperature"])
        if "max_tokens" in kwargs:
            payload["max_tokens"] = int(kwargs["max_tokens"])

        response = requests.post(
            f"{self.api_url}/v2/chat",
            json=payload,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        data = response.json()
        message = data.get("message") or {}
        content = message.get("content")
        if isinstance(content, list):
            return "".join(part.get("text", "") for part in content if part.get("type") in {None, "text"})
        if isinstance(content, str):
            return content
        if data.get("text"):
            return data["text"]
        return ""

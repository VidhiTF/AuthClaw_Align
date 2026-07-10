import logging
from typing import Any, Dict, List

import requests

from .base import BaseProvider

logger = logging.getLogger("authclaw.providers.azure_openai")


class AzureOpenAIProvider(BaseProvider):
    def __init__(
        self,
        api_key: str = None,
        deployment: str = None,
        api_url: str = None,
        api_version: str = "2024-02-15-preview",
        timeout: float = 30.0,
    ):
        self.api_key = api_key
        self.model_name = deployment or "gpt-4o"
        self.api_url = (api_url or "").rstrip("/")
        self.api_version = api_version or "2024-02-15-preview"
        self.timeout = timeout
        if not self.api_key:
            raise ValueError("Azure OpenAI provider credential is not configured.")
        if not self.api_url:
            raise ValueError("Azure OpenAI endpoint is not configured.")

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

        payload = {"messages": messages}
        if "temperature" in kwargs:
            payload["temperature"] = float(kwargs["temperature"])
        if "max_tokens" in kwargs:
            payload["max_tokens"] = int(kwargs["max_tokens"])

        response = requests.post(
            f"{self.api_url}/openai/deployments/{self.model_name}/chat/completions",
            params={"api-version": self.api_version},
            json=payload,
            headers={"api-key": self.api_key, "Content-Type": "application/json"},
            timeout=self.timeout,
        )
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]

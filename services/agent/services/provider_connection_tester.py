import re
from typing import Any, Dict

import requests

from services.secret_manager import normalize_provider


class ProviderConnectionTestError(RuntimeError):
    pass


def normalize_provider_payload(provider: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    normalized = normalize_provider(provider)
    source = dict(payload or {})
    api_base = (
        source.get("api_base")
        or source.get("base_url")
        or source.get("endpoint")
        or source.get("azure_endpoint")
    )
    api_version = source.get("api_version") or source.get("azure_api_version")
    deployment = source.get("deployment") or source.get("deployment_name")
    model = source.get("model")
    if normalized == "azure_openai":
        model = deployment or model
    normalized_payload = {
        "api_key": source.get("api_key"),
        "model": model,
        "api_base": api_base,
        "api_version": api_version,
        "deployment": deployment or model,
    }
    for key, value in source.items():
        if key not in {
            "api_key",
            "model",
            "api_base",
            "base_url",
            "endpoint",
            "azure_endpoint",
            "api_version",
            "azure_api_version",
            "deployment",
            "deployment_name",
        }:
            normalized_payload[key] = value
    return {key: value for key, value in normalized_payload.items() if value not in (None, "")}


def validate_provider_payload(provider: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    normalized = normalize_provider(provider)
    payload = normalize_provider_payload(normalized, payload)
    api_key = str(payload.get("api_key") or "").strip()
    if not api_key:
        raise ProviderConnectionTestError("Provider API key is required.")

    warnings = []
    if normalized == "openai" and not api_key.startswith(("sk-", "sk-proj-")):
        warnings.append("OpenAI keys usually start with sk- or sk-proj-.")
    if normalized == "gemini" and len(api_key) < 20:
        warnings.append("Gemini API key looks shorter than expected.")
    if normalized == "anthropic" and not api_key.startswith("sk-ant-"):
        warnings.append("Anthropic keys usually start with sk-ant-.")
    if normalized == "cohere" and len(api_key) < 20:
        warnings.append("Cohere API key looks shorter than expected.")
    if normalized == "azure_openai":
        if not payload.get("api_base"):
            raise ProviderConnectionTestError("Azure OpenAI requires api_base.")
        if not payload.get("api_version"):
            raise ProviderConnectionTestError("Azure OpenAI requires api_version.")
        if not (payload.get("deployment") or payload.get("model")):
            raise ProviderConnectionTestError("Azure OpenAI requires deployment or model.")

    return {
        "provider": normalized,
        "status": "validated",
        "live": False,
        "warnings": warnings,
    }


def test_provider_connection(provider: str, payload: Dict[str, Any], live: bool = False, timeout: float = 10.0) -> Dict[str, Any]:
    validation = validate_provider_payload(provider, payload)
    normalized = validation["provider"]
    payload = normalize_provider_payload(normalized, payload)
    if not live:
        return validation

    api_key = payload["api_key"]
    try:
        if normalized == "openai":
            api_base = str(payload.get("api_base") or "https://api.openai.com/v1").rstrip("/")
            response = requests.get(
                f"{api_base}/models",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=timeout,
            )
        elif normalized == "gemini":
            api_base = str(payload.get("api_base") or "https://generativelanguage.googleapis.com").rstrip("/")
            response = requests.get(
                f"{api_base}/v1beta/models",
                params={"key": api_key},
                timeout=timeout,
            )
        elif normalized == "anthropic":
            api_base = str(payload.get("api_base") or "https://api.anthropic.com").rstrip("/")
            response = requests.post(
                f"{api_base}/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json={
                    "model": payload.get("model") or "claude-3-5-sonnet-20241022",
                    "max_tokens": 1,
                    "messages": [{"role": "user", "content": "ping"}],
                },
                timeout=timeout,
            )
        elif normalized == "cohere":
            api_base = str(payload.get("api_base") or "https://api.cohere.com").rstrip("/")
            response = requests.get(
                f"{api_base}/v1/models",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=timeout,
            )
        elif normalized == "azure_openai":
            api_base = str(payload["api_base"]).rstrip("/")
            api_version = payload["api_version"]
            response = requests.get(
                f"{api_base}/openai/deployments",
                params={"api-version": api_version},
                headers={"api-key": api_key},
                timeout=timeout,
            )
        else:
            raise ProviderConnectionTestError(f"Unsupported provider: {provider}")
    except requests.RequestException as exc:
        raise ProviderConnectionTestError(f"Provider connection failed: {exc}") from exc

    if response.status_code >= 400:
        body = re.sub(r"\s+", " ", response.text[:300])
        raise ProviderConnectionTestError(f"Provider returned HTTP {response.status_code}: {body}")

    return {
        **validation,
        "status": "healthy",
        "live": True,
        "http_status": response.status_code,
    }

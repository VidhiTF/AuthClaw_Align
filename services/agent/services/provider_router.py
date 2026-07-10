import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

from database import engine
from providers import get_provider as get_legacy_provider
from providers.base import BaseProvider
from providers.gemini_provider import GeminiProvider
from providers.local_provider import LocalProvider
from services.provider_connection_tester import normalize_provider_payload
from services.secret_manager import SecretManager, SecretManagerError
from services.secret_manager import normalize_provider as normalize_provider_name
from sqlalchemy import text

logger = logging.getLogger("authclaw.provider_router")


@dataclass
class ProviderSelection:
    route_id: Optional[str]
    provider_name: str
    model: str
    endpoint: Optional[str]
    provider: BaseProvider
    source: str


class ProviderRouter:
    def __init__(self, tenant_id: int):
        self.tenant_id = tenant_id

    def select(self) -> ProviderSelection:
        route = self._lookup_route()
        credential = self._lookup_credential(route["provider"] if route else None)
        if route and not credential:
            credential = self._lookup_credential()

        if route and credential:
            if self._normalize_provider(route["provider"]) != self._normalize_provider(credential["provider"]):
                route = {
                    **route,
                    "id": None,
                    "provider": credential["provider"],
                    "model": credential["payload"].get("model") or self._default_model_for(credential["provider"]),
                    "endpoint": credential["payload"].get("api_base"),
                }
            return self._build_selection(route=route, credential=credential, source="tenant_route")

        if credential:
            route_like = {
                "id": None,
                "provider": credential["provider"],
                "model": credential["payload"].get("model") or self._default_model_for(credential["provider"]),
                "endpoint": credential["payload"].get("api_base"),
            }
            return self._build_selection(route=route_like, credential=credential, source="tenant_credential")

        environment_credential = self._lookup_environment_credential(route["provider"] if route else None)
        if environment_credential:
            route_like = {
                "id": route["id"] if route else None,
                "provider": route["provider"] if route else environment_credential["provider"],
                "model": (route.get("model") if route else None)
                or environment_credential["payload"].get("model")
                or self._default_model_for(environment_credential["provider"]),
                "endpoint": (route.get("endpoint") if route else None) or environment_credential["payload"].get("api_base"),
            }
            return self._build_selection(route=route_like, credential=environment_credential, source="environment_secret")

        if self._local_provider_fallback_enabled():
            local_provider = LocalProvider()
            return ProviderSelection(
                route_id=None,
                provider_name="local",
                model=local_provider.model_name,
                endpoint=local_provider.api_url,
                provider=local_provider,
                source="local_development_fallback",
            )

        legacy_provider = get_legacy_provider()
        return ProviderSelection(
            route_id=None,
            provider_name=legacy_provider.__class__.__name__,
            model=getattr(legacy_provider, "model_name", "authclaw-gateway"),
            endpoint=getattr(legacy_provider, "api_url", None),
            provider=legacy_provider,
            source="legacy_provider_fallback",
        )

    def _lookup_route(self) -> Optional[Dict[str, Any]]:
        with engine.connect() as conn:
            tenant = conn.execute(
                text("SELECT name, domain FROM tenants WHERE id = :tid"),
                {"tid": self.tenant_id},
            ).fetchone()
            tenant_tokens = {str(self.tenant_id), f"tenant:{self.tenant_id}"}
            if tenant:
                if tenant[0]:
                    tenant_tokens.add(str(tenant[0]))
                if tenant[1]:
                    tenant_tokens.add(str(tenant[1]))

            rows = conn.execute(
                text(
                    """
                    SELECT id, tenant_id, name, provider, endpoint, model, rate_limit, redaction_enabled, enabled, tenant_assignment
                    FROM gateway_routes
                    WHERE enabled = TRUE
                      AND (tenant_id = :tid OR tenant_id IS NULL)
                    ORDER BY id ASC
                    """
                ),
                {"tid": self.tenant_id},
            ).fetchall()

        for row in rows:
            route = dict(row._mapping)
            if route.get("tenant_id") == self.tenant_id:
                return route
            if route.get("tenant_assignment") in tenant_tokens:
                return route
        return None

    def _lookup_credential(self, preferred_provider: Optional[str] = None) -> Optional[Dict[str, Any]]:
        with engine.connect() as conn:
            if preferred_provider:
                rows = conn.execute(
                    text(
                        """
                        SELECT provider, encrypted_payload, secret_ref, secret_backend, secret_version
                        FROM tenant_credentials
                        WHERE tenant_id = :tid AND provider = :provider AND revoked_at IS NULL
                        ORDER BY updated_at DESC
                        """
                    ),
                    {"tid": self.tenant_id, "provider": self._normalize_provider(preferred_provider)},
                ).fetchall()
            else:
                rows = conn.execute(
                    text(
                        """
                        SELECT provider, encrypted_payload, secret_ref, secret_backend, secret_version
                        FROM tenant_credentials
                        WHERE tenant_id = :tid AND revoked_at IS NULL
                        ORDER BY updated_at DESC
                        """
                    ),
                    {"tid": self.tenant_id},
                ).fetchall()

        for row in rows:
            payload = self._decrypt_payload(dict(row._mapping))
            if payload:
                return {"provider": row[0], "payload": payload}
        return None

    def _lookup_environment_credential(self, preferred_provider: Optional[str] = None) -> Optional[Dict[str, Any]]:
        providers = [self._normalize_provider(preferred_provider)] if preferred_provider else [
            "openai",
            "anthropic",
            "cohere",
            "azure_openai",
            "gemini",
        ]
        manager = SecretManager()

        for provider in providers:
            if not provider:
                continue
            env_prefixes = [
                f"AUTHCLAW_TENANT_{self.tenant_id}_{provider.upper()}",
                f"AUTHCLAW_PROVIDER_{provider.upper()}",
            ]
            for prefix in env_prefixes:
                try:
                    json_payload = manager.get_json_secret(f"{prefix}_SECRET_JSON")
                    if json_payload and json_payload.get("api_key"):
                        return {"provider": provider, "payload": normalize_provider_payload(provider, json_payload)}
                    api_key = manager.get_secret(f"{prefix}_API_KEY")
                except SecretManagerError as exc:
                    logger.warning(f"Provider secret lookup failed for tenant {self.tenant_id}: {exc}")
                    continue
                if api_key:
                    payload = {
                        "api_key": api_key,
                        "model": manager.get_secret(f"{prefix}_MODEL"),
                        "api_base": manager.get_secret(f"{prefix}_API_BASE"),
                        "api_version": manager.get_secret(f"{prefix}_API_VERSION"),
                        "deployment": manager.get_secret(f"{prefix}_DEPLOYMENT"),
                    }
                    return {"provider": provider, "payload": normalize_provider_payload(provider, payload)}
        return None

    def _build_selection(self, route: Dict[str, Any], credential: Dict[str, Any], source: str) -> ProviderSelection:
        provider_name = self._normalize_provider(route["provider"])
        payload = normalize_provider_payload(provider_name, credential["payload"])
        model = route.get("model") or payload.get("model") or self._default_model_for(provider_name)
        endpoint = route.get("endpoint") or payload.get("api_base")
        api_key = payload.get("api_key")

        if provider_name == "gemini":
            provider = GeminiProvider(api_key=api_key, model_name=model, api_url=endpoint or None)
        elif provider_name == "openai":
            from providers.openai_provider import OpenAIProvider

            provider = OpenAIProvider(api_key=api_key, model_name=model, api_url=endpoint or None)
        elif provider_name == "anthropic":
            from providers.anthropic_provider import AnthropicProvider

            provider = AnthropicProvider(api_key=api_key, model_name=model, api_url=endpoint or None)
        elif provider_name == "cohere":
            from providers.cohere_provider import CohereProvider

            provider = CohereProvider(api_key=api_key, model_name=model, api_url=endpoint or None)
        elif provider_name == "azure_openai":
            from providers.azure_openai_provider import AzureOpenAIProvider

            provider = AzureOpenAIProvider(
                api_key=api_key,
                deployment=payload.get("deployment") or model,
                api_url=endpoint or None,
                api_version=payload.get("api_version"),
            )
        else:
            raise ValueError(f"Unsupported tenant provider configured: {route['provider']}")

        return ProviderSelection(
            route_id=str(route["id"]) if route.get("id") is not None else None,
            provider_name=provider_name,
            model=model,
            endpoint=endpoint,
            provider=provider,
            source=source,
        )

    def _decrypt_payload(self, credential_row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            provider = credential_row.get("provider")
            return normalize_provider_payload(provider, SecretManager().resolve_provider_payload(credential_row))
        except Exception as exc:
            logger.warning(f"Failed to decrypt provider credential for tenant {self.tenant_id}: {exc}")
            return None

    def _normalize_provider(self, provider: str) -> str:
        return normalize_provider_name(provider)

    def _local_provider_fallback_enabled(self) -> bool:
        env = os.getenv("AUTHCLAW_ENV", "development").strip().lower()
        if env in {"production", "prod"}:
            return False
        configured = os.getenv("AUTHCLAW_ALLOW_LOCAL_PROVIDER_FALLBACK")
        if configured is None:
            return True
        return configured.strip().lower() in {"1", "true", "yes", "on"}

    def _default_model_for(self, provider: str) -> str:
        if provider == "openai":
            return "gpt-4o"
        if provider == "anthropic":
            return "claude-3-5-sonnet-20241022"
        if provider == "cohere":
            return "command-r-plus"
        if provider == "azure_openai":
            return "gpt-4o"
        return "gemini-2.5-flash-lite"

import hashlib
import json

from sqlalchemy import text

from database import engine
from main import API_KEY, encrypt_secret
from providers.azure_openai_provider import AzureOpenAIProvider
from providers.cohere_provider import CohereProvider
from providers.gemini_provider import GeminiProvider
from providers.local_provider import LocalProvider
from providers.openai_provider import OpenAIProvider
from providers.anthropic_provider import AnthropicProvider
from services.provider_router import ProviderRouter


def _tenant_id_for_test_key():
    key_hash = hashlib.sha256(API_KEY.encode("utf-8")).hexdigest()
    with engine.connect() as conn:
        return conn.execute(
            text("SELECT tenant_id FROM tenant_api_keys WHERE key_hash = :hash"),
            {"hash": key_hash},
        ).scalar()


def _connect_provider(tenant_id, provider, payload):
    encrypted_payload = encrypt_secret(json.dumps(payload))
    with engine.connect() as conn:
        conn.execute(
            text(
                """
                INSERT INTO tenant_credentials (tenant_id, provider, encrypted_payload)
                VALUES (:tenant_id, :provider, :payload)
                ON CONFLICT (tenant_id, provider) DO UPDATE
                SET encrypted_payload = EXCLUDED.encrypted_payload, updated_at = NOW()
                """
            ),
            {"tenant_id": tenant_id, "provider": provider, "payload": encrypted_payload},
        )
        conn.commit()


def _create_route(tenant_id, provider, model):
    with engine.connect() as conn:
        row = conn.execute(
            text(
                """
                INSERT INTO gateway_routes (
                    name, provider, endpoint, model, rate_limit,
                    redaction_enabled, enabled, tenant_assignment
                )
                VALUES (
                    :name, :provider, :endpoint, :model, 100, true, true, :tenant_assignment
                )
                RETURNING id
                """
            ),
            {
                "name": f"test-{provider}-route",
                "provider": provider,
                "endpoint": "https://example.invalid/v1",
                "model": model,
                "tenant_assignment": str(tenant_id),
            },
        ).fetchone()
        conn.commit()
    return row[0]


def _cleanup_route(route_id, tenant_id, provider):
    with engine.connect() as conn:
        conn.execute(text("DELETE FROM gateway_routes WHERE id = :route_id"), {"route_id": route_id})
        conn.execute(
            text("DELETE FROM tenant_credentials WHERE tenant_id = :tenant_id AND provider = :provider"),
            {"tenant_id": tenant_id, "provider": provider},
        )
        conn.commit()


def _clear_tenant_provider_state(tenant_id):
    with engine.connect() as conn:
        conn.execute(
            text(
                """
                DELETE FROM gateway_routes
                WHERE tenant_id = :tenant_id OR tenant_assignment = :tenant_assignment
                """
            ),
            {"tenant_id": tenant_id, "tenant_assignment": str(tenant_id)},
        )
        conn.execute(text("DELETE FROM tenant_credentials WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
        conn.commit()


def test_provider_router_uses_local_fallback_without_credentials_in_development(monkeypatch):
    tenant_id = _tenant_id_for_test_key()
    _clear_tenant_provider_state(tenant_id)
    monkeypatch.setenv("AUTHCLAW_ENV", "development")
    monkeypatch.delenv("AUTHCLAW_ALLOW_LOCAL_PROVIDER_FALLBACK", raising=False)

    selection = ProviderRouter(tenant_id=tenant_id).select()

    assert selection.provider_name == "local"
    assert selection.model == "authclaw-local-secure"
    assert selection.source == "local_development_fallback"
    assert isinstance(selection.provider, LocalProvider)


def test_provider_router_selects_gemini_from_tenant_route_and_credentials():
    tenant_id = _tenant_id_for_test_key()
    route_id = _create_route(tenant_id, "gemini", "gemini-test-model")
    _connect_provider(tenant_id, "gemini", {"api_key": "dummy-api-key", "model": "gemini-credential-model"})

    try:
        selection = ProviderRouter(tenant_id=tenant_id).select()
    finally:
        _cleanup_route(route_id, tenant_id, "gemini")

    assert selection.route_id == str(route_id)
    assert selection.provider_name == "gemini"
    assert selection.model == "gemini-test-model"
    assert selection.source == "tenant_route"
    assert isinstance(selection.provider, GeminiProvider)


def test_provider_router_supports_openai_abstraction():
    tenant_id = _tenant_id_for_test_key()
    route_id = _create_route(tenant_id, "openai", "gpt-4o-mini")
    _connect_provider(tenant_id, "openai", {"api_key": "sk-test", "model": "gpt-4o-mini"})

    try:
        selection = ProviderRouter(tenant_id=tenant_id).select()
    finally:
        _cleanup_route(route_id, tenant_id, "openai")

    assert selection.route_id == str(route_id)
    assert selection.provider_name == "openai"
    assert selection.model == "gpt-4o-mini"
    assert selection.source == "tenant_route"
    assert isinstance(selection.provider, OpenAIProvider)


def test_provider_router_supports_anthropic_abstraction():
    tenant_id = _tenant_id_for_test_key()
    route_id = _create_route(tenant_id, "anthropic", "claude-test-model")
    _connect_provider(tenant_id, "anthropic", {"api_key": "sk-ant-test", "model": "claude-credential-model"})

    try:
        selection = ProviderRouter(tenant_id=tenant_id).select()
    finally:
        _cleanup_route(route_id, tenant_id, "anthropic")

    assert selection.route_id == str(route_id)
    assert selection.provider_name == "anthropic"
    assert selection.model == "claude-test-model"
    assert selection.source == "tenant_route"
    assert isinstance(selection.provider, AnthropicProvider)


def test_provider_router_supports_cohere_abstraction():
    tenant_id = _tenant_id_for_test_key()
    route_id = _create_route(tenant_id, "cohere", "command-r-plus")
    _connect_provider(tenant_id, "cohere", {"api_key": "cohere-test-key-1234567890", "model": "command-r"})

    try:
        selection = ProviderRouter(tenant_id=tenant_id).select()
    finally:
        _cleanup_route(route_id, tenant_id, "cohere")

    assert selection.route_id == str(route_id)
    assert selection.provider_name == "cohere"
    assert selection.model == "command-r-plus"
    assert selection.source == "tenant_route"
    assert isinstance(selection.provider, CohereProvider)


def test_provider_router_supports_native_azure_openai_abstraction():
    tenant_id = _tenant_id_for_test_key()
    route_id = _create_route(tenant_id, "azure_openai", "gpt-4o-prod")
    _connect_provider(
        tenant_id,
        "azure_openai",
        {
            "api_key": "azure-test-key-1234567890",
            "model": "gpt-4o-prod",
            "deployment": "gpt-4o-prod",
            "api_base": "https://resource.openai.azure.com",
            "api_version": "2024-02-15-preview",
        },
    )

    try:
        selection = ProviderRouter(tenant_id=tenant_id).select()
    finally:
        _cleanup_route(route_id, tenant_id, "azure_openai")

    assert selection.route_id == str(route_id)
    assert selection.provider_name == "azure_openai"
    assert selection.model == "gpt-4o-prod"
    assert selection.source == "tenant_route"
    assert isinstance(selection.provider, AzureOpenAIProvider)
    assert selection.provider.api_version == "2024-02-15-preview"

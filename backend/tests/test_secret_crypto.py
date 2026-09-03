import base64
import sys
from types import SimpleNamespace

import pytest

from app.core.crypto import (
    _vault_key_material,
    decrypt_secret,
    encrypt_deterministic,
    encrypt_secret,
    secret_management_status,
)
from app.core.startup_checks import validate_production_environment


def test_provider_secret_encryption_is_randomized_and_round_trips(monkeypatch):
    monkeypatch.setenv("ENVELOPE_KEY", "test-envelope-key-material-32-bytes!!")
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("AUTHCLAW_SECRET_PROVIDER", "env")
    monkeypatch.setenv("AUTHCLAW_SECRET_KEY_VERSION", "v7")

    first = encrypt_secret("sk-provider-secret")
    second = encrypt_secret("sk-provider-secret")

    assert first.startswith("authclaw-secret-v2:env:v7:")
    assert second.startswith("authclaw-secret-v2:env:v7:")
    assert first != second
    assert decrypt_secret(first) == "sk-provider-secret"
    assert decrypt_secret(second) == "sk-provider-secret"


def test_provider_secret_decrypt_supports_legacy_deterministic_rows(monkeypatch):
    monkeypatch.setenv("ENVELOPE_KEY", "test-envelope-key-material-32-bytes!!")
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)

    legacy = encrypt_deterministic("legacy-provider-secret")

    assert not legacy.startswith("authclaw-secret-v1:")
    assert decrypt_secret(legacy) == "legacy-provider-secret"


def test_provider_secret_decrypt_supports_v1_rows(monkeypatch):
    monkeypatch.setenv("ENVELOPE_KEY", "test-envelope-key-material-32-bytes!!")
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("AUTHCLAW_SECRET_PROVIDER", raising=False)
    monkeypatch.delenv("AUTHCLAW_SECRET_KEY_VERSION", raising=False)

    encrypted = encrypt_secret("new-provider-secret")
    legacy_v1 = encrypted.replace("authclaw-secret-v2:env:v1:", "authclaw-secret-v1:")

    assert decrypt_secret(legacy_v1) == "new-provider-secret"


def test_provider_secret_versioned_key_rotation(monkeypatch):
    monkeypatch.setenv("AUTHCLAW_SECRET_PROVIDER", "env")
    monkeypatch.setenv("AUTHCLAW_SECRET_KEY_VERSION", "v2")
    monkeypatch.setenv("ENVELOPE_KEY_V1", "old-test-envelope-key-material-32!!")
    monkeypatch.setenv("ENVELOPE_KEY_V2", "new-test-envelope-key-material-32!!")
    monkeypatch.delenv("ENVELOPE_KEY", raising=False)
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)

    encrypted = encrypt_secret("rotated-provider-secret")

    assert encrypted.startswith("authclaw-secret-v2:env:v2:")
    assert decrypt_secret(encrypted) == "rotated-provider-secret"


def test_vault_rejects_plaintext_address(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", "http://vault.internal")
    monkeypatch.setenv("VAULT_TOKEN", "test-token")

    with pytest.raises(RuntimeError, match="VAULT_ADDR must use https"):
        _vault_key_material("v1")


def test_production_env_provider_requires_key_version_and_real_key(monkeypatch):
    monkeypatch.setenv("AUTHCLAW_ENV", "production")
    monkeypatch.setenv("JWT_SECRET", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    monkeypatch.setenv("SESSION_SECRET", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    monkeypatch.setenv("AUTHCLAW_SECRET_PROVIDER", "env")
    monkeypatch.delenv("AUTHCLAW_SECRET_KEY_VERSION", raising=False)
    monkeypatch.setenv("ENVELOPE_KEY", "demo-local-envelope-key-change-me")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_FROM", "security@example.com")
    monkeypatch.setenv("DEMO_OTP_VISIBLE", "false")

    with pytest.raises(RuntimeError) as exc:
        validate_production_environment()

    assert "AUTHCLAW_SECRET_KEY_VERSION" in str(exc.value)
    assert "non-demo secret" in str(exc.value)


def test_aws_kms_wrapped_key_encrypts_fields_and_reports_key_id(monkeypatch):
    data_key = b"k" * 32
    requests = []

    class KMS:
        def decrypt(self, **kwargs):
            requests.append(kwargs)
            return {"Plaintext": data_key}

    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(client=lambda service: KMS()))
    monkeypatch.setenv("AUTHCLAW_SECRET_PROVIDER", "aws_kms")
    monkeypatch.setenv("AUTHCLAW_SECRET_KEY_VERSION", "v3")
    monkeypatch.setenv("AUTHCLAW_AWS_KMS_KEY_ID", "alias/authclaw-test")
    monkeypatch.setenv("AWS_KMS_ENCRYPTED_DATA_KEY", base64.b64encode(b"wrapped-data-key").decode())

    encrypted = encrypt_secret("sk-managed-secret")

    assert encrypted.startswith("authclaw-secret-v2:aws_kms:v3:")
    assert "sk-managed-secret" not in encrypted
    assert decrypt_secret(encrypted) == "sk-managed-secret"
    assert requests[-1]["KeyId"] == "alias/authclaw-test"
    assert secret_management_status()["key_id"] == "alias/authclaw-test"
    assert secret_management_status()["managed"] is True


def test_aws_kms_failure_is_safe_and_fail_closed(monkeypatch):
    class KMS:
        def decrypt(self, **_kwargs):
            raise PermissionError("provider-detail-must-not-leak")

    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(client=lambda service: KMS()))
    monkeypatch.setenv("AUTHCLAW_SECRET_PROVIDER", "aws_kms")
    monkeypatch.setenv("AUTHCLAW_SECRET_KEY_VERSION", "v3")
    monkeypatch.setenv("AUTHCLAW_AWS_KMS_KEY_ID", "alias/authclaw-test")
    monkeypatch.setenv("AWS_KMS_ENCRYPTED_DATA_KEY", base64.b64encode(b"wrapped-data-key").decode())

    with pytest.raises(RuntimeError) as exc:
        encrypt_secret("must-not-fallback")

    assert "PermissionError" in str(exc.value)
    assert "provider-detail-must-not-leak" not in str(exc.value)


def test_managed_field_ciphertext_rejects_tampering(monkeypatch):
    data_key = b"t" * 32
    monkeypatch.setitem(
        sys.modules,
        "boto3",
        SimpleNamespace(client=lambda service: SimpleNamespace(decrypt=lambda **kwargs: {"Plaintext": data_key})),
    )
    monkeypatch.setenv("AUTHCLAW_SECRET_PROVIDER", "aws_kms")
    monkeypatch.setenv("AUTHCLAW_SECRET_KEY_VERSION", "v4")
    monkeypatch.setenv("AUTHCLAW_AWS_KMS_KEY_ID", "alias/authclaw-test")
    monkeypatch.setenv("AWS_KMS_ENCRYPTED_DATA_KEY", base64.b64encode(b"wrapped-data-key").decode())
    encrypted = encrypt_secret("tamper-evident-secret")
    prefix, provider, version, payload = encrypted.split(":", 3)
    raw = bytearray(base64.b64decode(payload))
    raw[-1] ^= 1
    tampered = ":".join((prefix, provider, version, base64.b64encode(raw).decode()))

    with pytest.raises(ValueError):
        decrypt_secret(tampered)


def test_service_tls_boundary_rejects_plaintext_internal_urls(monkeypatch):
    monkeypatch.setenv("AUTHCLAW_ENV", "staging")
    _set_shared_environment_secrets(monkeypatch)
    monkeypatch.setenv("AUTHCLAW_REQUIRE_SERVICE_TLS", "true")
    monkeypatch.setenv("GATEWAY_INTERNAL_URL", "https://gateway.internal")
    monkeypatch.setenv("OPA_URL", "http://opa.internal")
    monkeypatch.setenv("PRESIDIO_URL", "https://presidio.internal")

    with pytest.raises(RuntimeError) as exc:
        validate_production_environment()

    assert "OPA_URL must use https or task-local loopback http" in str(exc.value)


def test_service_tls_boundary_accepts_task_local_sidecars(monkeypatch):
    monkeypatch.setenv("AUTHCLAW_ENV", "staging")
    _set_shared_environment_secrets(monkeypatch)
    monkeypatch.setenv("AUTHCLAW_REQUIRE_SERVICE_TLS", "true")
    monkeypatch.setenv("GATEWAY_INTERNAL_URL", "https://gateway.internal")
    monkeypatch.setenv("OPA_URL", "http://127.0.0.1:8181")
    monkeypatch.setenv("PRESIDIO_URL", "http://127.0.0.1:3000")

    validate_production_environment()


@pytest.mark.parametrize("invalid_url", ["https://", "https:///opa", "not-a-url"])
def test_service_tls_boundary_rejects_malformed_https_urls(monkeypatch, invalid_url):
    monkeypatch.setenv("AUTHCLAW_ENV", "staging")
    _set_shared_environment_secrets(monkeypatch)
    monkeypatch.setenv("AUTHCLAW_REQUIRE_SERVICE_TLS", "true")
    monkeypatch.setenv("GATEWAY_INTERNAL_URL", invalid_url)
    monkeypatch.setenv("OPA_URL", "https://opa.internal")
    monkeypatch.setenv("PRESIDIO_URL", "https://presidio.internal")

    with pytest.raises(RuntimeError, match="GATEWAY_INTERNAL_URL must use https"):
        validate_production_environment()


def test_production_kms_provider_requires_key_identifier(monkeypatch):
    monkeypatch.setenv("AUTHCLAW_ENV", "production")
    monkeypatch.setenv("JWT_SECRET", "a" * 32)
    monkeypatch.setenv("SESSION_SECRET", "b" * 32)
    monkeypatch.setenv("AUTHCLAW_SECRET_PROVIDER", "aws_kms")
    monkeypatch.setenv("AUTHCLAW_SECRET_KEY_VERSION", "v1")
    monkeypatch.setenv("AWS_KMS_ENCRYPTED_DATA_KEY", base64.b64encode(b"wrapped-data-key").decode())
    monkeypatch.delenv("AUTHCLAW_AWS_KMS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_KMS_KEY_ID", raising=False)
    monkeypatch.setenv("GATEWAY_INTERNAL_URL", "https://gateway.internal")
    monkeypatch.setenv("OPA_URL", "https://opa.internal")
    monkeypatch.setenv("PRESIDIO_URL", "https://presidio.internal")
    monkeypatch.setenv("PUBLIC_GATEWAY_URL", "https://gateway.example.com")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_FROM", "security@example.com")
    monkeypatch.setenv("DEMO_OTP_VISIBLE", "false")

    with pytest.raises(RuntimeError) as exc:
        validate_production_environment()

    assert "AUTHCLAW_AWS_KMS_KEY_ID" in str(exc.value)
def _set_shared_environment_secrets(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "shared-jwt-secret-material-32-bytes")
    monkeypatch.setenv("SESSION_SECRET", "shared-session-secret-material-32")
    monkeypatch.setenv("AUTHCLAW_SECRET_PROVIDER", "env")
    monkeypatch.setenv("AUTHCLAW_SECRET_KEY_VERSION", "v1")
    monkeypatch.setenv("ENVELOPE_KEY", "shared-envelope-secret-material-32")
    monkeypatch.setenv("DEMO_OTP_VISIBLE", "false")


def test_staging_rejects_silent_demo_secrets(monkeypatch):
    monkeypatch.setenv("AUTHCLAW_ENV", "staging")
    monkeypatch.setenv("JWT_SECRET", "dev-secret-change-in-production")
    monkeypatch.setenv("SESSION_SECRET", "change-this-demo-session-secret")
    monkeypatch.setenv("AUTHCLAW_SECRET_PROVIDER", "env")
    monkeypatch.setenv("ENVELOPE_KEY", "authclaw-default-32-byte-key-12")
    monkeypatch.setenv("AUTHCLAW_REQUIRE_SERVICE_TLS", "false")

    with pytest.raises(RuntimeError, match="shared environments"):
        validate_production_environment()


def test_staging_rejects_published_local_compose_defaults(monkeypatch):
    monkeypatch.setenv("AUTHCLAW_ENV", "staging")
    monkeypatch.setenv("JWT_SECRET", "authclaw-full-local-jwt-secret-change-me")
    monkeypatch.setenv("SESSION_SECRET", "authclaw-full-local-session-secret")
    monkeypatch.setenv("AUTHCLAW_SECRET_PROVIDER", "env")
    monkeypatch.setenv("ENVELOPE_KEY", "YXV0aGNsYXctbG9jYWwtZmVybmV0LWtleS1jaGFuZ2U=")
    monkeypatch.setenv("AUTHCLAW_REQUIRE_SERVICE_TLS", "false")

    with pytest.raises(RuntimeError, match="shared environments"):
        validate_production_environment()


def test_unknown_environment_is_rejected(monkeypatch):
    monkeypatch.setenv("AUTHCLAW_ENV", "production-us")
    with pytest.raises(RuntimeError, match="AUTHCLAW_ENV"):
        validate_production_environment()


def test_shared_backend_clickhouse_requires_non_default_password(monkeypatch):
    monkeypatch.setenv("AUTHCLAW_ENV", "staging")
    _set_shared_environment_secrets(monkeypatch)
    monkeypatch.setenv("CLICKHOUSE_HOST", "clickhouse.internal")
    monkeypatch.setenv("CLICKHOUSE_PASSWORD", "authclaw")

    with pytest.raises(RuntimeError, match="CLICKHOUSE_PASSWORD"):
        validate_production_environment()


def test_staging_kms_provider_requires_wrapped_key_and_identifier(monkeypatch):
    monkeypatch.setenv("AUTHCLAW_ENV", "staging")
    _set_shared_environment_secrets(monkeypatch)
    monkeypatch.setenv("AUTHCLAW_SECRET_PROVIDER", "aws_kms")
    monkeypatch.delenv("AWS_KMS_ENCRYPTED_DATA_KEY", raising=False)
    monkeypatch.delenv("KMS_ENCRYPTED_DATA_KEY", raising=False)
    monkeypatch.delenv("AUTHCLAW_AWS_KMS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_KMS_KEY_ID", raising=False)

    with pytest.raises(RuntimeError) as exc:
        validate_production_environment()

    assert "AWS_KMS_ENCRYPTED_DATA_KEY" in str(exc.value)
    assert "AUTHCLAW_AWS_KMS_KEY_ID" in str(exc.value)

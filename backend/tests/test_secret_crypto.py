import pytest

from app.core.crypto import decrypt_secret, encrypt_deterministic, encrypt_secret
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

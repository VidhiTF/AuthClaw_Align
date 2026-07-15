import hmac
import time
from unittest.mock import MagicMock

import jwt
import pytest
from fastapi import HTTPException

from app.core.auth import hash_key
from app.core import oidc
from app.core.passwords import hash_password, verify_password
from app.schemas.models import APIKeyCreate, APIKeyRotate
from app.services import oidc_sso
from app.services.email_service import send_otp_email
from app.api.v1.endpoints import auth as auth_endpoints


def test_api_key_create_rejects_unknown_scope():
    try:
        APIKeyCreate(name="bad", scopes=["read", "root"])
    except ValueError as exc:
        assert "Unsupported API key scopes" in str(exc)
    else:
        raise AssertionError("unknown scope should be rejected")


def test_api_key_create_normalizes_scopes_and_expiry():
    key = APIKeyCreate(name="ci", scopes=["write", "read", "read"], expires_in_days=30)

    assert key.scopes == ["read", "write"]
    assert key.expires_in_days == 30


def test_api_key_rotate_inherits_scopes_when_omitted():
    rotation = APIKeyRotate()

    assert rotation.scopes is None
    assert rotation.expires_in_days == 90


def test_api_key_hash_uses_keyed_digest(monkeypatch):
    monkeypatch.setenv("API_KEY_HASH_SECRET", "pepper-one")

    digest = hash_key("acl_test")

    assert digest == hmac.digest(b"pepper-one", b"acl_test", "sha3_256").hex()
    assert hash_key("acl_test") == digest
    monkeypatch.setenv("API_KEY_HASH_SECRET", "pepper-two")
    assert hash_key("acl_test") != digest


def test_oidc_config_disabled_without_env(monkeypatch):
    monkeypatch.delenv("OIDC_ISSUER_URL", raising=False)
    monkeypatch.delenv("OIDC_CLIENT_ID", raising=False)
    monkeypatch.delenv("OIDC_REDIRECT_URI", raising=False)

    config = oidc.oidc_config()

    assert config["enabled"] is False
    assert config["authorization_url"] == ""


def test_oidc_config_builds_authorization_url(monkeypatch):
    monkeypatch.setenv("OIDC_ISSUER_URL", "https://idp.example.com")
    monkeypatch.setenv("OIDC_CLIENT_ID", "authclaw-console")
    monkeypatch.setenv("OIDC_REDIRECT_URI", "https://authclaw.example.com/callback")

    config = oidc.oidc_config()

    assert config["enabled"] is True
    assert config["authorization_endpoint"] == "https://idp.example.com/authorize"
    assert "client_id=authclaw-console" in config["authorization_url"]


def test_oidc_authorization_url_includes_state_and_nonce():
    config = {
        "authorization_endpoint": "https://idp.example.com/authorize",
        "client_id": "authclaw-console",
        "redirect_uri": "https://authclaw.example.com/api/auth/oidc/callback",
        "scopes": ["openid", "email"],
    }

    url = oidc_sso.authorization_url(config, "state-token", "nonce-token")

    assert "state=state-token" in url
    assert "nonce=nonce-token" in url
    assert "response_type=code" in url


def test_oidc_group_role_mapping_uses_highest_privilege_group():
    config = {
        "groups_claim": "groups",
        "default_role": "viewer",
        "role_mapping": {
            "readers": "viewer",
            "admins": "admin",
        },
    }

    role = oidc_sso.role_from_claims(config, {"groups": ["readers", "admins"]})

    assert role == "admin"


def _identity_policy():
    return {
        "tenant_claim": "tenant_id",
        "tenant_claim_value": "immutable-external-tenant-id",
        "require_mfa": True,
        "accepted_amr": ["mfa"],
        "accepted_acr": [],
        "max_auth_age_seconds": 43200,
    }


def test_oidc_rejects_wrong_tenant():
    claims = {"tenant_id": "another-tenant", "amr": ["mfa"], "auth_time": int(time.time())}

    with pytest.raises(oidc_sso.OIDCAuthorizationError, match="not authorized"):
        oidc_sso.validate_identity_context(_identity_policy(), claims)


def test_oidc_rejects_missing_required_mfa_context():
    claims = {"tenant_id": "immutable-external-tenant-id", "amr": ["pwd"], "auth_time": int(time.time())}

    with pytest.raises(oidc_sso.OIDCAuthorizationError, match="MFA context"):
        oidc_sso.validate_identity_context(_identity_policy(), claims)


@pytest.mark.parametrize("azp", [None, "another-client"])
def test_oidc_rejects_invalid_azp_for_multiple_audiences(monkeypatch, azp):
    claims = {
        "aud": ["authclaw-console", "another-client"],
        "azp": azp,
        "nonce": "nonce",
        "tenant_id": "immutable-external-tenant-id",
        "amr": ["mfa"],
        "auth_time": int(time.time()),
    }
    key = MagicMock(key="signing-key")
    monkeypatch.setattr(jwt, "PyJWKClient", lambda *_: MagicMock(get_signing_key_from_jwt=lambda *_: key))
    monkeypatch.setattr(jwt, "decode", lambda *_args, **_kwargs: claims)

    with pytest.raises(oidc_sso.OIDCAuthenticationError):
        oidc_sso.validate_id_token({**_identity_policy(), "issuer": "https://idp.example.com", "client_id": "authclaw-console", "jwks_uri": "https://idp.example.com/jwks"}, "token", "nonce")


def test_oidc_accepts_single_audience_without_azp(monkeypatch):
    claims = {
        "aud": "authclaw-console",
        "nonce": "nonce",
        "tenant_id": "immutable-external-tenant-id",
        "amr": ["mfa"],
        "auth_time": int(time.time()),
    }
    key = MagicMock(key="signing-key")
    monkeypatch.setattr(jwt, "PyJWKClient", lambda *_: MagicMock(get_signing_key_from_jwt=lambda *_: key))
    monkeypatch.setattr(jwt, "decode", lambda *_args, **_kwargs: claims)

    assert oidc_sso.validate_id_token({**_identity_policy(), "issuer": "https://idp.example.com", "client_id": "authclaw-console", "jwks_uri": "https://idp.example.com/jwks"}, "token", "nonce") == claims


def test_oidc_invalid_token_returns_sanitized_401(monkeypatch):
    db = MagicMock()
    tenant = MagicMock(id="00000000-0000-4000-8000-000000000001")
    config = {"redirect_uri": "https://app.example.com/api/auth/oidc/callback"}
    monkeypatch.setattr(auth_endpoints, "OwnerSessionLocal", lambda: db)
    monkeypatch.setattr(auth_endpoints, "_oidc_callback_config", lambda *_: (tenant, config))
    monkeypatch.setattr(oidc_sso, "exchange_code", lambda *_: {"id_token": "invalid"})
    monkeypatch.setattr(oidc_sso, "validate_id_token", MagicMock(side_effect=jwt.InvalidSignatureError("sensitive detail")))

    with pytest.raises(HTTPException) as exc:
        auth_endpoints.oidc_callback(auth_endpoints.OIDCCallbackRequest(
            code="code",
            state="state",
            nonce="nonce",
            tenant_name="tenant",
            redirect_uri=config["redirect_uri"],
        ))

    assert exc.value.status_code == 401
    assert exc.value.detail == "OIDC authentication failed"
    assert "sensitive" not in exc.value.detail


@pytest.mark.parametrize("error", [
    oidc_sso.OIDCAuthorizationError("OIDC identity is not authorized for this tenant"),
    oidc_sso.OIDCAuthorizationError("Required OIDC MFA context is missing"),
])
def test_oidc_policy_rejection_returns_403(monkeypatch, error):
    db = MagicMock()
    tenant = MagicMock(id="00000000-0000-4000-8000-000000000001")
    config = {"redirect_uri": "https://app.example.com/api/auth/oidc/callback"}
    monkeypatch.setattr(auth_endpoints, "OwnerSessionLocal", lambda: db)
    monkeypatch.setattr(auth_endpoints, "_oidc_callback_config", lambda *_: (tenant, config))
    monkeypatch.setattr(oidc_sso, "exchange_code", lambda *_: {"id_token": "token"})
    monkeypatch.setattr(oidc_sso, "validate_id_token", MagicMock(side_effect=error))

    with pytest.raises(HTTPException) as exc:
        auth_endpoints.oidc_callback(auth_endpoints.OIDCCallbackRequest(
            code="code",
            state="state",
            nonce="nonce",
            tenant_name="tenant",
            redirect_uri=config["redirect_uri"],
        ))

    assert exc.value.status_code == 403
    assert exc.value.detail == str(error)


def test_oidc_rejects_redirect_uri_mismatch(monkeypatch):
    db = MagicMock()
    tenant = MagicMock(id="00000000-0000-4000-8000-000000000001")
    config = {"redirect_uri": "https://app.example.com/api/auth/oidc/callback"}
    monkeypatch.setattr(auth_endpoints, "OwnerSessionLocal", lambda: db)
    monkeypatch.setattr(auth_endpoints, "_oidc_callback_config", lambda *_: (tenant, config))

    with pytest.raises(HTTPException) as exc:
        auth_endpoints.oidc_callback(auth_endpoints.OIDCCallbackRequest(
            code="code",
            state="state",
            nonce="nonce",
            tenant_name="tenant",
            redirect_uri="https://evil.example.com/callback",
        ))

    assert exc.value.status_code == 400
    assert exc.value.detail == "Invalid OIDC redirect URI"


def test_password_hash_round_trips_and_rejects_wrong_password():
    encoded = hash_password("CorrectHorse!234")

    assert encoded.startswith("pbkdf2_sha256$")
    assert verify_password("CorrectHorse!234", encoded) is True
    assert verify_password("wrong-password", encoded) is False
    assert verify_password("CorrectHorse!234", None) is False


def test_local_email_outbox_replaces_demo_otp(monkeypatch, tmp_path):
    outbox = tmp_path / "email-outbox.jsonl"
    monkeypatch.delenv("SMTP_HOST", raising=False)
    monkeypatch.setenv("AUTHCLAW_ENV", "development")
    monkeypatch.setenv("DEMO_OTP_VISIBLE", "false")
    monkeypatch.setenv("AUTHCLAW_EMAIL_OUTBOX_PATH", str(outbox))

    result = send_otp_email("owner@example.com", "123456", "Acme", purpose="tenant setup")

    assert result.method == "local_outbox"
    saved = outbox.read_text()
    assert "owner@example.com" in saved
    assert "123456" in saved

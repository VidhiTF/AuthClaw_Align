import hmac
import time
from unittest.mock import MagicMock

import jwt
import pyotp
import pytest
from fastapi import HTTPException

from app.core.auth import hash_key
from app.core import oidc
from app.core.crypto import decrypt_secret
from app.core.passwords import hash_password, verify_password
from app.schemas.models import APIKeyCreate, APIKeyRotate
from app.services import oidc_sso
from app.services.email_service import send_otp_email
from app.api.v1.endpoints import auth as auth_endpoints
from app.api.v1.endpoints import users as user_endpoints


def _request(request_id="request-1"):
    return MagicMock(headers={"x-request-id": request_id})


def test_mfa_disable_requires_current_code():
    secret = pyotp.random_base32()
    user = MagicMock(
        id="00000000-0000-4000-8000-000000000001",
        tenant_id="00000000-0000-4000-8000-000000000002",
        email="owner@example.com",
        role="owner",
        mfa_enabled=True,
        mfa_secret=secret,
        mfa_backup_codes=["backup01"],
    )
    request = MagicMock()
    request.state.user_id = user.id
    request.state.tenant_id = user.tenant_id
    db = MagicMock()
    db.query.return_value.filter.return_value.with_for_update.return_value.first.return_value = (
        user
    )

    with pytest.raises(HTTPException, match="Invalid MFA token"):
        user_endpoints.disable_my_mfa(user_endpoints.MFADisableRequest(code="000000"), request, db)
    assert user.mfa_enabled is True
    db.commit.assert_not_called()

    response = user_endpoints.disable_my_mfa(
        user_endpoints.MFADisableRequest(code=pyotp.TOTP(secret).now()),
        request,
        db,
    )
    assert response.mfa_enabled is False
    assert user.mfa_secret is None
    assert user.mfa_backup_codes is None
    db.commit.assert_called_once()


def test_mfa_replacement_requires_current_factor_and_protects_credentials():
    secret = pyotp.random_base32()
    user = MagicMock(
        id="00000000-0000-4000-8000-000000000001",
        tenant_id="00000000-0000-4000-8000-000000000002",
        email="owner@example.com",
        role="owner",
        mfa_enabled=True,
        mfa_secret=secret,
        mfa_backup_codes=["backup01"],
    )
    request = MagicMock()
    request.state.user_id = user.id
    request.state.tenant_id = user.tenant_id
    db = MagicMock()
    db.query.return_value.filter.return_value.with_for_update.return_value.first.return_value = (
        user
    )

    with pytest.raises(HTTPException, match="Current MFA token"):
        user_endpoints.setup_my_mfa(request, None, db)
    db.commit.assert_not_called()

    response = user_endpoints.setup_my_mfa(
        request,
        user_endpoints.MFASetupRequest(code=pyotp.TOTP(secret).now()),
        db,
    )
    assert decrypt_secret(user.mfa_secret) == response.mfa_secret
    assert all(len(code) == 64 for code in user.mfa_backup_codes)
    assert not set(response.backup_codes).intersection(user.mfa_backup_codes)
    db.commit.assert_called_once()


def test_api_key_create_rejects_unknown_scope():
    try:
        APIKeyCreate(name="bad", scopes=["read", "root"])
    except ValueError as exc:
        assert "Unsupported API key scopes" in str(exc)
    else:
        raise AssertionError("unknown scope should be rejected")


def test_tenant_api_key_schemas_reject_platform_scope():
    with pytest.raises(ValueError, match="Unsupported API key scopes"):
        APIKeyCreate(name="platform", scopes=["platform.admin"])
    with pytest.raises(ValueError, match="Unsupported API key scopes"):
        APIKeyRotate(scopes=["platform.admin"])


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


@pytest.mark.parametrize(
    "endpoint",
    ("authorization_endpoint", "token_endpoint", "jwks_uri"),
)
def test_oidc_config_rejects_plaintext_endpoint(endpoint):
    payload = {
        "issuer": "https://idp.example.com",
        "client_id": "authclaw-console",
        "redirect_uri": "https://authclaw.example.com/callback",
        endpoint: "http://idp.example.com/endpoint",
    }

    with pytest.raises(ValueError, match="endpoints must use https"):
        oidc_sso.upsert_config(MagicMock(), "tenant-id", "user-id", payload)


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


@pytest.mark.parametrize("auto_provision", [False, True])
def test_oidc_unknown_user_requires_tenant_invitation(auto_provision):
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None
    tenant = MagicMock()
    tenant.id = "00000000-0000-4000-8000-000000000001"
    config = {
        "email_claim": "email",
        "groups_claim": "groups",
        "default_role": "viewer",
        "role_mapping": {},
        "auto_provision": auto_provision,
    }

    with pytest.raises(PermissionError, match="not provisioned"):
        oidc_sso.map_user(
            db,
            tenant,
            config,
            {"email": "invited@example.com"},
        )


def test_oidc_existing_active_user_still_maps_to_tenant():
    db = MagicMock()
    user = MagicMock(is_active=True, role="viewer")
    user_query = MagicMock()
    user_query.filter.return_value.first.return_value = user
    invite_query = MagicMock()
    invite_query.filter.return_value.first.return_value = None
    db.query.side_effect = [user_query, invite_query]
    tenant = MagicMock()
    config = {
        "email_claim": "email",
        "groups_claim": "groups",
        "default_role": "viewer",
        "role_mapping": {},
    }

    mapped_user, role = oidc_sso.map_user(
        db,
        tenant,
        config,
        {"email": "existing@example.com"},
    )

    assert mapped_user is user
    assert role == "viewer"


def test_oidc_legacy_user_still_synchronizes_role_from_idp():
    db = MagicMock()
    user = MagicMock(is_active=True, role="viewer")
    user_query = MagicMock()
    user_query.filter.return_value.first.return_value = user
    invite_query = MagicMock()
    invite_query.filter.return_value.first.return_value = None
    db.query.side_effect = [user_query, invite_query]

    mapped_user, role = oidc_sso.map_user(
        db,
        MagicMock(),
        {
            "email_claim": "email",
            "groups_claim": "groups",
            "default_role": "viewer",
            "role_mapping": {"admins": "admin"},
        },
        {"email": "legacy@example.com", "groups": ["admins"]},
    )

    assert mapped_user is user
    assert role == "admin"
    assert user.role == "admin"


def test_oidc_invited_user_keeps_persisted_role_instead_of_idp_escalation():
    db = MagicMock()
    user = MagicMock(is_active=True, role="viewer")
    user_query = MagicMock()
    user_query.filter.return_value.first.return_value = user
    invite_query = MagicMock()
    invite_query.filter.return_value.first.return_value = MagicMock()
    db.query.side_effect = [user_query, invite_query]
    tenant = MagicMock()
    tenant.id = "00000000-0000-4000-8000-000000000001"

    mapped_user, role = oidc_sso.map_user(
        db,
        tenant,
        {
            "email_claim": "email",
            "groups_claim": "groups",
            "default_role": "viewer",
            "role_mapping": {"admins": "admin"},
        },
        {"email": "Invited@Example.com", "groups": ["admins"]},
    )

    assert mapped_user is user
    assert role == "viewer"
    assert user.role == "viewer"
    invite_filters = invite_query.filter.call_args.args
    assert invite_filters[0].right.value == tenant.id
    assert invite_filters[1].right.value == "invited@example.com"


def test_oidc_legacy_owner_protection_is_unchanged():
    db = MagicMock()
    user = MagicMock(is_active=True, role="owner")
    user_query = MagicMock()
    user_query.filter.return_value.first.return_value = user
    invite_query = MagicMock()
    invite_query.filter.return_value.first.return_value = None
    db.query.side_effect = [user_query, invite_query]

    _, role = oidc_sso.map_user(
        db,
        MagicMock(),
        {
            "email_claim": "email",
            "groups_claim": "groups",
            "default_role": "viewer",
            "role_mapping": {},
        },
        {"email": "owner@example.com"},
    )

    assert role == "owner"
    assert user.role == "owner"


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


def test_oidc_rejects_substituted_id_token(monkeypatch):
    key = MagicMock(key="configured-provider-key")
    monkeypatch.setattr(jwt, "PyJWKClient", lambda *_: MagicMock(get_signing_key_from_jwt=lambda *_: key))
    monkeypatch.setattr(jwt, "decode", MagicMock(side_effect=jwt.InvalidSignatureError()))

    with pytest.raises(jwt.InvalidSignatureError):
        oidc_sso.validate_id_token({**_identity_policy(), "issuer": "https://idp.example.com", "client_id": "authclaw-console", "jwks_uri": "https://idp.example.com/jwks"}, "substituted-token", "nonce")


def test_oidc_rejects_replayed_id_token_from_previous_nonce(monkeypatch):
    claims = {"nonce": "previous-nonce"}
    key = MagicMock(key="configured-provider-key")
    monkeypatch.setattr(jwt, "PyJWKClient", lambda *_: MagicMock(get_signing_key_from_jwt=lambda *_: key))
    monkeypatch.setattr(jwt, "decode", lambda *_args, **_kwargs: claims)

    with pytest.raises(oidc_sso.OIDCAuthenticationError) as exc:
        oidc_sso.validate_id_token({**_identity_policy(), "issuer": "https://idp.example.com", "client_id": "authclaw-console", "jwks_uri": "https://idp.example.com/jwks"}, "replayed-token", "current-nonce")

    assert exc.value.reason_code == "nonce_validation_failed"


def test_oidc_invalid_token_returns_sanitized_401(monkeypatch):
    db = MagicMock()
    tenant = MagicMock(id="00000000-0000-4000-8000-000000000001")
    config = {"redirect_uri": "https://app.example.com/api/auth/oidc/callback"}
    monkeypatch.setattr(auth_endpoints, "OwnerSessionLocal", lambda: db)
    monkeypatch.setattr(auth_endpoints, "_oidc_callback_config", lambda *_: (tenant, config))
    monkeypatch.setattr(oidc_sso, "exchange_code", lambda *_: {"id_token": "invalid"})
    monkeypatch.setattr(oidc_sso, "validate_id_token", MagicMock(side_effect=jwt.InvalidSignatureError("sensitive detail")))
    monkeypatch.setattr(auth_endpoints, "_emit_oidc_audit", MagicMock())

    with pytest.raises(HTTPException) as exc:
        auth_endpoints.oidc_callback(
            auth_endpoints.OIDCCallbackRequest(
                code="code",
                state="state",
                nonce="nonce",
                tenant_name="tenant",
                redirect_uri=config["redirect_uri"],
            ),
            _request(),
        )

    assert exc.value.status_code == 401
    assert exc.value.detail == "OIDC authentication failed"
    assert "sensitive" not in exc.value.detail


def test_oidc_internal_error_returns_generic_response_and_is_logged(monkeypatch, caplog):
    db = MagicMock()
    tenant = MagicMock(id="00000000-0000-4000-8000-000000000001")
    config = {"redirect_uri": "https://app.example.com/api/auth/oidc/callback"}
    monkeypatch.setattr(auth_endpoints, "OwnerSessionLocal", lambda: db)
    monkeypatch.setattr(auth_endpoints, "_oidc_callback_config", lambda *_: (tenant, config))
    monkeypatch.setattr(oidc_sso, "exchange_code", MagicMock(side_effect=ValueError("sensitive provider detail")))

    with caplog.at_level("ERROR", logger="api.auth"), pytest.raises(HTTPException) as exc:
        auth_endpoints.oidc_callback(
            auth_endpoints.OIDCCallbackRequest(
                code="code",
                state="state",
                nonce="nonce",
                tenant_name="tenant",
                redirect_uri=config["redirect_uri"],
            ),
            _request(),
        )

    assert exc.value.detail == "OIDC authentication failed"
    assert "sensitive provider detail" not in exc.value.detail
    assert "sensitive provider detail" in caplog.text
    db.rollback.assert_called_once()


def test_password_reset_delivery_error_is_generic_and_logged(monkeypatch, caplog):
    db = MagicMock()
    tenant = MagicMock(id="00000000-0000-4000-8000-000000000001", name="tenant")
    monkeypatch.setattr(auth_endpoints, "OwnerSessionLocal", lambda: db)
    monkeypatch.setattr(auth_endpoints, "_active_users_for_email", lambda *_: [(MagicMock(), tenant)])
    monkeypatch.setattr(
        auth_endpoints,
        "_deliver_otp",
        MagicMock(side_effect=auth_endpoints.EmailDeliveryError("sensitive SMTP detail")),
    )

    with caplog.at_level("ERROR", logger="api.auth"), pytest.raises(HTTPException) as exc:
        auth_endpoints.request_password_reset(
            auth_endpoints.PasswordResetRequest(email="user@example.com", tenant_name="tenant")
        )

    assert exc.value.status_code == 503
    assert exc.value.detail == "Authentication service is temporarily unavailable"
    assert "sensitive SMTP detail" not in exc.value.detail
    assert "sensitive SMTP detail" in caplog.text
    db.rollback.assert_called_once()


@pytest.mark.parametrize(("error", "reason"), [
    (oidc_sso.OIDCAuthorizationError("OIDC identity is not authorized for this tenant", "wrong_tenant"), "wrong_tenant"),
    (oidc_sso.OIDCAuthorizationError("Required OIDC MFA context is missing", "missing_mfa"), "missing_mfa"),
])
def test_oidc_policy_rejection_returns_403(monkeypatch, error, reason):
    db = MagicMock()
    tenant = MagicMock(id="00000000-0000-4000-8000-000000000001")
    config = {"redirect_uri": "https://app.example.com/api/auth/oidc/callback"}
    monkeypatch.setattr(auth_endpoints, "OwnerSessionLocal", lambda: db)
    monkeypatch.setattr(auth_endpoints, "_oidc_callback_config", lambda *_: (tenant, config))
    monkeypatch.setattr(oidc_sso, "exchange_code", lambda *_: {"id_token": "token"})
    monkeypatch.setattr(oidc_sso, "validate_id_token", MagicMock(side_effect=error))
    emit = MagicMock()
    monkeypatch.setattr(auth_endpoints, "_emit_oidc_audit", emit)

    with pytest.raises(HTTPException) as exc:
        auth_endpoints.oidc_callback(
            auth_endpoints.OIDCCallbackRequest(
                code="code",
                state="state",
                nonce="nonce",
                tenant_name="tenant",
                redirect_uri=config["redirect_uri"],
            ),
            _request(),
        )

    assert exc.value.status_code == 403
    assert exc.value.detail == "OIDC authorization failed"
    emit.assert_called_once_with(
        tenant_id=str(tenant.id),
        action=reason,
        reason=reason,
        request_id="request-1",
        response_status=403,
    )


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (PermissionError("unknown user at Example IdP"), "authorization_failed"),
        (PermissionError("inactive user at Example IdP"), "authorization_failed"),
        (
            oidc_sso.OIDCAuthorizationError(
                "invitation tenant details",
                "invitation_authorization_failed",
            ),
            "invitation_authorization_failed",
        ),
    ],
)
def test_oidc_user_authorization_failure_is_generic_and_rolled_back(monkeypatch, error, reason):
    db = MagicMock()
    tenant = MagicMock(id="00000000-0000-4000-8000-000000000001")
    config = {"redirect_uri": "https://app.example.com/api/auth/oidc/callback"}
    issue_console_key = MagicMock()
    emit = MagicMock()
    monkeypatch.setattr(auth_endpoints, "OwnerSessionLocal", lambda: db)
    monkeypatch.setattr(auth_endpoints, "_oidc_callback_config", lambda *_: (tenant, config))
    monkeypatch.setattr(oidc_sso, "exchange_code", lambda *_: {"id_token": "token"})
    monkeypatch.setattr(oidc_sso, "validate_id_token", lambda *_: {"sub": "subject"})
    monkeypatch.setattr(oidc_sso, "map_user", MagicMock(side_effect=error))
    monkeypatch.setattr(oidc_sso, "issue_console_key", issue_console_key)
    monkeypatch.setattr(auth_endpoints, "_emit_oidc_audit", emit)

    with pytest.raises(HTTPException) as exc:
        auth_endpoints.oidc_callback(
            auth_endpoints.OIDCCallbackRequest(
                code="code",
                state="state",
                nonce="nonce",
                tenant_name="tenant",
                redirect_uri=config["redirect_uri"],
            ),
            _request(),
        )

    assert exc.value.status_code == 403
    assert exc.value.detail == "OIDC authorization failed"
    assert "Example IdP" not in exc.value.detail
    assert "invitation" not in exc.value.detail.lower()
    db.rollback.assert_called_once()
    db.commit.assert_not_called()
    issue_console_key.assert_not_called()
    emit.assert_called_once_with(
        tenant_id=str(tenant.id),
        action=reason,
        reason=reason,
        request_id="request-1",
        response_status=403,
    )


def test_oidc_rejects_redirect_uri_mismatch(monkeypatch):
    db = MagicMock()
    tenant = MagicMock(id="00000000-0000-4000-8000-000000000001")
    config = {"redirect_uri": "https://app.example.com/api/auth/oidc/callback"}
    monkeypatch.setattr(auth_endpoints, "OwnerSessionLocal", lambda: db)
    monkeypatch.setattr(auth_endpoints, "_oidc_callback_config", lambda *_: (tenant, config))
    emit = MagicMock()
    monkeypatch.setattr(auth_endpoints, "_emit_oidc_audit", emit)

    with pytest.raises(HTTPException) as exc:
        auth_endpoints.oidc_callback(
            auth_endpoints.OIDCCallbackRequest(
                code="code",
                state="state",
                nonce="nonce",
                tenant_name="tenant",
                redirect_uri="https://evil.example.com/callback",
            ),
            _request(),
        )

    assert exc.value.status_code == 400
    assert exc.value.detail == "Invalid OIDC redirect URI"
    emit.assert_called_once_with(
        tenant_id=str(tenant.id),
        action="redirect_uri_validation_failed",
        reason="redirect_uri_validation_failed",
        request_id="request-1",
        response_status=400,
    )


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (jwt.InvalidIssuerError(), "issuer_validation_failed"),
        (jwt.InvalidAudienceError(), "audience_validation_failed"),
        (jwt.InvalidSignatureError(), "signature_validation_failed"),
        (oidc_sso.OIDCAuthenticationError("nonce_validation_failed"), "nonce_validation_failed"),
        (jwt.DecodeError(), "invalid_token"),
    ],
)
def test_oidc_validation_failure_emits_categorical_audit(monkeypatch, error, reason):
    db = MagicMock()
    tenant = MagicMock(id="00000000-0000-4000-8000-000000000001")
    config = {"redirect_uri": "https://app.example.com/api/auth/oidc/callback"}
    emit = MagicMock()
    monkeypatch.setattr(auth_endpoints, "OwnerSessionLocal", lambda: db)
    monkeypatch.setattr(auth_endpoints, "_oidc_callback_config", lambda *_: (tenant, config))
    monkeypatch.setattr(oidc_sso, "exchange_code", lambda *_: {"id_token": "sensitive-id-token"})
    monkeypatch.setattr(oidc_sso, "validate_id_token", MagicMock(side_effect=error))
    monkeypatch.setattr(auth_endpoints, "_emit_oidc_audit", emit)

    with pytest.raises(HTTPException):
        auth_endpoints.oidc_callback(
            auth_endpoints.OIDCCallbackRequest(
                code="sensitive-code",
                state="sensitive-state",
                nonce="sensitive-nonce",
                tenant_name="tenant",
                redirect_uri=config["redirect_uri"],
            ),
            _request("correlation-1"),
        )

    emit.assert_called_once_with(
        tenant_id=str(tenant.id),
        action=reason,
        reason=reason,
        request_id="correlation-1",
        response_status=401,
    )


def test_oidc_success_emits_actor_and_tenant_audit(monkeypatch):
    db = MagicMock()
    tenant = MagicMock(id="00000000-0000-4000-8000-000000000001")
    tenant.name = "tenant"
    user = MagicMock(id="00000000-0000-4000-8000-000000000002", email="user@example.com")
    config = {"redirect_uri": "https://app.example.com/api/auth/oidc/callback"}
    emit = MagicMock()
    monkeypatch.setattr(auth_endpoints, "OwnerSessionLocal", lambda: db)
    monkeypatch.setattr(auth_endpoints, "_oidc_callback_config", lambda *_: (tenant, config))
    monkeypatch.setattr(oidc_sso, "exchange_code", lambda *_: {"id_token": "token"})
    monkeypatch.setattr(oidc_sso, "validate_id_token", lambda *_: {"sub": "subject"})
    monkeypatch.setattr(oidc_sso, "map_user", lambda *_: (user, "viewer"))
    monkeypatch.setattr(oidc_sso, "issue_console_key", lambda *_: ("api-key", ["read"]))
    monkeypatch.setattr(auth_endpoints, "_emit_oidc_audit", emit)

    auth_endpoints.oidc_callback(
        auth_endpoints.OIDCCallbackRequest(
            code="code",
            state="state",
            nonce="nonce",
            tenant_name="tenant",
            redirect_uri=config["redirect_uri"],
        ),
        _request("correlation-2"),
    )

    emit.assert_called_once_with(
        tenant_id=str(tenant.id),
        actor_id=str(user.id),
        action="oidc_login_succeeded",
        reason="success",
        request_id="correlation-2",
        response_status=200,
    )


@pytest.mark.parametrize(
    ("role", "scopes"),
    [
        ("viewer", ["read"]),
        ("developer", ["read"]),
        ("operator", ["read"]),
        ("admin", ["admin", "read", "write"]),
        ("owner", ["admin", "read", "write"]),
    ],
)
def test_password_login_preserves_persisted_invitation_role(monkeypatch, role, scopes):
    db = MagicMock()
    tenant = MagicMock(
        id="00000000-0000-4000-8000-000000000001",
    )
    tenant.name = "tenant"
    user = MagicMock(
        id="00000000-0000-4000-8000-000000000002",
        email="user@example.com",
        password_hash="password-hash",
        role=role,
    )
    monkeypatch.setattr(auth_endpoints, "OwnerSessionLocal", lambda: db)
    monkeypatch.setattr(auth_endpoints, "_active_users_for_email", lambda *_args: [(user, tenant)])
    monkeypatch.setattr(auth_endpoints, "verify_password", lambda *_: True)
    monkeypatch.setattr(auth_endpoints, "_enforce_password_login_rate_limit", lambda *_: None)

    response = auth_endpoints.password_login(
        auth_endpoints.PasswordLoginRequest(
            email="user@example.com",
            password="correct password",
            tenant_name="tenant",
        ),
        _request(),
    )

    assert str(response.user_id) == user.id
    assert str(response.tenant_id) == tenant.id
    assert response.role == role
    assert response.scopes == scopes
    assert user.role == role
    assert response.api_key.startswith("acl_console_")
    db.add.assert_called_once()
    db.commit.assert_called_once()


def test_password_login_rate_limits_before_database_lookup(monkeypatch):
    open_database = MagicMock()
    monkeypatch.setattr(auth_endpoints, "OwnerSessionLocal", open_database)
    monkeypatch.setattr(
        auth_endpoints,
        "_enforce_password_login_rate_limit",
        MagicMock(side_effect=HTTPException(status_code=429, detail="Too many login attempts. Try again later.")),
    )

    with pytest.raises(HTTPException) as exc:
        auth_endpoints.password_login(
            auth_endpoints.PasswordLoginRequest(email="USER@example.com", password="wrong"),
            _request(),
        )

    assert exc.value.status_code == 429
    open_database.assert_not_called()


def test_failed_password_login_is_audited(monkeypatch):
    db = MagicMock()
    tenant = MagicMock(id="00000000-0000-4000-8000-000000000001")
    user = MagicMock(
        id="00000000-0000-4000-8000-000000000002",
        password_hash="password-hash",
    )
    emit = MagicMock()
    monkeypatch.setattr(auth_endpoints, "OwnerSessionLocal", lambda: db)
    monkeypatch.setattr(
        auth_endpoints, "_active_users_for_email", lambda *_: [(user, tenant)]
    )
    monkeypatch.setattr(auth_endpoints, "verify_password", lambda *_: False)
    monkeypatch.setattr(auth_endpoints, "_enforce_password_login_rate_limit", lambda *_: None)
    monkeypatch.setattr(auth_endpoints, "_emit_oidc_audit", emit)

    with pytest.raises(HTTPException) as exc:
        auth_endpoints.password_login(
            auth_endpoints.PasswordLoginRequest(
                email="user@example.com", password="wrong password"
            ),
            _request("failed-login"),
        )

    assert exc.value.status_code == 401
    emit.assert_called_once_with(
        tenant_id=str(tenant.id),
        actor_id=str(user.id),
        action="password_login_failed",
        reason="invalid_credentials",
        request_id="failed-login",
        response_status=401,
        provider="password",
    )


def test_password_login_rate_limit_uses_normalized_account_and_direct_peer(monkeypatch):
    calls = []
    monkeypatch.setattr(auth_endpoints, "_enforce_onboarding_rate_limit", lambda *args: calls.append(args))
    request = MagicMock(headers={"x-forwarded-for": "198.51.100.9"})
    request.client.host = "203.0.113.7"

    auth_endpoints._enforce_password_login_rate_limit("user@example.com", request)

    assert calls[0][0] == f"auth:login:ip:{auth_endpoints._rate_limit_hash('203.0.113.7')}"
    assert calls[1][0] == f"auth:login:account:{auth_endpoints._rate_limit_hash('user@example.com')}"
    assert calls[0][1:3] == (auth_endpoints.LOGIN_IP_ATTEMPTS_PER_MINUTE, 60)
    assert calls[1][1:3] == (auth_endpoints.LOGIN_ACCOUNT_ATTEMPTS_PER_15_MINUTES, 900)


def test_oidc_audit_event_contains_no_sensitive_authentication_material(monkeypatch):
    published = []
    monkeypatch.setattr(auth_endpoints.event_backbone, "make_kafka_producer", lambda: object())
    monkeypatch.setattr(
        auth_endpoints.event_backbone,
        "publish_audit_event",
        lambda _producer, _tenant_id, event: published.append(event),
    )
    monkeypatch.setattr(auth_endpoints, "_oidc_kafka_producer", None)

    auth_endpoints._emit_oidc_audit(
        tenant_id="tenant-1",
        actor_id="user-1",
        action="nonce_validation_failed",
        reason="nonce_validation_failed",
        request_id="request-1",
        response_status=401,
    )

    assert published[0]["action"] == "auth:nonce_validation_failed"
    assert published[0]["reason"] == "nonce_validation_failed"
    assert published[0]["result"] == "failure"
    serialized = str(published[0]).lower()
    for forbidden in ("authorization_code", "id_token", "refresh_token", "nonce-token", "state-token", "client_secret", "cookie", "raw_claims"):
        assert forbidden not in serialized


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

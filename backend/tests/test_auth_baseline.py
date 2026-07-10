import hmac

from app.core.auth import hash_key
from app.core import oidc
from app.core.passwords import hash_password, verify_password
from app.schemas.models import APIKeyCreate, APIKeyRotate
from app.services import oidc_sso
from app.services.email_service import send_otp_email


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

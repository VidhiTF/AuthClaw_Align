"""Tenant OIDC SSO configuration and callback helpers."""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode

import jwt
import requests
from sqlalchemy.orm import Session

from app.api.v1.endpoints.onboarding import _scopes_for_role
from app.core.auth import hash_key
from app.core.crypto import decrypt_secret, encrypt_secret
from app.db.models import APIKey, Tenant, TenantOIDCConfig, User

VALID_ROLES = ("owner", "admin", "developer", "operator", "viewer")
ROLE_RANK = {role: index for index, role in enumerate(VALID_ROLES)}


class OIDCAuthenticationError(ValueError):
    """The identity provider response could not be authenticated."""


class OIDCAuthorizationError(PermissionError):
    """The authenticated identity does not satisfy tenant policy."""


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def env_config() -> dict[str, Any] | None:
    issuer = os.getenv("OIDC_ISSUER_URL", "").rstrip("/")
    client_id = os.getenv("OIDC_CLIENT_ID", "")
    redirect_uri = os.getenv("OIDC_REDIRECT_URI", "")
    if not issuer or not client_id or not redirect_uri:
        return None
    return {
        "source": "env",
        "enabled": True,
        "tenant_name": os.getenv("OIDC_TENANT_NAME", "").strip(),
        "issuer": issuer,
        "client_id": client_id,
        "client_secret": os.getenv("OIDC_CLIENT_SECRET", ""),
        "redirect_uri": redirect_uri,
        "scopes": os.getenv("OIDC_SCOPES", "openid email profile").split(),
        "authorization_endpoint": os.getenv("OIDC_AUTHORIZATION_ENDPOINT", f"{issuer}/authorize"),
        "token_endpoint": os.getenv("OIDC_TOKEN_ENDPOINT", f"{issuer}/token"),
        "jwks_uri": os.getenv("OIDC_JWKS_URI", f"{issuer}/.well-known/jwks.json"),
        "email_claim": os.getenv("OIDC_EMAIL_CLAIM", "email"),
        "groups_claim": os.getenv("OIDC_GROUPS_CLAIM", "groups"),
        "tenant_claim": os.getenv("OIDC_TENANT_CLAIM", "tenant_id"),
        "tenant_claim_value": os.getenv("OIDC_TENANT_CLAIM_VALUE", ""),
        "role_mapping": _parse_role_mapping(os.getenv("OIDC_GROUP_ROLE_MAPPING", "")),
        "default_role": _clean_role(os.getenv("OIDC_DEFAULT_ROLE", "viewer")),
        "auto_provision": os.getenv("OIDC_AUTO_PROVISION", "false").lower() == "true",
        "require_mfa": os.getenv("OIDC_REQUIRE_MFA", "true").lower() == "true",
        "accepted_amr": [value for value in os.getenv("OIDC_ACCEPTED_AMR", "mfa").split(",") if value],
        "accepted_acr": [value for value in os.getenv("OIDC_ACCEPTED_ACR", "").split(",") if value],
        "max_auth_age_seconds": int(os.getenv("OIDC_MAX_AUTH_AGE_SECONDS", "43200")),
        "status": "active",
    }


def _parse_role_mapping(value: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for pair in (value or "").split(","):
        if "=" not in pair:
            continue
        group, role = pair.split("=", 1)
        role = _clean_role(role)
        if group.strip():
            mapping[group.strip()] = role
    return mapping


def _clean_role(role: str | None) -> str:
    value = (role or "viewer").strip().lower()
    return value if value in VALID_ROLES else "viewer"


def _endpoints(config: TenantOIDCConfig | dict[str, Any]) -> dict[str, str]:
    if isinstance(config, dict):
        issuer = config["issuer"].rstrip("/")
        return {
            "authorization_endpoint": config.get("authorization_endpoint") or f"{issuer}/authorize",
            "token_endpoint": config.get("token_endpoint") or f"{issuer}/token",
            "jwks_uri": config.get("jwks_uri") or f"{issuer}/.well-known/jwks.json",
        }
    issuer = config.issuer.rstrip("/")
    return {
        "authorization_endpoint": config.authorization_endpoint or f"{issuer}/authorize",
        "token_endpoint": config.token_endpoint or f"{issuer}/token",
        "jwks_uri": config.jwks_uri or f"{issuer}/.well-known/jwks.json",
    }


def serialize_config(config: TenantOIDCConfig | None) -> dict[str, Any]:
    if not config:
        return {
            "enabled": False,
            "status": "disabled",
            "issuer": "",
            "client_id": "",
            "redirect_uri": "",
            "scopes": ["openid", "email", "profile"],
            "authorization_endpoint": "",
            "token_endpoint": "",
            "jwks_uri": "",
            "email_claim": "email",
            "groups_claim": "groups",
            "tenant_claim": "tenant_id",
            "tenant_claim_value": "",
            "role_mapping": {},
            "default_role": "viewer",
            "auto_provision": False,
            "require_mfa": True,
            "accepted_amr": ["mfa"],
            "accepted_acr": [],
            "max_auth_age_seconds": 43200,
            "has_client_secret": False,
            "last_tested_at": None,
            "last_error": None,
        }
    endpoints = _endpoints(config)
    return {
        "enabled": config.status == "active",
        "status": config.status,
        "issuer": config.issuer,
        "client_id": config.client_id,
        "redirect_uri": config.redirect_uri,
        "scopes": config.scopes or ["openid", "email", "profile"],
        **endpoints,
        "email_claim": config.email_claim,
        "groups_claim": config.groups_claim,
        "tenant_claim": config.tenant_claim,
        "tenant_claim_value": config.tenant_claim_value or "",
        "role_mapping": config.role_mapping or {},
        "default_role": config.default_role,
        "auto_provision": config.auto_provision,
        "require_mfa": config.require_mfa,
        "accepted_amr": config.accepted_amr or ["mfa"],
        "accepted_acr": config.accepted_acr or [],
        "max_auth_age_seconds": config.max_auth_age_seconds,
        "has_client_secret": bool(config.encrypted_client_secret),
        "last_tested_at": config.last_tested_at.isoformat() if config.last_tested_at else None,
        "last_error": config.last_error,
    }


def public_config(db: Session, tenant_name: str | None = None) -> tuple[Tenant | None, dict[str, Any] | None]:
    if tenant_name:
        tenant = db.query(Tenant).filter(Tenant.name.ilike(tenant_name.strip()), Tenant.status == "active").first()
        if tenant:
            row = db.query(TenantOIDCConfig).filter(
                TenantOIDCConfig.tenant_id == tenant.id,
                TenantOIDCConfig.status == "active",
            ).first()
            if row:
                return tenant, {**serialize_config(row), "source": "tenant"}
    env = env_config()
    if env:
        tenant = None
        mapped_name = tenant_name or env.get("tenant_name")
        if mapped_name:
            tenant = db.query(Tenant).filter(Tenant.name.ilike(mapped_name), Tenant.status == "active").first()
        return tenant, env
    return None, None


def authorization_url(config: dict[str, Any], state: str, nonce: str) -> str:
    return config["authorization_endpoint"] + "?" + urlencode({
        "client_id": config["client_id"],
        "redirect_uri": config["redirect_uri"],
        "response_type": "code",
        "scope": " ".join(config.get("scopes") or ["openid", "email", "profile"]),
        "state": state,
        "nonce": nonce,
    })


def upsert_config(db: Session, tenant_id: Any, user_id: Any, payload: dict[str, Any]) -> TenantOIDCConfig:
    issuer = str(payload.get("issuer") or "").rstrip("/")
    client_id = str(payload.get("client_id") or "").strip()
    redirect_uri = str(payload.get("redirect_uri") or "").strip()
    if not issuer.startswith("https://") or not redirect_uri.startswith("https://"):
        raise ValueError("OIDC issuer and redirect URI must use https")
    if not client_id:
        raise ValueError("OIDC client_id is required")
    tenant_claim = str(payload.get("tenant_claim") or "tenant_id").strip()
    tenant_claim_value = str(payload.get("tenant_claim_value") or "").strip()
    if payload.get("enabled") and (not tenant_claim or not tenant_claim_value):
        raise ValueError("Active OIDC configuration requires tenant claim and claim value")
    max_auth_age_seconds = int(payload.get("max_auth_age_seconds", 43200))
    if max_auth_age_seconds < 0:
        raise ValueError("OIDC max_auth_age_seconds cannot be negative")
    scopes = payload.get("scopes") or ["openid", "email", "profile"]
    if "openid" not in scopes:
        scopes = ["openid", *scopes]
    status = "active" if payload.get("enabled") else "disabled"
    role_mapping = {
        str(group): _clean_role(role)
        for group, role in dict(payload.get("role_mapping") or {}).items()
        if str(group).strip()
    }

    config = db.query(TenantOIDCConfig).filter(TenantOIDCConfig.tenant_id == tenant_id).first()
    if not config:
        config = TenantOIDCConfig(id=uuid.uuid4(), tenant_id=tenant_id, created_by=user_id)
        db.add(config)
    config.issuer = issuer
    config.client_id = client_id
    if payload.get("client_secret"):
        config.encrypted_client_secret = encrypt_secret(str(payload["client_secret"]))
    elif payload.get("clear_client_secret"):
        config.encrypted_client_secret = None
    config.redirect_uri = redirect_uri
    config.scopes = scopes
    config.authorization_endpoint = str(payload.get("authorization_endpoint") or "").strip() or None
    config.token_endpoint = str(payload.get("token_endpoint") or "").strip() or None
    config.jwks_uri = str(payload.get("jwks_uri") or "").strip() or None
    config.email_claim = str(payload.get("email_claim") or "email").strip()
    config.groups_claim = str(payload.get("groups_claim") or "groups").strip()
    config.tenant_claim = tenant_claim
    config.tenant_claim_value = tenant_claim_value or None
    config.role_mapping = role_mapping
    config.default_role = _clean_role(payload.get("default_role"))
    config.auto_provision = bool(payload.get("auto_provision"))
    config.require_mfa = bool(payload.get("require_mfa", True))
    config.accepted_amr = [str(value) for value in payload.get("accepted_amr", ["mfa"]) if str(value)]
    config.accepted_acr = [str(value) for value in payload.get("accepted_acr", []) if str(value)]
    config.max_auth_age_seconds = max_auth_age_seconds
    config.status = status
    config.updated_by = user_id
    config.updated_at = now_utc()
    db.commit()
    db.refresh(config)
    return config


def test_config(db: Session, config: TenantOIDCConfig) -> dict[str, Any]:
    endpoints = _endpoints(config)
    try:
        response = requests.get(endpoints["jwks_uri"], timeout=5)
        response.raise_for_status()
        keys = response.json().get("keys", [])
        if not keys:
            raise ValueError("JWKS endpoint returned no keys")
        config.last_tested_at = now_utc()
        config.last_error = None
        db.commit()
        return {"ok": True, "jwks_keys": len(keys), "authorization_endpoint": endpoints["authorization_endpoint"]}
    except Exception:
        config.last_tested_at = now_utc()
        config.last_error = "OIDC configuration test failed"
        db.commit()
        return {"ok": False, "error": "OIDC configuration test failed"}


def _client_secret(config: dict[str, Any] | TenantOIDCConfig) -> str:
    if isinstance(config, dict):
        return str(config.get("client_secret") or "")
    return decrypt_secret(config.encrypted_client_secret) if config.encrypted_client_secret else ""


def exchange_code(config: dict[str, Any] | TenantOIDCConfig, code: str, redirect_uri: str) -> dict[str, Any]:
    endpoints = _endpoints(config)
    client_id = config["client_id"] if isinstance(config, dict) else config.client_id
    secret = _client_secret(config)
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
    }
    if secret:
        data["client_secret"] = secret
    response = requests.post(endpoints["token_endpoint"], data=data, timeout=10)
    response.raise_for_status()
    return response.json()


def validate_id_token(config: dict[str, Any] | TenantOIDCConfig, id_token: str, nonce: str) -> dict[str, Any]:
    endpoints = _endpoints(config)
    issuer = config["issuer"] if isinstance(config, dict) else config.issuer
    client_id = config["client_id"] if isinstance(config, dict) else config.client_id
    signing_key = jwt.PyJWKClient(endpoints["jwks_uri"]).get_signing_key_from_jwt(id_token)
    claims = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
        audience=client_id,
        issuer=issuer,
        options={"require": ["exp", "iat", "iss", "aud", "sub"]},
    )
    audience = claims.get("aud")
    if isinstance(audience, list) and len(audience) > 1 and claims.get("azp") != client_id:
        raise OIDCAuthenticationError("OIDC authentication failed")
    if claims.get("nonce") != nonce:
        raise OIDCAuthenticationError("OIDC authentication failed")
    if claims.get("email_verified") is False:
        raise OIDCAuthenticationError("OIDC authentication failed")
    validate_identity_context(config, claims)
    return claims


def _config_value(config: dict[str, Any] | TenantOIDCConfig, name: str, default: Any = None) -> Any:
    return config.get(name, default) if isinstance(config, dict) else getattr(config, name, default)


def validate_identity_context(config: dict[str, Any] | TenantOIDCConfig, claims: dict[str, Any]) -> None:
    tenant_claim = str(_config_value(config, "tenant_claim", "tenant_id"))
    expected_tenant = str(_config_value(config, "tenant_claim_value", "") or "")
    if not expected_tenant or str(claims.get(tenant_claim) or "") != expected_tenant:
        raise OIDCAuthorizationError("OIDC identity is not authorized for this tenant")

    if not bool(_config_value(config, "require_mfa", True)):
        return
    amr = claims.get("amr") or []
    if isinstance(amr, str):
        amr = [amr]
    accepted_amr = set(_config_value(config, "accepted_amr", ["mfa"]) or [])
    accepted_acr = set(_config_value(config, "accepted_acr", []) or [])
    mfa_satisfied = bool(accepted_amr.intersection(str(value) for value in amr))
    mfa_satisfied = mfa_satisfied or str(claims.get("acr") or "") in accepted_acr
    if not mfa_satisfied:
        raise OIDCAuthorizationError("Required OIDC MFA context is missing")

    max_age = int(_config_value(config, "max_auth_age_seconds", 43200))
    auth_time = claims.get("auth_time")
    if max_age and (not isinstance(auth_time, (int, float)) or now_utc().timestamp() - auth_time > max_age or auth_time > now_utc().timestamp() + 60):
        raise OIDCAuthorizationError("Required OIDC MFA context is missing")


def role_from_claims(config: dict[str, Any] | TenantOIDCConfig, claims: dict[str, Any]) -> str:
    groups_claim = config["groups_claim"] if isinstance(config, dict) else config.groups_claim
    default_role = _clean_role(config.get("default_role") if isinstance(config, dict) else config.default_role)
    mapping = dict(config.get("role_mapping") if isinstance(config, dict) else config.role_mapping or {})
    groups = claims.get(groups_claim) or []
    if isinstance(groups, str):
        groups = [groups]
    best = default_role
    for group in groups:
        mapped = _clean_role(mapping.get(str(group)))
        if ROLE_RANK[mapped] < ROLE_RANK[best]:
            best = mapped
    return best


def issue_console_key(db: Session, tenant: Tenant, user: User, email: str, role: str, source: str) -> tuple[str, list[str]]:
    raw_key = "acl_console_" + os.urandom(24).hex()
    scopes = _scopes_for_role(role)
    now = now_utc()
    db.add(APIKey(
        tenant_id=tenant.id,
        key_hash=hash_key(raw_key),
        name=f"Console Session - {email}",
        description=f"Short-lived key issued after {source} login",
        scopes=scopes,
        is_active=True,
        expires_at=now + timedelta(hours=24),
        created_by=user.id,
    ))
    user.last_login = now
    return raw_key, scopes


def map_user(db: Session, tenant: Tenant, config: dict[str, Any] | TenantOIDCConfig, claims: dict[str, Any]) -> tuple[User, str]:
    email_claim = config["email_claim"] if isinstance(config, dict) else config.email_claim
    email = str(claims.get(email_claim) or "").strip().lower()
    if not email or "@" not in email:
        raise ValueError(f"OIDC claim {email_claim} did not contain an email address")
    role = role_from_claims(config, claims)
    user = db.query(User).filter(User.tenant_id == tenant.id, User.email == email).first()
    auto_provision = bool(config.get("auto_provision") if isinstance(config, dict) else config.auto_provision)
    if not user:
        if not auto_provision:
            raise PermissionError("SSO user is not provisioned in this tenant")
        user = User(id=uuid.uuid4(), tenant_id=tenant.id, email=email, role=role, is_active=True)
        db.add(user)
    if not user.is_active:
        raise PermissionError("SSO user is disabled")
    if user.role != "owner" or role == "owner":
        user.role = role
    return user, _clean_role(user.role)

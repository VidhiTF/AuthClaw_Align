import base64
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from sqlalchemy import text

from database import engine
from services.secret_manager import SecretManager
from services.tenant_context import auth_lookup_context, tenant_context


SUPPORTED_PROVIDER_TYPES = {
    "microsoft_entra",
    "google_workspace",
    "okta",
    "auth0",
    "generic_oidc",
}

DEFAULT_SCOPES = "openid email profile offline_access"
DEFAULT_ROLE = "Developer"
DEFAULT_PERMISSIONS = "read_write_gateway"
OIDC_STATE_TTL_SECONDS = int(os.getenv("AUTHCLAW_OIDC_STATE_TTL_SECONDS", "600"))
JWKS_CACHE_TTL_SECONDS = int(os.getenv("AUTHCLAW_JWKS_CACHE_TTL_SECONDS", "3600"))
JWKS_STALE_TTL_SECONDS = int(os.getenv("AUTHCLAW_JWKS_STALE_TTL_SECONDS", "86400"))


class EnterpriseIdentityError(RuntimeError):
    pass


@dataclass(frozen=True)
class OIDCProviderConfig:
    id: int
    tenant_id: int
    provider_type: str
    display_name: str
    client_id: str
    encrypted_client_secret: str
    discovery_url: Optional[str]
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: Optional[str]
    jwks_uri: str
    redirect_uri: str
    scopes: str
    groups_claim: str
    role_mapping: Dict[str, str]
    enabled: bool


def _b64url_decode(value: str) -> bytes:
    padding_len = (-len(value)) % 4
    return base64.urlsafe_b64decode(value + ("=" * padding_len))


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _hash_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def generate_pkce_verifier() -> str:
    return _b64url_encode(secrets.token_bytes(32))


def pkce_challenge(verifier: str) -> str:
    return _b64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())


def normalize_provider_type(provider_type: str) -> str:
    normalized = (provider_type or "").strip().lower().replace(" ", "_").replace("-", "_")
    aliases = {
        "azure_ad": "microsoft_entra",
        "azure": "microsoft_entra",
        "entra": "microsoft_entra",
        "microsoft": "microsoft_entra",
        "google": "google_workspace",
        "workspace": "google_workspace",
        "oidc": "generic_oidc",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized not in SUPPORTED_PROVIDER_TYPES:
        raise EnterpriseIdentityError(f"Unsupported OIDC provider type '{provider_type}'.")
    return normalized


def _json_loads(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return default


def discover_oidc_metadata(discovery_url: str) -> Dict[str, Any]:
    response = requests.get(discovery_url, timeout=10)
    response.raise_for_status()
    metadata = response.json()
    required = ["issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"]
    missing = [name for name in required if not metadata.get(name)]
    if missing:
        raise EnterpriseIdentityError(f"OIDC discovery metadata is missing: {', '.join(missing)}")
    return metadata


def _row_to_config(row) -> OIDCProviderConfig:
    mapping = row._mapping if hasattr(row, "_mapping") else row
    return OIDCProviderConfig(
        id=mapping["id"],
        tenant_id=mapping["tenant_id"],
        provider_type=mapping["provider_type"],
        display_name=mapping["display_name"],
        client_id=mapping["client_id"],
        encrypted_client_secret=mapping["encrypted_client_secret"],
        discovery_url=mapping.get("discovery_url"),
        issuer=mapping["issuer"],
        authorization_endpoint=mapping["authorization_endpoint"],
        token_endpoint=mapping["token_endpoint"],
        userinfo_endpoint=mapping.get("userinfo_endpoint"),
        jwks_uri=mapping["jwks_uri"],
        redirect_uri=mapping["redirect_uri"],
        scopes=mapping.get("scopes") or DEFAULT_SCOPES,
        groups_claim=mapping.get("groups_claim") or "groups",
        role_mapping=_json_loads(mapping.get("role_mapping"), {}),
        enabled=bool(mapping.get("enabled")),
    )


def get_provider_config(tenant_id: int, provider_id: int) -> OIDCProviderConfig:
    with tenant_context(tenant_id, required=True), engine.connect() as conn:
        row = conn.execute(
            text(
                """
                SELECT *
                FROM tenant_identity_providers
                WHERE id = :provider_id
                  AND tenant_id = :tenant_id
                  AND enabled = true
                """
            ),
            {"provider_id": provider_id, "tenant_id": tenant_id},
        ).mappings().fetchone()
    if not row:
        raise EnterpriseIdentityError("Enabled identity provider not found for tenant.")
    return _row_to_config(row)


def list_provider_configs(tenant_id: int) -> List[Dict[str, Any]]:
    with tenant_context(tenant_id, required=True), engine.connect() as conn:
        rows = conn.execute(
            text(
                """
                SELECT id, provider_type, display_name, client_id, discovery_url, issuer,
                       authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri,
                       redirect_uri, scopes, groups_claim, role_mapping, enabled,
                       created_at, updated_at
                FROM tenant_identity_providers
                WHERE tenant_id = :tenant_id
                ORDER BY id DESC
                """
            ),
            {"tenant_id": tenant_id},
        ).mappings().fetchall()
    results = []
    for row in rows:
        item = dict(row)
        item["role_mapping"] = _json_loads(item.get("role_mapping"), {})
        for key in ("created_at", "updated_at"):
            if hasattr(item.get(key), "isoformat"):
                item[key] = item[key].isoformat()
        results.append(item)
    return results


def upsert_provider_config(tenant_id: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    provider_type = normalize_provider_type(payload.get("provider_type") or payload.get("type") or "generic_oidc")
    discovery_url = payload.get("discovery_url")
    metadata: Dict[str, Any] = {}
    if discovery_url:
        metadata = discover_oidc_metadata(discovery_url)

    issuer = payload.get("issuer") or metadata.get("issuer")
    authorization_endpoint = payload.get("authorization_endpoint") or metadata.get("authorization_endpoint")
    token_endpoint = payload.get("token_endpoint") or metadata.get("token_endpoint")
    userinfo_endpoint = payload.get("userinfo_endpoint") or metadata.get("userinfo_endpoint")
    jwks_uri = payload.get("jwks_uri") or metadata.get("jwks_uri")
    client_id = payload.get("client_id")
    client_secret = payload.get("client_secret")
    redirect_uri = payload.get("redirect_uri")

    required = {
        "client_id": client_id,
        "client_secret": client_secret,
        "issuer": issuer,
        "authorization_endpoint": authorization_endpoint,
        "token_endpoint": token_endpoint,
        "jwks_uri": jwks_uri,
        "redirect_uri": redirect_uri,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise EnterpriseIdentityError(f"Identity provider config is missing: {', '.join(missing)}")

    encrypted_client_secret = SecretManager().encrypt_for_database(str(client_secret))
    role_mapping = json.dumps(payload.get("role_mapping") or {})
    enabled = bool(payload.get("enabled", True))
    provider_id = payload.get("id")

    with tenant_context(tenant_id, required=True), engine.connect() as conn:
        if provider_id:
            row = conn.execute(
                text(
                    """
                    UPDATE tenant_identity_providers
                    SET provider_type = :provider_type,
                        display_name = :display_name,
                        client_id = :client_id,
                        encrypted_client_secret = :encrypted_client_secret,
                        discovery_url = :discovery_url,
                        issuer = :issuer,
                        authorization_endpoint = :authorization_endpoint,
                        token_endpoint = :token_endpoint,
                        userinfo_endpoint = :userinfo_endpoint,
                        jwks_uri = :jwks_uri,
                        redirect_uri = :redirect_uri,
                        scopes = :scopes,
                        groups_claim = :groups_claim,
                        role_mapping = :role_mapping,
                        enabled = :enabled,
                        updated_at = NOW()
                    WHERE id = :provider_id AND tenant_id = :tenant_id
                    RETURNING id
                    """
                ),
                {
                    "provider_id": provider_id,
                    "tenant_id": tenant_id,
                    "provider_type": provider_type,
                    "display_name": payload.get("display_name") or provider_type,
                    "client_id": client_id,
                    "encrypted_client_secret": encrypted_client_secret,
                    "discovery_url": discovery_url,
                    "issuer": issuer,
                    "authorization_endpoint": authorization_endpoint,
                    "token_endpoint": token_endpoint,
                    "userinfo_endpoint": userinfo_endpoint,
                    "jwks_uri": jwks_uri,
                    "redirect_uri": redirect_uri,
                    "scopes": payload.get("scopes") or DEFAULT_SCOPES,
                    "groups_claim": payload.get("groups_claim") or "groups",
                    "role_mapping": role_mapping,
                    "enabled": enabled,
                },
            ).fetchone()
            if not row:
                raise EnterpriseIdentityError("Identity provider config not found for tenant.")
            saved_id = row[0]
        else:
            saved_id = conn.execute(
                text(
                    """
                    INSERT INTO tenant_identity_providers (
                        tenant_id, provider_type, display_name, client_id, encrypted_client_secret,
                        discovery_url, issuer, authorization_endpoint, token_endpoint,
                        userinfo_endpoint, jwks_uri, redirect_uri, scopes, groups_claim,
                        role_mapping, enabled
                    )
                    VALUES (
                        :tenant_id, :provider_type, :display_name, :client_id, :encrypted_client_secret,
                        :discovery_url, :issuer, :authorization_endpoint, :token_endpoint,
                        :userinfo_endpoint, :jwks_uri, :redirect_uri, :scopes, :groups_claim,
                        :role_mapping, :enabled
                    )
                    RETURNING id
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "provider_type": provider_type,
                    "display_name": payload.get("display_name") or provider_type,
                    "client_id": client_id,
                    "encrypted_client_secret": encrypted_client_secret,
                    "discovery_url": discovery_url,
                    "issuer": issuer,
                    "authorization_endpoint": authorization_endpoint,
                    "token_endpoint": token_endpoint,
                    "userinfo_endpoint": userinfo_endpoint,
                    "jwks_uri": jwks_uri,
                    "redirect_uri": redirect_uri,
                    "scopes": payload.get("scopes") or DEFAULT_SCOPES,
                    "groups_claim": payload.get("groups_claim") or "groups",
                    "role_mapping": role_mapping,
                    "enabled": enabled,
                },
            ).scalar()
        conn.commit()
    return {"id": saved_id, "provider_type": provider_type, "enabled": enabled}


def set_provider_enabled(tenant_id: int, provider_id: int, enabled: bool) -> Dict[str, Any]:
    with tenant_context(tenant_id, required=True), engine.connect() as conn:
        row = conn.execute(
            text(
                """
                UPDATE tenant_identity_providers
                SET enabled = :enabled, updated_at = NOW()
                WHERE id = :provider_id AND tenant_id = :tenant_id
                RETURNING id, enabled
                """
            ),
            {"provider_id": provider_id, "tenant_id": tenant_id, "enabled": enabled},
        ).fetchone()
        conn.commit()
    if not row:
        raise EnterpriseIdentityError("Identity provider config not found for tenant.")
    return {"id": row[0], "enabled": bool(row[1])}


def create_authorization_request(tenant_id: int, provider_id: int) -> Dict[str, Any]:
    provider = get_provider_config(tenant_id, provider_id)
    state = _b64url_encode(secrets.token_bytes(32))
    nonce = _b64url_encode(secrets.token_bytes(24))
    verifier = generate_pkce_verifier()
    challenge = pkce_challenge(verifier)
    state_hash = _hash_token(state)
    expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(seconds=OIDC_STATE_TTL_SECONDS)

    with tenant_context(tenant_id, required=True), engine.connect() as conn:
        conn.execute(
            text(
                """
                INSERT INTO oidc_login_states (
                    state_hash, tenant_id, provider_id, code_verifier, nonce,
                    redirect_uri, expires_at
                )
                VALUES (
                    :state_hash, :tenant_id, :provider_id, :code_verifier, :nonce,
                    :redirect_uri, :expires_at
                )
                """
            ),
            {
                "state_hash": state_hash,
                "tenant_id": tenant_id,
                "provider_id": provider_id,
                "code_verifier": verifier,
                "nonce": nonce,
                "redirect_uri": provider.redirect_uri,
                "expires_at": expires_at,
            },
        )
        conn.commit()

    query = urlencode(
        {
            "client_id": provider.client_id,
            "redirect_uri": provider.redirect_uri,
            "response_type": "code",
            "scope": provider.scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "access_type": "offline",
            "prompt": "consent",
        }
    )
    return {
        "authorization_url": f"{provider.authorization_endpoint}?{query}",
        "state": state,
        "expires_at": expires_at.isoformat(),
        "provider": provider.display_name,
        "provider_type": provider.provider_type,
        "pkce": {"method": "S256"},
    }


def _load_state(state: str) -> Dict[str, Any]:
    state_hash = _hash_token(state)
    with auth_lookup_context(), engine.connect() as conn:
        row = conn.execute(
            text(
                """
                SELECT state_hash, tenant_id, provider_id, code_verifier, nonce, redirect_uri
                FROM oidc_login_states
                WHERE state_hash = :state_hash
                  AND used_at IS NULL
                  AND expires_at > NOW()
                """
            ),
            {"state_hash": state_hash},
        ).mappings().fetchone()
    if not row:
        raise EnterpriseIdentityError("OIDC login state is invalid or expired.")
    return dict(row)


def _mark_state_used(state_hash: str, tenant_id: int) -> None:
    with tenant_context(tenant_id, required=True), engine.connect() as conn:
        conn.execute(
            text("UPDATE oidc_login_states SET used_at = NOW() WHERE state_hash = :state_hash"),
            {"state_hash": state_hash},
        )
        conn.commit()


def _get_client_secret(provider: OIDCProviderConfig) -> str:
    return SecretManager().decrypt_from_database(provider.encrypted_client_secret)


def exchange_authorization_code(provider: OIDCProviderConfig, code: str, code_verifier: str) -> Dict[str, Any]:
    response = requests.post(
        provider.token_endpoint,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": provider.redirect_uri,
            "client_id": provider.client_id,
            "client_secret": _get_client_secret(provider),
            "code_verifier": code_verifier,
        },
        headers={"Accept": "application/json"},
        timeout=15,
    )
    response.raise_for_status()
    token_response = response.json()
    if not token_response.get("id_token"):
        raise EnterpriseIdentityError("OIDC provider did not return an id_token.")
    return token_response


def _load_cached_jwks(provider_id: int, allow_stale: bool = False) -> Optional[Dict[str, Any]]:
    cutoff_seconds = JWKS_STALE_TTL_SECONDS if allow_stale else 0
    with auth_lookup_context(), engine.connect() as conn:
        if allow_stale:
            row = conn.execute(
                text(
                    """
                    SELECT jwks_json
                    FROM oidc_jwks_cache
                    WHERE provider_id = :provider_id
                      AND refreshed_at > NOW() - (:cutoff_seconds * INTERVAL '1 second')
                    """
                ),
                {"provider_id": provider_id, "cutoff_seconds": cutoff_seconds},
            ).fetchone()
        else:
            row = conn.execute(
                text(
                    """
                    SELECT jwks_json
                    FROM oidc_jwks_cache
                    WHERE provider_id = :provider_id
                      AND expires_at > NOW()
                    """
                ),
                {"provider_id": provider_id},
            ).fetchone()
    if not row:
        return None
    return _json_loads(row[0], None)


def refresh_jwks(provider: OIDCProviderConfig) -> Dict[str, Any]:
    try:
        response = requests.get(provider.jwks_uri, timeout=10)
        response.raise_for_status()
        jwks = response.json()
        if not isinstance(jwks.get("keys"), list):
            raise EnterpriseIdentityError("JWKS payload is missing keys.")
        expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(seconds=JWKS_CACHE_TTL_SECONDS)
        with tenant_context(provider.tenant_id, required=True), engine.connect() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO oidc_jwks_cache (
                        provider_id, tenant_id, jwks_json, refreshed_at, expires_at, last_error
                    )
                    VALUES (:provider_id, :tenant_id, :jwks_json, NOW(), :expires_at, NULL)
                    ON CONFLICT (provider_id) DO UPDATE SET
                        jwks_json = EXCLUDED.jwks_json,
                        refreshed_at = NOW(),
                        expires_at = EXCLUDED.expires_at,
                        last_error = NULL
                    """
                ),
                {
                    "provider_id": provider.id,
                    "tenant_id": provider.tenant_id,
                    "jwks_json": json.dumps(jwks),
                    "expires_at": expires_at,
                },
            )
            conn.commit()
        return jwks
    except Exception as exc:
        with tenant_context(provider.tenant_id, required=True), engine.connect() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO oidc_jwks_cache (
                        provider_id, tenant_id, jwks_json, refreshed_at, expires_at, last_error
                    )
                    VALUES (:provider_id, :tenant_id, '{}', NOW(), NOW(), :last_error)
                    ON CONFLICT (provider_id) DO UPDATE SET last_error = :last_error
                    """
                ),
                {"provider_id": provider.id, "tenant_id": provider.tenant_id, "last_error": str(exc)[:500]},
            )
            conn.commit()
        cached = _load_cached_jwks(provider.id, allow_stale=True)
        if cached:
            return cached
        raise EnterpriseIdentityError(f"Unable to refresh JWKS: {exc}") from exc


def get_jwks(provider: OIDCProviderConfig) -> Dict[str, Any]:
    cached = _load_cached_jwks(provider.id, allow_stale=False)
    if cached:
        return cached
    return refresh_jwks(provider)


def _public_key_from_jwk(jwk: Dict[str, Any]):
    if jwk.get("kty") != "RSA":
        raise EnterpriseIdentityError("Only RSA OIDC signing keys are supported.")
    n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
    return rsa.RSAPublicNumbers(e, n).public_key()


def validate_id_token(id_token: str, provider: OIDCProviderConfig, nonce: Optional[str] = None) -> Dict[str, Any]:
    parts = id_token.split(".")
    if len(parts) != 3:
        raise EnterpriseIdentityError("Invalid ID token format.")
    header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
    claims = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
    signature = _b64url_decode(parts[2])
    if header.get("alg") != "RS256":
        raise EnterpriseIdentityError("Unsupported ID token signing algorithm.")

    jwks = get_jwks(provider)
    key = next((item for item in jwks.get("keys", []) if item.get("kid") == header.get("kid")), None)
    if not key:
        jwks = refresh_jwks(provider)
        key = next((item for item in jwks.get("keys", []) if item.get("kid") == header.get("kid")), None)
    if not key:
        raise EnterpriseIdentityError("OIDC signing key not found in JWKS.")

    public_key = _public_key_from_jwk(key)
    public_key.verify(
        signature,
        f"{parts[0]}.{parts[1]}".encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    now = int(time.time())
    if claims.get("iss") != provider.issuer:
        raise EnterpriseIdentityError("ID token issuer does not match tenant IdP config.")
    audience = claims.get("aud")
    if isinstance(audience, list):
        valid_audience = provider.client_id in audience
    else:
        valid_audience = audience == provider.client_id
    if not valid_audience:
        raise EnterpriseIdentityError("ID token audience does not match tenant IdP config.")
    if int(claims.get("exp", 0)) <= now:
        raise EnterpriseIdentityError("ID token has expired.")
    if claims.get("nbf") and int(claims["nbf"]) > now + 60:
        raise EnterpriseIdentityError("ID token is not valid yet.")
    if nonce and claims.get("nonce") != nonce:
        raise EnterpriseIdentityError("ID token nonce does not match login state.")
    return claims


def fetch_userinfo(provider: OIDCProviderConfig, access_token: Optional[str]) -> Dict[str, Any]:
    if not provider.userinfo_endpoint or not access_token:
        return {}
    response = requests.get(
        provider.userinfo_endpoint,
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


def map_role(provider: OIDCProviderConfig, claims: Dict[str, Any], userinfo: Dict[str, Any]) -> str:
    groups_value = userinfo.get(provider.groups_claim, claims.get(provider.groups_claim, []))
    if isinstance(groups_value, str):
        groups = [groups_value]
    else:
        groups = list(groups_value or [])
    for group in groups:
        mapped = provider.role_mapping.get(group)
        if mapped:
            return mapped
    return provider.role_mapping.get("*", DEFAULT_ROLE)


def permissions_for_role(role: str) -> str:
    if role in {"Super Admin", "Platform Admin"}:
        return "all_access"
    if role == "Security Admin":
        return "read_write_gateway,manage_policies,manage_approvals"
    if role == "Auditor":
        return "audit_read"
    return DEFAULT_PERMISSIONS


def upsert_oidc_user(provider: OIDCProviderConfig, claims: Dict[str, Any], userinfo: Dict[str, Any]) -> Dict[str, Any]:
    email = userinfo.get("email") or claims.get("email") or claims.get("preferred_username") or claims.get("upn")
    if not email:
        raise EnterpriseIdentityError("OIDC user profile did not include an email.")
    subject = claims.get("sub")
    role = map_role(provider, claims, userinfo)
    permissions = permissions_for_role(role)
    name = userinfo.get("name") or claims.get("name") or ""
    first_name = userinfo.get("given_name") or (name.split(" ", 1)[0] if name else None)
    last_name = userinfo.get("family_name") or (name.split(" ", 1)[1] if " " in name else None)
    random_password_hash = hashlib.sha256(secrets.token_bytes(32)).hexdigest()

    with tenant_context(provider.tenant_id, required=True), engine.connect() as conn:
        existing = conn.execute(
            text("SELECT id FROM tenant_users WHERE tenant_id = :tenant_id AND lower(email) = lower(:email)"),
            {"tenant_id": provider.tenant_id, "email": email},
        ).fetchone()
        if existing:
            user_id = existing[0]
            conn.execute(
                text(
                    """
                    UPDATE tenant_users
                    SET first_name = COALESCE(:first_name, first_name),
                        last_name = COALESCE(:last_name, last_name),
                        role = :role,
                        permissions = :permissions,
                        email_verified = true,
                        status = 'active',
                        last_login_at = NOW(),
                        updated_at = NOW()
                    WHERE id = :user_id AND tenant_id = :tenant_id
                    """
                ),
                {
                    "user_id": user_id,
                    "tenant_id": provider.tenant_id,
                    "first_name": first_name,
                    "last_name": last_name,
                    "role": role,
                    "permissions": permissions,
                },
            )
        else:
            user_id = conn.execute(
                text(
                    """
                    INSERT INTO tenant_users (
                        tenant_id, first_name, last_name, email, password_hash,
                        role, permissions, email_verified, mfa_enabled, status, last_login_at
                    )
                    VALUES (
                        :tenant_id, :first_name, :last_name, :email, :password_hash,
                        :role, :permissions, true, false, 'active', NOW()
                    )
                    RETURNING id
                    """
                ),
                {
                    "tenant_id": provider.tenant_id,
                    "first_name": first_name,
                    "last_name": last_name,
                    "email": email,
                    "password_hash": random_password_hash,
                    "role": role,
                    "permissions": permissions,
                },
            ).scalar()
        conn.commit()
    return {
        "user_id": user_id,
        "tenant_id": provider.tenant_id,
        "email": email,
        "subject": subject,
        "role": role,
        "permissions": permissions,
    }


def store_provider_refresh_token(provider: OIDCProviderConfig, user_id: int, refresh_token: Optional[str], provider_subject: str = "") -> None:
    if not refresh_token:
        return
    encrypted = SecretManager().encrypt_for_database(refresh_token)
    with tenant_context(provider.tenant_id, required=True), engine.connect() as conn:
        conn.execute(
            text(
                """
                INSERT INTO oidc_user_sessions (
                    tenant_id, provider_id, user_id, provider_subject,
                    encrypted_provider_refresh_token, token_version, revoked_at
                )
                VALUES (
                    :tenant_id, :provider_id, :user_id, :provider_subject,
                    :encrypted_refresh_token, 1, NULL
                )
                ON CONFLICT (provider_id, user_id) DO UPDATE SET
                    encrypted_provider_refresh_token = EXCLUDED.encrypted_provider_refresh_token,
                    token_version = oidc_user_sessions.token_version + 1,
                    revoked_at = NULL,
                    updated_at = NOW()
                """
            ),
            {
                "tenant_id": provider.tenant_id,
                "provider_id": provider.id,
                "user_id": user_id,
                "provider_subject": provider_subject,
                "encrypted_refresh_token": encrypted,
            },
        )
        conn.commit()


def complete_oidc_callback(state: str, code: str) -> Dict[str, Any]:
    state_record = _load_state(state)
    provider = get_provider_config(state_record["tenant_id"], state_record["provider_id"])
    token_response = exchange_authorization_code(provider, code, state_record["code_verifier"])
    claims = validate_id_token(token_response["id_token"], provider, nonce=state_record["nonce"])
    userinfo = fetch_userinfo(provider, token_response.get("access_token"))
    profile = upsert_oidc_user(provider, claims, userinfo)
    store_provider_refresh_token(provider, profile["user_id"], token_response.get("refresh_token"), claims.get("sub", ""))
    _mark_state_used(state_record["state_hash"], provider.tenant_id)
    return {
        "profile": profile,
        "claims": claims,
        "provider": {
            "id": provider.id,
            "type": provider.provider_type,
            "display_name": provider.display_name,
        },
        "provider_refresh_token_stored": bool(token_response.get("refresh_token")),
    }


def public_jwks() -> Dict[str, Any]:
    raw = os.getenv("AUTHCLAW_PUBLIC_JWKS")
    if raw:
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise EnterpriseIdentityError("AUTHCLAW_PUBLIC_JWKS is not valid JSON.") from exc

    secret = os.getenv("AUTHCLAW_JWT_SECRET") or os.getenv("JWT_SECRET") or ""
    if not secret:
        return {"keys": []}
    kid = hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]
    return {
        "keys": [
            {
                "kty": "oct",
                "use": "sig",
                "alg": "HS256",
                "kid": kid,
                "status": "legacy-local-session-key-not-public",
            }
        ]
    }


def revoke_authclaw_refresh_token(refresh_token: str) -> bool:
    from main import decode_jwt

    payload = decode_jwt(refresh_token)
    if not payload or not payload.get("jti") or not payload.get("tenant_id"):
        return False
    with tenant_context(payload["tenant_id"], required=True), engine.connect() as conn:
        result = conn.execute(
            text(
                """
                UPDATE auth_refresh_tokens
                SET revoked_at = NOW()
                WHERE jti = :jti
                  AND tenant_id = :tenant_id
                  AND revoked_at IS NULL
                """
            ),
            {"jti": payload["jti"], "tenant_id": payload["tenant_id"]},
        )
        conn.commit()
    return bool(result.rowcount)


def security_posture() -> Dict[str, Any]:
    env = os.getenv("AUTHCLAW_ENV", "development").lower()
    secret_backend = SecretManager().backend
    production = env in {"production", "prod"}
    return {
        "environment": env,
        "production": production,
        "secret_backend": secret_backend,
        "oidc_provider_types": sorted(SUPPORTED_PROVIDER_TYPES),
        "local_bypasses_disabled_in_production": production,
        "https_enforcement": production or os.getenv("AUTHCLAW_ENFORCE_HTTPS", "").lower() in {"1", "true", "yes", "on"},
        "jwks_cache_ttl_seconds": JWKS_CACHE_TTL_SECONDS,
        "jwks_stale_fallback_seconds": JWKS_STALE_TTL_SECONDS,
    }

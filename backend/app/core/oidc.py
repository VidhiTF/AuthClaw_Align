"""OIDC/SSO configuration hooks.

AuthClaw still authenticates API requests with tenant API keys. This module
exposes production-safe OIDC metadata so console login can be extended to an
enterprise IdP without scattering environment parsing through endpoints.
"""

from __future__ import annotations

import os
from urllib.parse import urlencode


def oidc_enabled() -> bool:
    return bool(os.getenv("OIDC_ISSUER_URL") and os.getenv("OIDC_CLIENT_ID"))


def oidc_config() -> dict[str, object]:
    issuer = os.getenv("OIDC_ISSUER_URL", "").rstrip("/")
    client_id = os.getenv("OIDC_CLIENT_ID", "")
    redirect_uri = os.getenv("OIDC_REDIRECT_URI", "")
    scopes = os.getenv("OIDC_SCOPES", "openid email profile").split()
    authorization_endpoint = os.getenv("OIDC_AUTHORIZATION_ENDPOINT", f"{issuer}/authorize" if issuer else "")
    token_endpoint = os.getenv("OIDC_TOKEN_ENDPOINT", f"{issuer}/token" if issuer else "")
    jwks_uri = os.getenv("OIDC_JWKS_URI", f"{issuer}/.well-known/jwks.json" if issuer else "")
    auth_url = ""
    if oidc_enabled() and authorization_endpoint and redirect_uri:
        auth_url = authorization_endpoint + "?" + urlencode(
            {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": " ".join(scopes),
            }
        )
    return {
        "enabled": oidc_enabled(),
        "issuer": issuer,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scopes": scopes,
        "authorization_endpoint": authorization_endpoint,
        "token_endpoint": token_endpoint,
        "jwks_uri": jwks_uri,
        "authorization_url": auth_url,
    }

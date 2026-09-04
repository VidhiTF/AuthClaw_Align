"""Server-owned, single-use OIDC transactions and narrowly scoped BFF authentication."""

import hashlib
import hmac
import json
import os
import re
import time

import redis
from fastapi import HTTPException, Request
from starlette.concurrency import run_in_threadpool

LIFETIME_SECONDS = 600
SCOPES = {"/v1/auth/oidc/start", "/v1/auth/oidc/callback"}
BINDING_FIELDS = (
    "tenant_id",
    "provider",
    "issuer",
    "client_id",
    "redirect_uri",
    "token_endpoint",
    "jwks_uri",
)


def transaction_key(identifier: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", identifier):
        raise HTTPException(400, "Invalid OIDC transaction")
    return f"authclaw:oidc:v2:{{{identifier}}}"


def register(client, identifier: str, record: dict) -> None:
    try:
        accepted = client.set(
            transaction_key(identifier),
            json.dumps(record),
            nx=True,
            ex=LIFETIME_SECONDS,
        )
    except redis.RedisError:
        raise HTTPException(503, "OIDC transaction service unavailable") from None
    if not accepted:
        raise HTTPException(400, "Invalid OIDC transaction")


def consume(client, identifier: str) -> dict:
    try:
        # GETDEL is a single atomic command. Never retry an ambiguous outcome.
        value = client.getdel(transaction_key(identifier))
    except redis.RedisError:
        raise HTTPException(503, "OIDC transaction service unavailable") from None
    try:
        record = json.loads(value) if value else None
        age = time.time() - record["created_at"] if isinstance(record, dict) else -1
        if not 0 <= age < LIFETIME_SECONDS:
            raise ValueError("expired")
        return record
    except (ValueError, TypeError, KeyError):
        raise HTTPException(400, "Invalid OIDC transaction") from None


def binding(tenant, config) -> dict:
    def get(name):
        return (
            config.get(name)
            if isinstance(config, dict)
            else getattr(config, name, None)
        )

    issuer = get("issuer")
    return {
        "tenant_id": str(tenant.id),
        "provider": get("source") or "tenant",
        "issuer": issuer,
        "client_id": get("client_id"),
        "redirect_uri": get("redirect_uri"),
        "token_endpoint": get("token_endpoint") or f"{issuer.rstrip('/')}/token",
        "jwks_uri": get("jwks_uri") or f"{issuer.rstrip('/')}/.well-known/jwks.json",
    }


def validate_binding(record: dict, current: dict) -> None:
    if any(
        not record.get(key) or record[key] != current.get(key) for key in BINDING_FIELDS
    ):
        raise HTTPException(400, "OIDC configuration changed; restart login")


async def authenticate_bff(request: Request) -> None:
    path = request.url.path.removeprefix("/api")
    if request.method != "POST" or path not in SCOPES:
        raise HTTPException(401, "Invalid OIDC service authentication")
    secret = os.getenv("OIDC_BFF_EXCHANGE_SECRET", "")
    if len(secret) < 32:
        raise HTTPException(503, "OIDC service authentication unavailable")
    contexts = request.headers.getlist("x-authclaw-oidc-context")
    signatures = request.headers.getlist("x-authclaw-oidc-signature")
    invalid = HTTPException(401, "Invalid OIDC service authentication")
    if len(contexts) != 1 or len(signatures) != 1:
        raise invalid
    context, signature = contexts[0], signatures[0]
    if not re.fullmatch(r"[0-9]{10};[0-9a-f]{32}", context) or not re.fullmatch(
        r"[0-9a-f]{64}", signature
    ):
        raise invalid
    timestamp, nonce = context.split(";")
    if abs(time.time() - int(timestamp)) > 30:
        raise invalid
    body = await request.body()
    if len(body) > 65536:
        raise invalid
    material = f"authclaw:oidc-service:v1\nPOST\n{path}\n{context}\n{hashlib.sha256(body).hexdigest()}"
    expected = hmac.new(secret.encode(), material.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise invalid
    from app.api.v1.endpoints.onboarding import _get_redis

    try:
        accepted = await run_in_threadpool(
            _get_redis().set,
            f"authclaw:oidc-service:v1:{{{nonce}}}",
            "1",
            nx=True,
            ex=61,
        )
    except redis.RedisError:
        raise HTTPException(503, "OIDC service authentication unavailable") from None
    if not accepted:
        raise invalid

"""Path/body-bound, short-lived console client identity for public auth routes."""

import hashlib
import hmac
import ipaddress
import os
import re
import time

import redis
from fastapi import HTTPException, Request
from starlette.concurrency import run_in_threadpool

from app.services import event_backbone

DOMAIN = "authclaw:bff-client-ip:v1\nPOST\n/v1/auth/login\n"


def validate_bff_client_ip_config() -> None:
    enabled = os.getenv("AUTHCLAW_BFF_CLIENT_IP_ENABLED", "false")
    if enabled not in {"true", "false"}:
        raise ValueError("AUTHCLAW_BFF_CLIENT_IP_ENABLED must be true or false")
    if enabled == "true" and len(os.getenv("BFF_CLIENT_IP_SECRET", "")) < 32:
        raise ValueError("BFF_CLIENT_IP_SECRET must contain at least 32 characters")


async def authenticate_bff_client_ip(request: Request) -> None:
    contexts = request.headers.getlist("x-authclaw-client-context")
    signatures = request.headers.getlist("x-authclaw-client-signature")
    if not contexts and not signatures:
        return  # Direct API callers retain trusted-proxy/socket identity.
    invalid = HTTPException(400, "Invalid client context")
    if (
        os.getenv("AUTHCLAW_BFF_CLIENT_IP_ENABLED", "false") != "true"
        or len(contexts) != 1
        or len(signatures) != 1
    ):
        raise invalid
    context, signature = contexts[0], signatures[0]
    if len(context) > 200 or not re.fullmatch(r"[0-9a-f]{64}", signature):
        raise invalid
    body = await request.body()
    if len(body) > 65536:
        raise invalid
    path = request.url.path.removeprefix("/api") if request.url.path.startswith("/api/v1/") else request.url.path
    material = f"authclaw:bff-client-ip:v1\n{request.method}\n{path}\n{context}\n" + hashlib.sha256(body).hexdigest()
    secret = os.getenv("BFF_CLIENT_IP_SECRET", "")
    if len(secret) < 32:
        raise HTTPException(503, "Client identity verification unavailable")
    expected = hmac.new(secret.encode(), material.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        event_backbone.increment_metric("bff_client_identity_rejected_total")
        raise invalid
    try:
        raw_ip, timestamp, nonce = context.split(";")
        if "%" in raw_ip or not re.fullmatch(r"[0-9a-f]{32}", nonce):
            raise ValueError("invalid context")
        address = ipaddress.ip_address(raw_ip)
        if abs(time.time() - int(timestamp)) > 30:
            raise ValueError("expired context")
    except ValueError:
        raise invalid from None
    from app.api.v1.endpoints.onboarding import _get_redis

    try:
        accepted = await run_in_threadpool(
            _get_redis().set, f"authclaw:bff-ip:v1:{{{nonce}}}", "1", nx=True, ex=61
        )
    except redis.RedisError:
        event_backbone.increment_metric("bff_client_identity_unavailable_total")
        raise HTTPException(503, "Client identity verification unavailable") from None
    if not accepted:
        raise invalid
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    peer = request.scope.get("client")
    request.scope["client"] = (address.compressed, peer[1] if peer else 0)
    event_backbone.increment_metric("bff_client_identity_verified_total")

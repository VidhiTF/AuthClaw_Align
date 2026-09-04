import hashlib
import hmac
import time
import os
import uuid

import pytest
import redis
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from app.core.bff_client_ip import DOMAIN, authenticate_bff_client_ip
from app.api.v1.endpoints import onboarding

SECRET = "synthetic-test-key-with-at-least-32-characters"
BODY = b'{"email":"test@example.com","password":"synthetic"}'


def signed(ip="198.51.100.9", age=0, body=BODY, nonce="a" * 32):
    context = f"{ip};{int(time.time()) - age};{nonce}"
    material = DOMAIN + context + "\n" + hashlib.sha256(body).hexdigest()
    return {
        "x-authclaw-client-context": context,
        "x-authclaw-client-signature": hmac.new(
            SECRET.encode(), material.encode(), hashlib.sha256
        ).hexdigest(),
    }


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("AUTHCLAW_BFF_CLIENT_IP_ENABLED", "true")
    monkeypatch.setenv("BFF_CLIENT_IP_SECRET", SECRET)
    nonces = set()

    class Store:
        def set(self, key, value, *, nx, ex):
            assert nx and ex == 61
            if key in nonces:
                return False
            nonces.add(key)
            return True

    monkeypatch.setattr(onboarding, "_get_redis", lambda: Store())
    app = FastAPI()

    @app.post("/v1/auth/login", dependencies=[Depends(authenticate_bff_client_ip)])
    @app.post("/api/v1/auth/login", dependencies=[Depends(authenticate_bff_client_ip)])
    def login(request: Request):
        return {"ip": request.client.host}

    return TestClient(app)


def test_signed_clients_are_distinct_and_nonce_is_one_time(client):
    headers = signed()
    first = client.post("/v1/auth/login", headers=headers, content=BODY)
    assert first.json()["ip"] == "198.51.100.9"
    assert (
        client.post("/v1/auth/login", headers=headers, content=BODY).status_code == 400
    )
    second = client.post(
        "/api/v1/auth/login",
        headers=signed("203.0.113.1", nonce="b" * 32),
        content=BODY,
    )
    assert second.json()["ip"] == "203.0.113.1"


@pytest.mark.parametrize(
    "change", ["signature", "body", "expired", "future", "scope", "duplicate"]
)
def test_invalid_identity_is_rejected(client, change):
    headers = signed(
        age=60 if change == "expired" else -60 if change == "future" else 0,
        ip="fe80::1%eth0" if change == "scope" else "198.51.100.9",
    )
    if change == "signature":
        headers["x-authclaw-client-signature"] = "0" * 64
    if change == "duplicate":
        headers = list(headers.items()) + [("x-authclaw-client-context", "forged")]
    response = client.post(
        "/v1/auth/login", headers=headers, content=b"{}" if change == "body" else BODY
    )
    assert response.status_code == 400


def test_direct_request_does_not_trust_unsigned_context(client):
    response = client.post(
        "/v1/auth/login", headers={"x-forwarded-for": "198.51.100.9"}, content=BODY
    )
    assert response.json()["ip"] == "testclient"


def test_nonce_store_failure_blocks_login(client, monkeypatch):
    def unavailable():
        raise redis.TimeoutError("lost response")

    monkeypatch.setattr(onboarding, "_get_redis", unavailable)
    assert (
        client.post("/v1/auth/login", headers=signed(), content=BODY).status_code == 503
    )


def test_signed_login_limits_one_browser_without_collapsing_another(monkeypatch):
    from app.api.v1.endpoints import auth
    from app.services.abuse_controls import versioned_limit_key

    if not os.getenv("REDIS_URL"):
        pytest.skip("real Redis is not configured")
    store = redis.Redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
    monkeypatch.setattr(onboarding, "_get_redis", lambda: store)
    monkeypatch.setenv("AUTHCLAW_BFF_CLIENT_IP_ENABLED", "true")
    monkeypatch.setenv("BFF_CLIENT_IP_SECRET", SECRET)
    monkeypatch.setattr(auth, "LOGIN_IP_ATTEMPTS_PER_MINUTE", 2)
    monkeypatch.setattr(auth, "LOGIN_ACCOUNT_ATTEMPTS_PER_15_MINUTES", 100)
    app = FastAPI()
    email = f"{uuid.uuid4().hex}@example.com"
    ips = ["198.51.100.211", "198.51.100.212"]
    keys = [
        versioned_limit_key(f"auth:login:ip:{auth._rate_limit_hash(ip)}") for ip in ips
    ]
    keys.append(
        versioned_limit_key(f"auth:login:account:{auth._rate_limit_hash(email)}")
    )

    @app.post("/v1/auth/login", dependencies=[Depends(authenticate_bff_client_ip)])
    def login(request: Request):
        auth._enforce_password_login_rate_limit(email, request)
        return {"ip": request.client.host}

    store.delete(*keys)
    try:
        with TestClient(app) as browser:

            def attempt(ip):
                return browser.post(
                    "/v1/auth/login",
                    content=BODY,
                    headers=signed(ip, nonce=uuid.uuid4().hex),
                )

            assert [attempt(ips[0]).status_code for _ in range(3)] == [200, 200, 429]
            assert attempt(ips[1]).status_code == 200
    finally:
        store.delete(*keys)
        store.close()

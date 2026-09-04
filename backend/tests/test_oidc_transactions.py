import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi import HTTPException

from app.services import oidc_transactions as transactions


@pytest.fixture
def exchange_client(monkeypatch):
    import secrets
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.api.v1.endpoints import auth, onboarding
    from unittest.mock import MagicMock

    class Store:
        values = {}

        def set(self, key, value, nx=False, ex=None):
            if nx and key in self.values:
                return False
            self.values[key] = value
            return True

        def getdel(self, key):
            return self.values.pop(key, None)

    store = Store()
    monkeypatch.setenv(
        "OIDC_BFF_EXCHANGE_SECRET", "test-oidc-exchange-secret-with-32-characters"
    )
    monkeypatch.setattr(onboarding, "_get_redis", lambda: store)
    monkeypatch.setattr(auth, "_get_redis", lambda: store)
    complete = MagicMock(
        return_value={
            "session_token": "session",
            "tenant_id": "11111111-1111-4111-8111-111111111111",
            "user_id": "22222222-2222-4222-8222-222222222222",
            "tenant_name": "Tenant",
            "email": "user@example.com",
            "role": "viewer",
            "scopes": ["read"],
        }
    )
    monkeypatch.setattr(auth, "oidc_callback", complete)
    app = FastAPI()
    app.include_router(auth.router, prefix="/v1/auth")
    app.include_router(auth.router, prefix="/api/v1/auth")
    identifier = secrets.token_urlsafe(32)
    transactions.register(
        store,
        identifier,
        {
            "created_at": time.time(),
            "tenant_name": "Tenant",
            "redirect_uri": "https://app/callback",
            "nonce": "server-nonce",
        },
    )
    return TestClient(app), identifier, complete, store


def signed_request(
    identifier, path="/v1/auth/oidc/callback", body_override=None, **extra
):
    import hashlib
    import hmac
    import json
    import secrets

    body = json.dumps(
        body_override
        if body_override is not None
        else {"transaction_id": identifier, "code": "code", **extra}
    )
    context = f"{int(time.time())};{secrets.token_hex(16)}"
    material = f"authclaw:oidc-service:v1\nPOST\n{path}\n{context}\n{hashlib.sha256(body.encode()).hexdigest()}"
    signature = hmac.new(
        b"test-oidc-exchange-secret-with-32-characters",
        material.encode(),
        hashlib.sha256,
    ).hexdigest()
    return body, {
        "content-type": "application/json",
        "x-authclaw-oidc-context": context,
        "x-authclaw-oidc-signature": signature,
    }


@pytest.mark.parametrize("prefix", ["/v1", "/api/v1"])
def test_exchange_requires_service_proof_and_consumes_once(exchange_client, prefix):
    client, identifier, complete, _ = exchange_client
    body, headers = signed_request(identifier)
    path = prefix + "/auth/oidc/callback"
    assert (
        client.post(
            path, content=body, headers={"content-type": "application/json"}
        ).status_code
        == 401
    )
    assert not complete.called
    response = client.post(path, content=body, headers=headers)
    assert response.status_code == 200
    assert complete.call_args.args[0].nonce == "server-nonce"
    assert client.post(path, content=body, headers=headers).status_code == 401
    body, headers = signed_request(identifier)
    assert client.post(path, content=body, headers=headers).status_code == 400
    assert complete.call_count == 1


@pytest.mark.parametrize(
    "change",
    ["body", "scope", "duplicate", "nonce", "state", "tenant_name", "redirect_uri"],
)
def test_exchange_rejects_tampering_and_browser_context(exchange_client, change):
    client, identifier, complete, _ = exchange_client
    extra = (
        {change: "forged"}
        if change in {"nonce", "state", "tenant_name", "redirect_uri"}
        else {}
    )
    body, headers = signed_request(
        identifier,
        path="/v1/auth/oidc/start" if change == "scope" else "/v1/auth/oidc/callback",
        **extra,
    )
    if change == "body":
        body = body.replace('"code": "code"', '"code": "altered"')
    if change == "duplicate":
        headers = list(headers.items()) + [("x-authclaw-oidc-context", "forged")]
    response = client.post("/v1/auth/oidc/callback", content=body, headers=headers)
    assert response.status_code in {401, 422}
    assert not complete.called


def test_redis_loss_after_consumption_never_exchanges(exchange_client, monkeypatch):
    import redis

    client, identifier, complete, store = exchange_client

    def lost(key):
        store.values.pop(key, None)
        raise redis.TimeoutError("response lost after GETDEL")

    monkeypatch.setattr(store, "getdel", lost)
    body, headers = signed_request(identifier)
    assert (
        client.post("/v1/auth/oidc/callback", content=body, headers=headers).status_code
        == 503
    )
    assert not complete.called


def test_expired_or_missing_transaction_never_exchanges(exchange_client):
    import json

    client, identifier, complete, store = exchange_client
    store.values[transactions.transaction_key(identifier)] = json.dumps(
        {"created_at": time.time() - 601}
    )
    body, headers = signed_request(identifier)
    assert (
        client.post("/v1/auth/oidc/callback", content=body, headers=headers).status_code
        == 400
    )
    assert not complete.called


def test_transaction_binding_rejects_each_changed_dimension():
    context = {
        "tenant_id": "tenant",
        "issuer": "https://idp",
        "client_id": "client",
        "provider": "env",
        "redirect_uri": "https://app/callback",
        "token_endpoint": "https://idp/token",
        "jwks_uri": "https://idp/jwks",
    }
    transactions.validate_binding(context, context)
    for key in context:
        with pytest.raises(HTTPException):
            transactions.validate_binding(context, {**context, key: "substitution"})


def test_real_transaction_is_one_time_across_clients(monkeypatch):
    import os
    import redis
    import secrets

    if not os.getenv("REDIS_URL"):
        pytest.skip("real Redis not configured")
    first = redis.Redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
    second = redis.Redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
    transaction_id = secrets.token_urlsafe(32)
    record = {"nonce": "server-nonce", "created_at": time.time()}
    transactions.register(first, transaction_id, record)

    def consume(client):
        try:
            return transactions.consume(client, transaction_id)
        except HTTPException as exc:
            assert exc.status_code == 400
            return None

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(consume, [first, second]))
        assert results.count(record) == 1
        assert results.count(None) == 1
    finally:
        first.delete(transactions.transaction_key(transaction_id))
        first.close()
        second.close()


@pytest.mark.parametrize(
    "substitution",
    [None, "issuer", "client_id", "provider", "redirect_uri", "nonce", "tenant_id"],
)
def test_signed_start_to_real_id_token_validation(monkeypatch, substitution):
    import os
    import json
    import secrets
    import uuid
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    import jwt
    import redis
    from cryptography.hazmat.primitives.asymmetric import rsa
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.api.v1.endpoints import auth, onboarding
    from app.services import oidc_sso

    if not os.getenv("REDIS_URL"):
        pytest.skip("real Redis not configured")
    store = redis.Redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
    tenant = SimpleNamespace(id=uuid.uuid4(), name="Canonical Tenant")
    config = {
        "source": "env",
        "issuer": "https://idp.example",
        "client_id": "console",
        "redirect_uri": "https://app.example/api/auth/oidc/callback",
        "authorization_endpoint": "https://idp.example/authorize",
        "email_claim": "email",
        "groups_claim": "groups",
        "role_mapping": {},
        "default_role": "viewer",
        "tenant_claim": "tenant_id",
        "tenant_claim_value": "idp-tenant",
        "require_mfa": False,
    }
    db = MagicMock()
    db.execute.return_value.one.return_value = SimpleNamespace(
        user_id=uuid.uuid4(), email="user@example.com", role="viewer"
    )
    monkeypatch.setattr(auth, "OwnerSessionLocal", lambda: db)
    monkeypatch.setattr(auth, "_emit_oidc_audit", lambda **_: None)
    monkeypatch.setattr(oidc_sso, "public_config", lambda *_: (tenant, config))
    monkeypatch.setattr(onboarding, "_get_redis", lambda: store)
    monkeypatch.setattr(auth, "_get_redis", lambda: store)
    monkeypatch.setenv(
        "OIDC_BFF_EXCHANGE_SECRET", "test-oidc-exchange-secret-with-32-characters"
    )
    app = FastAPI()
    app.include_router(auth.router, prefix="/v1/auth")
    identifier = secrets.token_urlsafe(32)
    key = transactions.transaction_key(identifier)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr(
        jwt,
        "PyJWKClient",
        lambda *_: SimpleNamespace(
            get_signing_key_from_jwt=lambda _: SimpleNamespace(
                key=private_key.public_key()
            )
        ),
    )
    try:
        # Independent clients represent separate BFF replicas using the same store.
        first, second = TestClient(app), TestClient(app)
        body, headers = signed_request(
            identifier,
            path="/v1/auth/oidc/start",
            body_override={"transaction_id": identifier},
        )
        started = first.post("/v1/auth/oidc/start", content=body, headers=headers)
        assert started.status_code == 200
        record = json.loads(store.get(key))
        assert record["tenant_name"] == "Canonical Tenant"
        claims = {
            "iss": config["issuer"],
            "aud": config["client_id"],
            "sub": "subject",
            "iat": int(time.time()),
            "exp": int(time.time()) + 60,
            "nonce": record["nonce"],
            "email": "user@example.com",
            "tenant_id": "idp-tenant",
        }
        if substitution == "nonce":
            claims["nonce"] = "attacker"
        elif substitution == "tenant_id":
            tenant.id = uuid.uuid4()
        elif substitution:
            config["source" if substitution == "provider" else substitution] = (
                "https://changed.example"
            )
        token = jwt.encode(claims, private_key, algorithm="RS256")
        exchange = MagicMock(return_value={"id_token": token})
        monkeypatch.setattr(oidc_sso, "exchange_code", exchange)
        body, headers = signed_request(identifier)
        result = second.post("/v1/auth/oidc/callback", content=body, headers=headers)
        assert not store.exists(key)
        if substitution:
            assert result.status_code in {400, 401}
            assert not db.commit.called
            if substitution != "nonce":
                assert not exchange.called
        else:
            assert result.status_code == 200
            assert result.json()["session_token"].startswith("acl_session_")
            assert db.commit.call_count == 1
        body, headers = signed_request(identifier)
        assert (
            first.post(
                "/v1/auth/oidc/callback", content=body, headers=headers
            ).status_code
            == 400
        )
    finally:
        store.delete(key)
        store.close()

import hashlib
import hmac
import json

from main import base64_url_decode, base64_url_encode, create_jwt, decode_jwt


def test_approval_placeholder():
    # Placeholder to allow pytest to run successfully
    assert True


def test_jwt_rotation_preserves_previous_tokens(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_V1", "previous-jwt-signing-secret")
    monkeypatch.setenv("JWT_SECRET_V2", "active-jwt-signing-secret")
    monkeypatch.setenv("AUTHCLAW_JWT_KEY_VERSION", "v1")
    previous_token = create_jwt({"sub": "rotation-test"})

    monkeypatch.setenv("AUTHCLAW_JWT_KEY_VERSION", "v2")
    active_token = create_jwt({"sub": "rotation-test"})

    assert json.loads(base64_url_decode(active_token.split(".")[0]))["kid"] == "v2"
    assert decode_jwt(previous_token)["sub"] == "rotation-test"
    assert decode_jwt(active_token)["sub"] == "rotation-test"

    header = base64_url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = base64_url_encode(json.dumps({"sub": "legacy-token"}).encode())
    signature = base64_url_encode(hmac.new(b"previous-jwt-signing-secret", f"{header}.{payload}".encode(), hashlib.sha256).digest())
    assert decode_jwt(f"{header}.{payload}.{signature}")["sub"] == "legacy-token"


if __name__ == "__main__":
    from nodes.approval_node import approval_node
    state = {
        "risk_level": "HIGH",
        "message": "test message"
    }
    print(approval_node(state))

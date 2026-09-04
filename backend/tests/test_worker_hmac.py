import hashlib
import hmac

import pytest

from app.services import ephemeral_workers as workers


def test_worker_hash_is_independently_keyed_and_domain_separated(monkeypatch):
    monkeypatch.setenv("WORKER_TOKEN_HMAC_ACTIVE_VERSION", "v1")
    monkeypatch.setenv(
        "WORKER_TOKEN_HMAC_KEY_V1", "test-only-worker-hmac-key-material-32"
    )
    raw = "ewt.v1.abcdefgh." + "a" * 43
    expected = hmac.new(
        b"test-only-worker-hmac-key-material-32",
        b"authclaw:worker-token:v1\0v1\0" + raw.encode(),
        hashlib.sha256,
    ).hexdigest()
    assert workers.hash_worker_token(raw) == expected
    assert expected != hashlib.sha256(raw.encode()).hexdigest()
    monkeypatch.setenv(
        "WORKER_TOKEN_HMAC_KEY_V1", "different-worker-hmac-key-material-32"
    )
    assert workers.hash_worker_token(raw) != expected


@pytest.mark.parametrize(
    "raw",
    ["ewt_demo_secret", "", "ewt.v1.short.secret", "ewt.v999.abcdefgh." + "a" * 43],
)
def test_worker_hash_rejects_legacy_malformed_or_missing_key(raw, monkeypatch):
    monkeypatch.setenv(
        "WORKER_TOKEN_HMAC_KEY_V1", "test-only-worker-hmac-key-material-32"
    )
    with pytest.raises((ValueError, RuntimeError)):
        workers.hash_worker_token(raw)


def test_issuance_pause_precedes_database_access(monkeypatch):
    monkeypatch.setenv("WORKER_TOKEN_ISSUANCE_PAUSED", "true")
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as error:
        workers.issue_worker_token(
            None,
            tenant_id="ignored",
            connector="aws",
            action_id="s3.sync",
            purpose="scan",
            scopes=["aws:s3:read"],
        )
    assert error.value.status_code == 503


def test_retained_key_rotation_and_unknown_versions(monkeypatch):
    from app.core import worker_tokens

    monkeypatch.setenv("WORKER_TOKEN_HMAC_ACTIVE_VERSION", "v1")
    monkeypatch.setenv(
        "WORKER_TOKEN_HMAC_KEY_V1", "old-test-worker-hmac-key-material-32"
    )
    _, old = worker_tokens.generate()
    old_hash = worker_tokens.hash_token(old)
    monkeypatch.setenv("WORKER_TOKEN_HMAC_ACTIVE_VERSION", "v2")
    monkeypatch.setenv(
        "WORKER_TOKEN_HMAC_KEY_V2", "new-test-worker-hmac-key-material-32"
    )
    _, new = worker_tokens.generate()
    assert new.startswith("ewt.v2.")
    assert worker_tokens.hash_token(old) == old_hash
    assert worker_tokens.hash_token(new) != old_hash
    monkeypatch.delenv("WORKER_TOKEN_HMAC_KEY_V1")
    with pytest.raises(RuntimeError):
        worker_tokens.hash_token(old)

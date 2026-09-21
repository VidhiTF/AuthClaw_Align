from concurrent.futures import ThreadPoolExecutor
import os
import uuid
from types import SimpleNamespace

import pytest
import redis
from fastapi import HTTPException

from app.services import abuse_controls
from app.core.auth import MFAVerification


class FakeRedis:
    def __init__(self):
        self.values = {}
        self.ttls = {}
        self.calls = 0
        self.error = None

    def eval(self, script, number_of_keys, *args):
        self.calls += 1
        if self.error:
            raise self.error
        keys = args[:number_of_keys]
        argv = args[number_of_keys:]
        if script == abuse_controls.ATOMIC_INCREMENT_LUA:
            key = keys[0]
            self.values[key] = self.values.get(key, 0) + 1
            self.ttls.setdefault(key, int(argv[0]))
            return [self.values[key], self.ttls[key]]
        if script == abuse_controls.MFA_CHECK_LUA:
            return self.ttls.get(keys[0], -2)
        if script == abuse_controls.MFA_RESET_LUA:
            remaining = self.ttls.get(keys[2], -2)
            if remaining > 0:
                return remaining
            removed = 0
            for key in keys:
                removed += int(key in self.values or key in self.ttls)
                self.values.pop(key, None)
                self.ttls.pop(key, None)
            return 0
        if script == abuse_controls.MFA_FAILURE_LUA:
            attempts, level, cooldown = keys
            threshold = int(argv[1])
            self.values[attempts] = self.values.get(attempts, 0) + 1
            self.ttls.setdefault(attempts, int(argv[0]))
            if self.values[attempts] < threshold:
                return [self.values[attempts], 0, 0]
            failures = self.values.pop(attempts)
            self.ttls.pop(attempts, None)
            self.values[level] = self.values.get(level, 0) + 1
            effective_level = self.values[level] if int(argv[5]) else 1
            cooldown_ms = min(int(argv[2]) * (2 ** (effective_level - 1)), int(argv[3]))
            self.values[cooldown] = 1
            self.ttls[cooldown] = cooldown_ms
            return [failures, cooldown_ms, self.values[level]]
        raise AssertionError("unexpected script")


@pytest.fixture(autouse=True)
def quiet_audit(monkeypatch):
    monkeypatch.setattr(
        abuse_controls.event_backbone, "publish_audit_event", lambda *_args: None
    )


def test_atomic_increment_uses_one_call_and_preserves_first_ttl():
    client = FakeRedis()
    first = abuse_controls.atomic_increment(client, "login:user", 60)
    second = abuse_controls.atomic_increment(client, "login:user", 60)
    assert first == (1, 60_000)
    assert second == (2, 60_000)
    assert client.calls == 2
    assert "v2:{" in abuse_controls.versioned_limit_key("login:user")


def test_atomic_increment_does_not_retry_ambiguous_timeout():
    client = FakeRedis()
    client.error = redis.TimeoutError("response lost")
    with pytest.raises(redis.TimeoutError):
        abuse_controls.atomic_increment(client, "login:user", 60)
    assert client.calls == 1


def test_atomic_increment_concurrency_leaves_positive_ttl():
    redis_url = os.getenv("REDIS_URL")
    if not redis_url:
        pytest.skip("real Redis is not configured")
    client = redis.Redis.from_url(redis_url, decode_responses=True)
    logical_key = f"release4:concurrency:{os.getpid()}"
    key = abuse_controls.versioned_limit_key(logical_key)
    client.delete(key)
    try:
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(
                pool.map(
                    lambda _index: abuse_controls.atomic_increment(
                        client, logical_key, 30
                    ),
                    range(64),
                )
            )
        assert sorted(count for count, _ttl in results) == list(range(1, 65))
        assert client.pttl(key) > 0
    finally:
        client.delete(key)


def test_mfa_isolated_by_user_and_operation_and_success_resets(monkeypatch):
    client = FakeRedis()
    user = SimpleNamespace(id="user-1")
    monkeypatch.setattr(
        "app.core.auth.verify_mfa_code_result",
        lambda _user, code: MFAVerification(code == "valid", method="totp" if code == "valid" else None),
    )
    for _ in range(2):
        assert not abuse_controls.verify_mfa_challenge(
            client, user, "bad", tenant_id="tenant-1", operation="mfa_disable"
        )
    assert abuse_controls.verify_mfa_challenge(
        client, user, "valid", tenant_id="tenant-1", operation="gateway_approval"
    )
    disable_keys = abuse_controls._mfa_keys("tenant-1", "user-1", "mfa_disable")
    approval_keys = abuse_controls._mfa_keys("tenant-1", "user-1", "gateway_approval")
    assert client.values.get(disable_keys[0]) == 2
    assert all(key not in client.values for key in approval_keys)


def test_success_admitted_before_cooldown_cannot_clear_new_cooldown(monkeypatch):
    user = SimpleNamespace(id="user-1")

    class CooldownDuringVerification(FakeRedis):
        def eval(self, script, number_of_keys, *args):
            if script == abuse_controls.MFA_RESET_LUA:
                cooldown_key = args[2]
                self.values[cooldown_key] = 1
                self.ttls[cooldown_key] = 2_000
            return super().eval(script, number_of_keys, *args)

    client = CooldownDuringVerification()
    monkeypatch.setattr(
        "app.core.auth.verify_mfa_code_result",
        lambda *_args: MFAVerification(True, method="totp"),
    )

    with pytest.raises(HTTPException) as blocked:
        abuse_controls.verify_mfa_challenge(
            client, user, "valid", tenant_id="tenant-1", operation="gateway_approval"
        )

    assert blocked.value.status_code == 429
    cooldown_key = abuse_controls._mfa_keys(
        "tenant-1", "user-1", "gateway_approval"
    )[2]
    assert client.ttls[cooldown_key] == 2_000


def test_mfa_cooldown_escalates_but_is_bounded(monkeypatch):
    client = FakeRedis()
    user = SimpleNamespace(id="user-1")
    monkeypatch.setattr(
        "app.core.auth.verify_mfa_code_result",
        lambda *_args: MFAVerification(False),
    )
    monkeypatch.setenv("MFA_FAILURE_THRESHOLD", "2")
    monkeypatch.setenv("MFA_BASE_COOLDOWN_SECONDS", "2")
    monkeypatch.setenv("MFA_MAX_COOLDOWN_SECONDS", "4")

    assert not abuse_controls.verify_mfa_challenge(
        client, user, "bad", tenant_id="tenant-1", operation="destructive_remediation"
    )
    with pytest.raises(HTTPException) as first:
        abuse_controls.verify_mfa_challenge(
            client,
            user,
            "bad",
            tenant_id="tenant-1",
            operation="destructive_remediation",
        )
    assert first.value.status_code == 429
    keys = abuse_controls._mfa_keys("tenant-1", "user-1", "destructive_remediation")
    assert client.ttls[keys[2]] == 2_000

    client.ttls.pop(keys[2])
    client.values.pop(keys[2], None)
    assert not abuse_controls.verify_mfa_challenge(
        client, user, "bad", tenant_id="tenant-1", operation="destructive_remediation"
    )
    with pytest.raises(HTTPException):
        abuse_controls.verify_mfa_challenge(
            client,
            user,
            "bad",
            tenant_id="tenant-1",
            operation="destructive_remediation",
        )
    assert client.ttls[keys[2]] == 4_000


def test_mfa_redis_failure_is_retryable_and_never_verifies(monkeypatch):
    client = FakeRedis()
    client.error = redis.ConnectionError("down")

    def verify(*_args):
        pytest.fail("verification must not run without attempt state")

    monkeypatch.setattr("app.core.auth.verify_mfa_code_result", verify)
    with pytest.raises(HTTPException) as exc:
        abuse_controls.verify_mfa_challenge(
            client,
            SimpleNamespace(id="user-1"),
            "valid",
            tenant_id="tenant-1",
            operation="mfa_disable",
        )
    assert exc.value.status_code == 503
    assert exc.value.headers == {"Retry-After": "5"}
    assert client.calls == 1


def test_replayed_totp_is_rejected_counted_and_audited(monkeypatch):
    client = FakeRedis()
    user = SimpleNamespace(id="user-1")
    actions = []
    monkeypatch.setattr(
        "app.core.auth.verify_mfa_code_result",
        lambda *_args: MFAVerification(False, method="totp", reason="replay"),
    )
    monkeypatch.setattr(
        abuse_controls,
        "_audit",
        lambda _tenant, _user, _operation, action, _request: actions.append(action),
    )

    assert abuse_controls.verify_mfa_challenge(
        client, user, "123456", tenant_id="tenant-1", operation="gateway_approval"
    ) is False

    attempts_key = abuse_controls._mfa_keys(
        "tenant-1", "user-1", "gateway_approval"
    )[0]
    assert client.values[attempts_key] == 1
    assert "replay_rejected" in actions


@pytest.fixture
def real_redis():
    url = os.getenv("REDIS_URL")
    if not url:
        pytest.skip("real Redis is not configured")
    client = redis.Redis.from_url(url, decode_responses=True)
    client.ping()
    yield client
    client.close()


def test_real_mfa_scripts_expire_escalate_and_reset(real_redis, monkeypatch):
    user = SimpleNamespace(id=str(uuid.uuid4()))
    monkeypatch.setenv("MFA_FAILURE_THRESHOLD", "2")
    monkeypatch.setenv("MFA_BASE_COOLDOWN_SECONDS", "1")
    monkeypatch.setenv("MFA_MAX_COOLDOWN_SECONDS", "2")
    monkeypatch.setattr(
        "app.core.auth.verify_mfa_code_result",
        lambda _user, code: MFAVerification(code == "valid", method="totp" if code == "valid" else None),
    )
    keys = abuse_controls._mfa_keys("tenant", user.id, "mfa_disable")

    def verify(code):
        return abuse_controls.verify_mfa_challenge(
            real_redis, user, code, tenant_id="tenant", operation="mfa_disable"
        )

    try:
        assert verify("bad") is False
        assert real_redis.pttl(keys[0]) > 0
        for expected_seconds in [1, 2, 2]:
            with pytest.raises(HTTPException) as cooldown:
                verify("bad")
            assert cooldown.value.status_code == 429
            assert 0 < real_redis.pttl(keys[2]) <= expected_seconds * 1000
            # Exercise Redis expiration without a wall-clock sleep.
            real_redis.pexpire(keys[2], 0)
            assert verify("bad") is False
        assert verify("valid") is True
        assert all(not real_redis.exists(key) for key in keys)
        assert verify("bad") is False
        real_redis.pexpire(keys[0], 0)
        assert verify("bad") is False
        assert real_redis.get(keys[0]) == "1"
    finally:
        real_redis.delete(*keys)


@pytest.mark.parametrize("executed", [False, True])
def test_real_counter_response_loss_is_never_replayed(real_redis, executed):
    logical = "response-loss:" + str(uuid.uuid4())
    key = abuse_controls.versioned_limit_key(logical)

    class LostResponse:
        calls = 0

        def eval(self, *args):
            self.calls += 1
            if executed:
                real_redis.eval(*args)
            raise redis.TimeoutError("simulated loss before/after server execution")

    connection = LostResponse()
    try:
        with pytest.raises(redis.TimeoutError):
            abuse_controls.atomic_increment(connection, logical, 60)
        assert connection.calls == 1
        assert real_redis.get(key) == ("1" if executed else None)
        if executed:
            assert real_redis.pttl(key) > 0
    finally:
        real_redis.delete(key)

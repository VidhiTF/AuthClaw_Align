"""Atomic Redis-backed request and MFA abuse controls."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from dataclasses import dataclass

import redis
from fastapi import HTTPException, status

from app.services import event_backbone

logger = logging.getLogger("authclaw.abuse_controls")

ATOMIC_INCREMENT_LUA = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return {count, redis.call('PTTL', KEYS[1])}
"""

MFA_CHECK_LUA = "return redis.call('PTTL', KEYS[1])"

MFA_FAILURE_LUA = """
local remaining = redis.call('PTTL', KEYS[3])
if remaining == -1 then return redis.error_reply('invalid cooldown TTL') end
if remaining > 0 then return {0, remaining, 0} end
local failures = redis.call('INCR', KEYS[1])
if failures == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
if failures < tonumber(ARGV[2]) then return {failures, 0, 0} end
redis.call('DEL', KEYS[1])
local level = math.min(tonumber(redis.call('GET', KEYS[2]) or '0') + 1, 13)
redis.call('SET', KEYS[2], level, 'PX', ARGV[5])
if ARGV[6] ~= '1' then level = 1 end
local cooldown = tonumber(ARGV[3]) * (2 ^ (level - 1))
if cooldown > tonumber(ARGV[4]) then cooldown = tonumber(ARGV[4]) end
redis.call('SET', KEYS[3], '1', 'PX', cooldown)
return {failures, cooldown, level}
"""

MFA_RESET_LUA = """
local remaining = redis.call('PTTL', KEYS[3])
if remaining == -1 then return redis.error_reply('invalid cooldown TTL') end
if remaining > 0 then return remaining end
redis.call('DEL', KEYS[1], KEYS[2], KEYS[3])
return 0
"""


@dataclass(frozen=True)
class MFAControlConfig:
    threshold: int
    window_ms: int
    base_cooldown_ms: int
    max_cooldown_ms: int
    escalation_ttl_ms: int
    escalating_cooldown: bool


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def mfa_control_config() -> MFAControlConfig:
    window = _bounded_int("MFA_ATTEMPT_WINDOW_SECONDS", 300, 30, 3600)
    base = _bounded_int("MFA_BASE_COOLDOWN_SECONDS", 30, 1, 900)
    maximum = _bounded_int("MFA_MAX_COOLDOWN_SECONDS", 300, base, 3600)
    escalating = os.getenv("MFA_ESCALATING_COOLDOWN_ENABLED", "true").strip().lower()
    if escalating not in {"true", "false"}:
        raise ValueError("MFA_ESCALATING_COOLDOWN_ENABLED must be true or false")
    return MFAControlConfig(
        threshold=_bounded_int("MFA_FAILURE_THRESHOLD", 5, 2, 20),
        window_ms=window * 1000,
        base_cooldown_ms=base * 1000,
        max_cooldown_ms=maximum * 1000,
        escalation_ttl_ms=max(window, maximum * 2) * 1000,
        escalating_cooldown=escalating == "true",
    )


def validate_abuse_control_config() -> None:
    mfa_control_config()


def versioned_limit_key(logical_key: str) -> str:
    digest = hashlib.sha256(logical_key.encode("utf-8")).hexdigest()[:32]
    return f"authclaw:limit:v2:{{{digest}}}:count"


def atomic_increment(
    client: redis.Redis, logical_key: str, window_seconds: int
) -> tuple[int, int]:
    """Execute exactly one non-retried server-side increment/TTL operation."""
    if window_seconds <= 0:
        raise ValueError("rate-limit window must be positive")
    result = client.eval(
        ATOMIC_INCREMENT_LUA, 1, versioned_limit_key(logical_key), window_seconds * 1000
    )
    count, ttl = int(result[0]), int(result[1])
    if count < 1 or ttl < 0:
        raise redis.RedisError("invalid counter state")
    return count, ttl


def _mfa_keys(tenant_id: str, user_id: str, operation: str) -> tuple[str, str, str]:
    subject = hashlib.sha256(f"{tenant_id}:{user_id}".encode("utf-8")).hexdigest()[:32]
    operation_name = operation.replace("_", "-")
    prefix = f"authclaw:mfa:v2:{{{subject}}}:{operation_name}"
    return f"{prefix}:attempts", f"{prefix}:level", f"{prefix}:cooldown"


def _audit(
    tenant_id: str, user_id: str, operation: str, action: str, request_id: str
) -> None:
    request_id = request_id if isinstance(request_id, str) else ""
    event_backbone.increment_metric(f"mfa_abuse_{action}_total")
    event = event_backbone.audit_event(
        event_type="authentication",
        tenant_id=tenant_id,
        subject_id=user_id,
        identity_action=f"{operation}:{action}:{request_id or uuid.uuid4()}",
        action=f"mfa:{action}",
        reason=operation,
        provider="mfa-abuse-control",
        request_id=request_id,
    )
    event["actor_id"] = user_id
    event["result"] = "success" if action in {"reset", "recovery"} else "failure"
    if action in {"reset", "recovery"}:
        event["response_status"] = 200
    elif action.startswith("redis_"):
        event["response_status"] = 503
    elif action.startswith("cooldown"):
        event["response_status"] = 429
    else:
        event["response_status"] = 400
    if event_backbone.publish_audit_event(None, tenant_id, event):
        logger.warning("MFA security audit persistence failed action=%s", action)
    logger.info("[MFA_SECURITY_AUDIT] %s", json.dumps(event, sort_keys=True))


def _redis_failure(
    exc: redis.RedisError, tenant_id: str, user_id: str, operation: str, request_id: str
) -> HTTPException:
    ambiguous = isinstance(exc, redis.TimeoutError)
    action = "redis_ambiguous" if ambiguous else "redis_unavailable"
    _audit(tenant_id, user_id, operation, action, request_id)
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="MFA verification temporarily unavailable. Try again later.",
        headers={"Retry-After": "5"},
    )


def verify_mfa_challenge(
    client: redis.Redis,
    user,
    code: str,
    *,
    tenant_id: str,
    operation: str,
    request_id: str = "",
    pending_enrollment: bool = False,
) -> bool:
    """Verify MFA with an atomic, per-user/per-operation bounded cooldown."""
    attempts_key, level_key, cooldown_key = _mfa_keys(
        tenant_id, str(user.id), operation
    )
    config = mfa_control_config()
    try:
        cooldown_ms = int(client.eval(MFA_CHECK_LUA, 1, cooldown_key))
        if cooldown_ms == -1:
            raise redis.RedisError("invalid cooldown state")
    except redis.RedisError as exc:
        raise _redis_failure(
            exc, tenant_id, str(user.id), operation, request_id
        ) from exc
    if cooldown_ms > 0:
        _audit(tenant_id, str(user.id), operation, "cooldown", request_id)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many MFA attempts. Try again later.",
            headers={"Retry-After": str(max(1, (cooldown_ms + 999) // 1000))},
        )

    from app.core.auth import verify_mfa_code_result

    verification = (
        verify_mfa_code_result(user, code, pending_enrollment=True)
        if pending_enrollment
        else verify_mfa_code_result(user, code)
    )
    if verification.verified:
        try:
            cooldown_ms = int(client.eval(
                MFA_RESET_LUA, 3, attempts_key, level_key, cooldown_key
            ))
        except redis.RedisError as exc:
            raise _redis_failure(
                exc, tenant_id, str(user.id), operation, request_id
            ) from exc
        if cooldown_ms > 0:
            _audit(tenant_id, str(user.id), operation, "cooldown", request_id)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many MFA attempts. Try again later.",
                headers={"Retry-After": str(max(1, (cooldown_ms + 999) // 1000))},
            )
        _audit(tenant_id, str(user.id), operation, "reset", request_id)
        return True

    if verification.reason == "replay":
        _audit(tenant_id, str(user.id), operation, "replay_rejected", request_id)

    try:
        result = client.eval(
            MFA_FAILURE_LUA,
            3,
            attempts_key,
            level_key,
            cooldown_key,
            config.window_ms,
            config.threshold,
            config.base_cooldown_ms,
            config.max_cooldown_ms,
            config.escalation_ttl_ms,
            int(config.escalating_cooldown),
        )
    except redis.RedisError as exc:
        raise _redis_failure(
            exc, tenant_id, str(user.id), operation, request_id
        ) from exc
    cooldown_ms = int(result[1])
    _audit(
        tenant_id,
        str(user.id),
        operation,
        "cooldown_started" if cooldown_ms else "failure",
        request_id,
    )
    if cooldown_ms:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many MFA attempts. Try again later.",
            headers={"Retry-After": str(max(1, (cooldown_ms + 999) // 1000))},
        )
    return False

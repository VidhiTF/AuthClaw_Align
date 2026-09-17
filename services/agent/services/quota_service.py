"""Fail-closed admission; identities must come from verified authentication."""
import hashlib
from ipaddress import ip_address
import math
import os
import threading
import time
from urllib.parse import urlparse


class QuotaUnavailable(RuntimeError):
    pass


class QuotaExceeded(RuntimeError):
    def __init__(self, dimension, retry_after=60):
        super().__init__("quota exhausted")
        self.dimension = dimension
        self.retry_after = retry_after


LIMITS = {
    "tenant": "AUTHCLAW_RATE_LIMIT_PER_MINUTE",
    "user": "AUTHCLAW_RATE_LIMIT_USER_RPM",
    "key": "AUTHCLAW_RATE_LIMIT_KEY_RPM",
    "expensive_model": "AUTHCLAW_RATE_LIMIT_EXPENSIVE_MODEL_RPM",
}
ADMISSION_LUA = """
local counts = {}
local ttls = {}
for i, key in ipairs(KEYS) do
    local raw = redis.call('GET', key)
    local count = tonumber(raw or '0')
    local ttl = redis.call('PTTL', key)
    if not count or count < 0 or count > 2147483647 or count ~= math.floor(count) or
       (raw and (tostring(count) ~= raw or ttl < 0 or ttl > 60000)) then
        return redis.error_reply('invalid quota state')
    end
    counts[i] = count
    ttls[i] = ttl
end
for i, key in ipairs(KEYS) do
    if counts[i] >= tonumber(ARGV[i]) then
        return {0, i, math.max(1, ttls[i]), 0}
    end
end
local remaining = 9007199254740991
for i, key in ipairs(KEYS) do
    if ttls[i] < 0 then
        redis.call('SET', key, 1, 'PX', 60000)
    else
        redis.call('INCR', key)
    end
    remaining = math.min(remaining, tonumber(ARGV[i]) - counts[i] - 1)
end
return {1, 0, 60000, remaining}
"""
_lock = threading.RLock()
_memory = {}
_client = None
_client_url = None
_metrics = {"available": 0, "admitted": 0, "rejected": 0,
            "unavailable": 0, "ambiguous": 0, "latency_seconds": 0.0,
            "decisions": 0}


def _isolated():
    return os.getenv("AUTHCLAW_ENV", "development").strip().lower() in {
        "development", "dev", "local", "isolated-test"}


def _boolean(name, default="false"):
    raw = os.getenv(name, default).strip().lower()
    if raw not in {"true", "false", "1", "0", "yes", "no", "on", "off"}:
        raise ValueError(f"{name} must be boolean")
    return raw in {"true", "1", "yes", "on"}


def _limit(name):
    raw = os.getenv(name, "30" if _isolated() else "")
    if not raw.isascii() or not raw.isdigit() or not 0 < int(raw) <= 2147483647:
        raise ValueError(f"{name} must be a positive integer <= 2147483647")
    return int(raw)


def quota_config_errors():
    errors = []
    for name in LIMITS.values():
        try:
            _limit(name)
        except ValueError as exc:
            errors.append(str(exc))
    try:
        enabled = _boolean("AUTHCLAW_RATE_LIMIT_ENABLED", "true")
        memory = _boolean("AUTHCLAW_ALLOW_MEMORY_RATE_LIMIT")
        if not enabled and not _isolated():
            errors.append("Distributed rate limiting must be enabled")
        if memory and not _isolated():
            errors.append("Memory rate limiting requires an isolated environment")
        url = os.getenv("REDIS_URL", "").strip()
        if enabled and not url and not (memory and _isolated()):
            errors.append("REDIS_URL is required for distributed rate limiting")
        if url and (urlparse(url).scheme not in {"redis", "rediss"} or not urlparse(url).hostname):
            errors.append("REDIS_URL must be a Redis URL with a hostname")
        if url and not _isolated() and urlparse(url).scheme == "redis":
            host = urlparse(url).hostname
            try:
                loopback = ip_address(host).is_loopback
            except ValueError:
                loopback = host == "localhost"
            if not loopback:
                errors.append("Shared environments require Redis TLS except for loopback sidecars")
    except ValueError as exc:
        errors.append(str(exc))
    return errors


def _backend():
    global _client, _client_url
    errors = quota_config_errors()
    if errors:
        raise QuotaUnavailable("; ".join(errors))
    if not _boolean("AUTHCLAW_RATE_LIMIT_ENABLED", "true"):
        return "disabled"
    url = os.getenv("REDIS_URL", "").strip()
    if not url:
        return None
    with _lock:
        if _client is None or _client_url != url:
            import redis
            from redis.backoff import NoBackoff
            from redis.retry import Retry
            _client = redis.Redis.from_url(
                url, socket_connect_timeout=0.25, socket_timeout=0.25,
                retry_on_timeout=False, retry=Retry(NoBackoff(), 0))
            _client_url = url
        return _client


def metrics_snapshot():
    with _lock:
        return dict(_metrics)


def record_unavailable(ambiguous=False):
    with _lock:
        _metrics["available"] = 0
        _metrics["unavailable"] += 1
        _metrics["ambiguous"] += int(ambiguous)


def check_available():
    try:
        client = _backend()
        if client is not None and client != "disabled" and client.ping() is not True:
            raise QuotaUnavailable("Invalid Redis availability response")
        with _lock:
            _metrics["available"] = 1
    except Exception as exc:
        record_unavailable()
        raise QuotaUnavailable("Quota admission unavailable") from exc


def _digest(value):
    return hashlib.sha256(str(value).encode()).hexdigest()


def _memory_admit(keys, limits):
    now = time.monotonic()
    with _lock:
        for key in list(_memory):
            if _memory[key][1] <= now:
                del _memory[key]
        for i, (key, limit) in enumerate(zip(keys, limits)):
            count, expires = _memory.get(key, (0, now + 60))
            if count >= limit:
                return [0, i + 1, min(60000, max(1, math.ceil((expires - now) * 1000))), 0]
        remaining = min(limits)
        for key, limit in zip(keys, limits):
            count, expires = _memory.get(key, (0, now + 60))
            _memory[key] = count + 1, expires
            remaining = min(remaining, limit - count - 1)
        return [1, 0, 60000, remaining]


def admit(tenant_id, user_id=None, key_id=None, tenant_limit=None, provider_model=None):
    started = time.monotonic()
    attempted = False
    try:
        client = _backend()
        if tenant_id is None or not str(tenant_id).strip():
            raise QuotaUnavailable("Verified tenant identity required")
        if user_id is None and key_id is None and provider_model is None:
            raise QuotaUnavailable("Verified user or service key identity required")
        subjects = {"tenant": tenant_id}
        if user_id is not None:
            subjects["user"] = user_id
        if key_id is not None:
            subjects["key"] = key_id
        if provider_model is not None:
            if not str(provider_model).strip():
                raise QuotaUnavailable("Resolved model required")
            subjects = {"expensive_model": tenant_id}
        limits = [_limit(LIMITS[dimension]) for dimension in subjects]
        if tenant_limit is not None and provider_model is None:
            if type(tenant_limit) is not int or tenant_limit <= 0:
                raise QuotaUnavailable("Invalid resolved tenant quota")
            limits[0] = min(limits[0], tenant_limit)
        prefix = f"authclaw:quota:v1:{{{_digest(tenant_id)}}}"
        keys = [f"{prefix}:{dimension}:{_digest(subject)}" for dimension, subject in subjects.items()]
        if client == "disabled":
            result = [1, 0, 60000, min(limits)]
        elif client is None:
            result = _memory_admit(keys, limits)
        else:
            attempted = True
            result = client.eval(ADMISSION_LUA, len(keys), *keys, *limits)
        if (not isinstance(result, (list, tuple)) or len(result) != 4 or
                any(type(value) is not int for value in result)):
            raise QuotaUnavailable("Invalid quota response")
        allowed, index, ttl, remaining = result
        max_remaining = min(limits) - (0 if client == "disabled" else 1)
        if (allowed not in {0, 1} or not 0 < ttl <= 60000 or remaining < 0 or
                (allowed == 1 and (index != 0 or remaining > max_remaining)) or
                (allowed == 0 and (not 1 <= index <= len(keys) or remaining != 0))):
            raise QuotaUnavailable("Indeterminate quota admission")
        with _lock:
            _metrics["available"] = 1
            _metrics["admitted" if allowed else "rejected"] += 1
        if not allowed:
            raise QuotaExceeded(list(subjects)[index - 1], math.ceil(ttl / 1000))
        return {"remaining": remaining, "retry_after": math.ceil(ttl / 1000)}
    except QuotaExceeded:
        raise
    except Exception as exc:
        record_unavailable(attempted)
        raise QuotaUnavailable("Quota admission unavailable") from exc
    finally:
        with _lock:
            _metrics["decisions"] += 1
            _metrics["latency_seconds"] += time.monotonic() - started

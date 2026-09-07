"""Bounded Redis client shared by agent request paths."""

from functools import lru_cache
import os

import redis


def _seconds(name: str, default: float, minimum: float, maximum: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be numeric") from exc
    return max(minimum, min(value, maximum))


@lru_cache(maxsize=1)
def get_redis_client() -> redis.Redis:
    url = os.getenv("REDIS_URL", "").strip()
    if not url:
        raise RuntimeError("REDIS_URL is not configured")
    return redis.Redis.from_url(
        url,
        socket_connect_timeout=_seconds("REDIS_CONNECT_TIMEOUT_SECONDS", 2, 0.1, 10),
        socket_timeout=_seconds("REDIS_READ_TIMEOUT_SECONDS", 2, 0.1, 10),
        health_check_interval=30,
        max_connections=int(_seconds("REDIS_MAX_CONNECTIONS", 10, 1, 50)),
        retry_on_timeout=False,
        retry_on_error=[],
    )


def close_redis_client() -> None:
    if get_redis_client.cache_info().currsize:
        get_redis_client().close()
        get_redis_client.cache_clear()

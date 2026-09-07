"""Bounded shared Redis client for backend request paths."""

from __future__ import annotations

import os
from functools import lru_cache

import redis
from redis.backoff import NoBackoff
from redis.retry import Retry


def _seconds(name: str, default: float, minimum: float = 0.1, maximum: float = 10.0) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(value, maximum))


def _integer(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(value, maximum))


@lru_cache(maxsize=1)
def get_redis_client() -> redis.Redis:
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    if redis_url and not redis_url.startswith(("redis://", "rediss://")):
        redis_url = f"redis://{redis_url}"
    return redis.Redis.from_url(
        redis_url,
        decode_responses=True,
        socket_connect_timeout=_seconds("REDIS_CONNECT_TIMEOUT_SECONDS", 2),
        socket_timeout=_seconds("REDIS_READ_TIMEOUT_SECONDS", 2),
        socket_keepalive=True,
        health_check_interval=_integer("REDIS_HEALTH_CHECK_INTERVAL_SECONDS", 15, 5, 60),
        max_connections=_integer("REDIS_MAX_CONNECTIONS", 20, 1, 100),
        retry_on_timeout=False,
        retry=Retry(NoBackoff(), 0),
    )


def close_redis_client() -> None:
    if get_redis_client.cache_info().currsize:
        get_redis_client().close()
        get_redis_client.cache_clear()


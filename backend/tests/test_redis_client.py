from app.core import redis_client


def test_backend_redis_client_is_bounded_and_does_not_retry_ambiguous_writes(monkeypatch):
    captured = {}

    def from_url(url, **kwargs):
        captured.update({"url": url, **kwargs})
        return object()

    redis_client.get_redis_client.cache_clear()
    monkeypatch.setattr(redis_client.redis.Redis, "from_url", from_url)
    monkeypatch.setenv("REDIS_URL", "rediss://cache.example:6379")
    monkeypatch.setenv("REDIS_MAX_CONNECTIONS", "999")

    redis_client.get_redis_client()

    assert captured["socket_connect_timeout"] == 2
    assert captured["socket_timeout"] == 2
    assert captured["max_connections"] == 100
    assert captured["retry_on_timeout"] is False
    assert captured["retry"]._retries == 0
    redis_client.get_redis_client.cache_clear()


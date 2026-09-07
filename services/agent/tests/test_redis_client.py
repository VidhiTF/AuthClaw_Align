from services import redis_client


class _FakeRedis:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def test_redis_client_has_bounded_timeouts_and_no_ambiguous_retries(monkeypatch):
    captured = {}
    fake = _FakeRedis()

    def from_url(url, **kwargs):
        captured.update(url=url, **kwargs)
        return fake

    redis_client.get_redis_client.cache_clear()
    monkeypatch.setenv("REDIS_URL", "rediss://cache.example:6379")
    monkeypatch.setattr(redis_client.redis.Redis, "from_url", from_url)
    assert redis_client.get_redis_client() is fake
    assert captured["socket_connect_timeout"] == 2
    assert captured["socket_timeout"] == 2
    assert captured["max_connections"] == 10
    assert captured["retry_on_timeout"] is False
    assert captured["retry_on_error"] == []

    redis_client.close_redis_client()
    assert fake.closed

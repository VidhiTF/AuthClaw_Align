"""Opt-in integration proof against disposable real Redis (no database flush)."""
import concurrent.futures
import os
import sys
import time
import unittest
import uuid
import socket
import threading
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services import quota_service as quota


@unittest.skipUnless(os.getenv("QUOTA_TEST_REDIS_URL"), "requires disposable real Redis")
class RedisQuotaTests(unittest.TestCase):
    def setUp(self):
        import redis
        self.url = os.environ["QUOTA_TEST_REDIS_URL"]
        # Setup/observation is outside the admission latency budget; production
        # quota clients retain their mandatory 250 ms timeouts.
        self.client = redis.Redis.from_url(self.url, socket_timeout=2)
        self.tenant = "quota-test-" + uuid.uuid4().hex
        self.prefix = f"authclaw:quota:v1:{{{quota._digest(self.tenant)}}}"
        self.env = patch.dict(os.environ, {
            "AUTHCLAW_ENV": "test", "REDIS_URL": self.url,
            "AUTHCLAW_RATE_LIMIT_ENABLED": "true", "AUTHCLAW_ALLOW_MEMORY_RATE_LIMIT": "false",
            **{name: "100" for name in quota.LIMITS.values()},
        })
        self.env.start()
        self.addCleanup(self.env.stop)
        self.addCleanup(self.cleanup_keys)

    def cleanup_keys(self):
        keys = list(self.client.scan_iter(self.prefix + "*"))
        if keys:
            self.client.delete(*keys)

    def test_concurrent_clients_share_exact_admission(self):
        import redis
        clients = [redis.Redis.from_url(self.url) for _ in range(3)]
        key = f"{self.prefix}:tenant:{quota._digest(self.tenant)}"
        def attempt(index):
            return clients[index % 3].eval(quota.ADMISSION_LUA, 1, key, 17)[0]
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
                self.assertEqual(sum(pool.map(attempt, range(150))), 17)
            self.assertEqual(int(self.client.get(key)), 17)
            self.assertGreater(self.client.pttl(key), 0)
        finally:
            for client in clients:
                client.close()

    def test_corrupt_counter_blocks_all_writes(self):
        tenant_key = f"{self.prefix}:tenant:{quota._digest(self.tenant)}"
        user_key = f"{self.prefix}:user:{quota._digest('user')}"
        for malformed in ("not-a-number", "1.5", "01", "1e2", "2147483648"):
            self.client.set(user_key, malformed, px=60000)
            with self.assertRaises(quota.QuotaUnavailable):
                quota.admit(self.tenant, "user")
            self.assertIsNone(self.client.get(tenant_key))
        self.client.set(user_key, "1")
        with self.assertRaises(quota.QuotaUnavailable):
            quota.admit(self.tenant, "user")
        self.assertIsNone(self.client.get(tenant_key))
        self.client.set(user_key, "1", px=120000)
        with self.assertRaises(quota.QuotaUnavailable):
            quota.admit(self.tenant, "user")
        self.assertIsNone(self.client.get(tenant_key))

    def test_independent_dimensions_denial_and_expiry(self):
        for dimension in quota.LIMITS:
            self.cleanup_keys()
            with patch.dict(os.environ, {quota.LIMITS[dimension]: "1"}):
                kwargs = {"provider_model": "provider/model"} if dimension == "expensive_model" else {"user_id": "u", "key_id": "k"}
                quota.admit(self.tenant, **kwargs)
                keys = list(self.client.scan_iter(self.prefix + "*"))
                before = {key: self.client.get(key) for key in keys}
                with self.assertRaises(quota.QuotaExceeded) as caught:
                    quota.admit(self.tenant, **kwargs)
                self.assertEqual(caught.exception.dimension, dimension)
                self.assertEqual(before, {key: self.client.get(key) for key in keys})
                for key in keys:
                    self.client.pexpire(key, 1)
                time.sleep(0.02)
                quota.admit(self.tenant, **kwargs)

    def test_after_write_timeout_fails_closed_without_retry(self):
        real_client = self.client
        class AmbiguousClient:
            calls = 0
            def eval(self, *args):
                self.calls += 1
                real_client.eval(*args)
                raise TimeoutError("response lost after Redis execution")
        ambiguous = AmbiguousClient()
        with patch.object(quota, "_backend", return_value=ambiguous):
            with self.assertRaises(quota.QuotaUnavailable):
                quota.admit(self.tenant, "u")
        self.assertEqual(ambiguous.calls, 1)
        tenant_key = f"{self.prefix}:tenant:{quota._digest(self.tenant)}"
        self.assertEqual(int(self.client.get(tenant_key)), 1)
        quota.check_available()
        quota.admit(self.tenant, "u")
        self.assertEqual(int(self.client.get(tenant_key)), 2)

    def test_real_socket_timeout_before_execution_and_recovery(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        connections = []
        finished = threading.Event()
        def blackhole():
            connection, _ = listener.accept()
            connections.append(connection)
            connection.recv(4096)
            finished.wait(2)
            connection.close()
        worker = threading.Thread(target=blackhole, daemon=True)
        worker.start()
        started = time.monotonic()
        try:
            with patch.dict(os.environ, {"REDIS_URL": f"redis://127.0.0.1:{listener.getsockname()[1]}"}):
                with self.assertRaises(quota.QuotaUnavailable):
                    quota.admit(self.tenant, "u")
            self.assertLess(time.monotonic() - started, 1.5)
            self.assertEqual(len(connections), 1)
            self.assertEqual(list(self.client.scan_iter(self.prefix + "*")), [])
        finally:
            finished.set()
            listener.close()
            worker.join(3)
        quota.check_available()
        quota.admit(self.tenant, "u")


if __name__ == "__main__":
    unittest.main()

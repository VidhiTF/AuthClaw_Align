import concurrent.futures
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services import quota_service as quota


class QuotaServiceTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {
            "AUTHCLAW_ENV": "development", "AUTHCLAW_ALLOW_MEMORY_RATE_LIMIT": "true",
            "AUTHCLAW_RATE_LIMIT_ENABLED": "true", "REDIS_URL": "",
            **{name: "100" for name in quota.LIMITS.values()},
        }, clear=True)
        self.env.start()
        quota._memory.clear()
        self.addCleanup(self.env.stop)

    def test_dimensions_are_independently_enforced_without_denial_charge(self):
        for dimension in ("tenant", "user", "key"):
            with self.subTest(dimension=dimension):
                quota._memory.clear()
                with patch.dict(os.environ, {quota.LIMITS[dimension]: "1"}):
                    quota.admit("t", "u", "k")
                    before = dict(quota._memory)
                    with self.assertRaises(quota.QuotaExceeded) as caught:
                        quota.admit("t", "u", "k")
                    self.assertEqual(caught.exception.dimension, dimension)
                    self.assertEqual(before, quota._memory)

    def test_users_keys_and_tenants_are_scoped(self):
        with patch.dict(os.environ, {quota.LIMITS["user"]: "2", quota.LIMITS["key"]: "1"}):
            quota.admit("a", "u", "k1")
            quota.admit("a", "u", "k2")
            with self.assertRaises(quota.QuotaExceeded) as caught:
                quota.admit("a", "u", "k3")
            self.assertEqual(caught.exception.dimension, "user")
            quota.admit("a", "other", "k3")
            quota.admit("b", "u", "k1")

    def test_provider_counter_is_aggregate_and_separate(self):
        with patch.dict(os.environ, {quota.LIMITS["tenant"]: "1", quota.LIMITS["expensive_model"]: "1"}):
            quota.admit("t", "u")
            quota.admit("t", provider_model="openai/resolved")
            with self.assertRaises(quota.QuotaExceeded) as caught:
                quota.admit("t", provider_model="fallback/other")
            self.assertEqual(caught.exception.dimension, "expensive_model")
            quota.admit("other", provider_model="openai/resolved")

    def test_service_key_is_independently_enforced(self):
        with patch.dict(os.environ, {quota.LIMITS["key"]: "1"}):
            quota.admit("t", key_id="service")
            with self.assertRaises(quota.QuotaExceeded):
                quota.admit("t", key_id="service")

    def test_concurrency_admits_exact_capacity(self):
        with patch.dict(os.environ, {quota.LIMITS["tenant"]: "9"}):
            def attempt(_):
                try:
                    quota.admit("t", "u", "k")
                    return 1
                except quota.QuotaExceeded:
                    return 0
            with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
                self.assertEqual(sum(pool.map(attempt, range(100))), 9)

    def test_window_boundary_and_expiry(self):
        with patch.dict(os.environ, {quota.LIMITS["tenant"]: "1"}):
            with patch.object(quota.time, "monotonic", return_value=100):
                quota.admit("t", "u")
            with patch.object(quota.time, "monotonic", return_value=159.999):
                with self.assertRaises(quota.QuotaExceeded):
                    quota.admit("t", "u")
            with patch.object(quota.time, "monotonic", return_value=160):
                quota.admit("t", "u")

    def test_strict_config_missing_invalid_and_disabled(self):
        for env in ("production", "prod", "staging", "test", "shared-test", "unknown"):
            with self.subTest(env=env), patch.dict(os.environ, {"AUTHCLAW_ENV": env}):
                self.assertTrue(quota.quota_config_errors())
                with self.assertRaises(quota.QuotaUnavailable):
                    quota.admit("t", "u")
        for invalid in ("", "0", "-1", "3.5", "oops", "999999999999999"):
            with patch.dict(os.environ, {quota.LIMITS["key"]: invalid}):
                self.assertTrue(quota.quota_config_errors())
        with patch.dict(os.environ, {"AUTHCLAW_ENV": "production", "REDIS_URL": "redis://localhost", "AUTHCLAW_ALLOW_MEMORY_RATE_LIMIT": "false"}):
            self.assertEqual(quota.quota_config_errors(), [])
            with patch.dict(os.environ, {"AUTHCLAW_RATE_LIMIT_ENABLED": "false"}):
                self.assertTrue(quota.quota_config_errors())

    def test_no_implicit_memory_or_identity(self):
        with patch.dict(os.environ, {"AUTHCLAW_ALLOW_MEMORY_RATE_LIMIT": "false"}):
            with self.assertRaises(quota.QuotaUnavailable):
                quota.admit("t", "u")
        for args in ((None, "u"), ("t", None)):
            with self.assertRaises(quota.QuotaUnavailable):
                quota.admit(*args)

    def test_failed_and_ambiguous_redis_execution_never_retries(self):
        for error in (ConnectionRefusedError(), TimeoutError("before execution"), TimeoutError("after execution")):
            client = Mock()
            client.eval.side_effect = error
            before = quota.metrics_snapshot()["ambiguous"]
            with patch.object(quota, "_backend", return_value=client):
                with self.assertRaises(quota.QuotaUnavailable):
                    quota.admit("t", "u", "k")
            client.eval.assert_called_once()
            self.assertEqual(quota.metrics_snapshot()["ambiguous"], before + 1)
            self.assertEqual(quota.metrics_snapshot()["available"], 0)

    def test_invalid_redis_responses_and_recovery(self):
        client = Mock()
        with patch.object(quota, "_backend", return_value=client):
            for response in (None, [], [True, 0, 60000, 1], [1, 0, -1, 2], [0, 9, 1, 0], [2, 0, 5, 1], [1, 0, 60000, 999], [1, 0, 60000, 100]):
                client.eval.return_value = response
                with self.assertRaises(quota.QuotaUnavailable):
                    quota.admit("t", "u")
            client.eval.return_value = [1, 0, 60000, 10]
            self.assertEqual(quota.admit("t", "u")["remaining"], 10)
            self.assertEqual(quota.metrics_snapshot()["available"], 1)
            client.ping.return_value = False
            with self.assertRaises(quota.QuotaUnavailable):
                quota.check_available()
            client.ping.return_value = True
            quota.check_available()

    def test_cluster_keys_and_no_request_identity_metrics(self):
        client = Mock()
        client.eval.return_value = [1, 0, 60000, 99]
        with patch.object(quota, "_backend", return_value=client):
            quota.admit("sensitive-tenant", "sensitive-user", "sensitive-key")
        args = client.eval.call_args.args
        self.assertEqual(args[1], 3)
        keys = args[2:5]
        self.assertEqual(len({key.split("{")[1].split("}")[0] for key in keys}), 1)
        self.assertNotIn("sensitive", repr(keys))
        self.assertNotIn("sensitive", repr(quota.metrics_snapshot()))

    def test_shared_redis_transport_requires_tls_or_loopback(self):
        with patch.dict(os.environ, {"AUTHCLAW_ENV": "staging", "AUTHCLAW_ALLOW_MEMORY_RATE_LIMIT": "false"}):
            for url in ("redis://cache.internal:6379", "redis://10.0.0.4:6379"):
                with patch.dict(os.environ, {"REDIS_URL": url}):
                    self.assertTrue(quota.quota_config_errors())
            for url in ("rediss://cache.internal:6379", "redis://127.0.0.1:6379", "redis://[::1]:6379"):
                with patch.dict(os.environ, {"REDIS_URL": url}):
                    self.assertEqual(quota.quota_config_errors(), [])


if __name__ == "__main__":
    unittest.main()

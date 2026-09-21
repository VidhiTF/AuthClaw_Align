"""Current delivery failures outrank missing queue checkpoint observations."""
import sys
import os
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.observability_service import ObservabilityService


class QueueHealthTests(unittest.TestCase):
    def test_security_alert_recovery_does_not_require_kafka_checkpoint(self):
        for audit in (False, True):
            for queued, dead, expected in ((0, 0, "healthy"), (1, 0, "unknown"), (0, 1, "degraded")):
                with self.subTest(audit=audit, queued=queued, dead=dead):
                    streams = {"security_alert": {"delivered": 1, "queued": queued, "dead_letter": dead}}
                    checkpoints = []
                    if audit:
                        streams["audit"] = {"delivered": 1, "queued": 0, "dead_letter": 0}
                        checkpoints = [self.checkpoint(dead_letter_count=0, pending_events=0)]
                    result = ObservabilityService()._queue_lag({"streams": streams, "checkpoints": checkpoints})
                    self.assertEqual(result["status"], expected)
                    self.assertEqual(result["pending_events"], queued + dead)
                    self.assertEqual(result["alertable"], expected != "healthy")

    def test_malformed_pipeline_and_checkpoints_never_raise(self):
        malformed = [None, [], "bad", 7]
        malformed += [{"streams": {}, "checkpoints": value} for value in (None, {}, "bad", 2, [None], [[]], [{"stream": []}], [{"stream": None}])]
        for pipeline in malformed:
            with self.subTest(pipeline=pipeline):
                result = ObservabilityService()._queue_lag(pipeline)
                self.assertEqual(result["status"], "unknown")
                self.assertTrue(result["alertable"])
                self.assertIsNone(result["max_lag_seconds"])

    def test_invalid_threshold_is_unavailable(self):
        for threshold in ("", "bad", "-1", "0", "1.5"):
            with self.subTest(threshold=threshold), patch.dict(os.environ, AUTHCLAW_QUEUE_LAG_ALERT_SECONDS=threshold):
                result = ObservabilityService()._queue_lag({"streams": {}, "checkpoints": []})
                self.assertEqual(result["status"], "unavailable")
                self.assertTrue(result["alertable"])

    def test_pending_alert_does_not_hide_known_audit_lag_failure(self):
        result = ObservabilityService()._queue_lag({
            "streams": {"audit": {"queued": 1, "dead_letter": 0}, "security_alert": {"queued": 1, "dead_letter": 0}},
            "checkpoints": [self.checkpoint(lag_seconds=600, pending_events=1, dead_letter_count=0)],
        })
        self.assertEqual(result["status"], "degraded")
        self.assertEqual(result["pending_events"], 2)
        self.assertIsNone(result["max_lag_seconds"])

    def checkpoint(self, **changes):
        return {"stream": "audit", "updated_at": datetime.now(timezone.utc),
                "lag_seconds": 0, "dead_letter_count": 1, "pending_events": 3,
                **changes}

    def test_live_dead_letters_survive_incomplete_checkpoints(self):
        for checkpoints in ([], [self.checkpoint(updated_at=datetime.now(timezone.utc) - timedelta(days=1))],
                            [self.checkpoint(dead_letter_count=0)],
                            [self.checkpoint(stream="analytics")]):
            with self.subTest(checkpoints=checkpoints):
                result = ObservabilityService()._queue_lag({
                    "streams": {"audit": {"queued": 2, "dead_letter": 1}},
                    "checkpoints": checkpoints,
                })
                self.assertEqual(result["status"], "degraded")
                self.assertEqual(result["dead_letter_count"], 1)
                self.assertEqual(result["pending_events"], 3)
                self.assertIsNone(result["max_lag_seconds"])
                self.assertTrue(result["alertable"])

    def test_pending_without_checkpoint_preserves_counts_without_health(self):
        result = ObservabilityService()._queue_lag({
            "streams": {"audit": {"queued": 2, "dead_letter": 0}}, "checkpoints": [],
        })
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["pending_events"], 2)
        self.assertEqual(result["dead_letter_count"], 0)
        self.assertIsNone(result["max_lag_seconds"])

    def test_malformed_current_counts_never_claim_health(self):
        for counts in (None, [], {"queued": None}, {"dead_letter": "bad"},
                       {"queued": False}, {"queued": 0.5},
                       {"queued": -1, "dead_letter": 1}):
            with self.subTest(counts=counts):
                result = ObservabilityService()._queue_lag({
                    "streams": {"audit": counts},
                    "checkpoints": [self.checkpoint(dead_letter_count=0, pending_events=0)],
                })
                self.assertEqual(result["status"], "unknown")
                self.assertTrue(result["alertable"])

    def test_fresh_checkpoint_still_reports_observed_health_and_failure(self):
        for dead_letters, status in ((0, "healthy"), (1, "degraded")):
            result = ObservabilityService()._queue_lag({
                "streams": {"audit": {"queued": 0, "dead_letter": dead_letters}},
                "checkpoints": [self.checkpoint(dead_letter_count=dead_letters, pending_events=dead_letters)],
            })
            self.assertEqual(result["status"], status)
            self.assertEqual(result["dead_letter_count"], dead_letters)


if __name__ == "__main__":
    unittest.main()

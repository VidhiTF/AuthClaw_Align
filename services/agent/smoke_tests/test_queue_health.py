"""Current delivery failures outrank missing queue checkpoint observations."""
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.observability_service import ObservabilityService


class QueueHealthTests(unittest.TestCase):
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

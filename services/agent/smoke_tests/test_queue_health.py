"""Current delivery failures outrank missing queue checkpoint observations."""
import sys
import os
import unittest
import io
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.observability_service import ObservabilityService
from services.event_pipeline import EventPipeline


class QueueHealthTests(unittest.TestCase):
    def test_kafka_acknowledgement_controls_delivery_and_health(self):
        acknowledged = {"partition": 0, "offset": 0, "error_code": None, "error": None}
        rejected = {"partition": None, "offset": None, "error_code": 50003, "error": "Broker unavailable"}
        malformed = [None, {}, [], {"offsets": None}, {"offsets": []},
                     {"offsets": [acknowledged, acknowledged]}, {"offsets": [None]}]
        malformed += [{"offsets": [{**acknowledged, key: value}]}
                      for key, value in (("error_code", 50003), ("error", "rejected"),
                                         ("offset", None), ("offset", -1), ("offset", True),
                                         ("partition", "0"), ("partition", -1))]
        malformed += [{"offsets": [{"partition": 0}]}, {"offsets": [rejected]}]
        cases = [(json.dumps(body).encode(), False) for body in malformed]
        cases += [(b"not json", False), (json.dumps({"offsets": [acknowledged]}).encode(), True)]
        for body, succeeds in cases:
            with self.subTest(body=body):
                database = MagicMock()
                conn = database.begin.return_value.__enter__.return_value
                record = {"status": "queued", "stream": "audit", "tenant_id": 7,
                          "payload": "{}", "attempts": 0, "topic": "audit", "error_message": None}
                conn.execute.return_value.fetchone.return_value = SimpleNamespace(_mapping=record)
                def response(*args, **kwargs):
                    result = io.BytesIO(body)
                    result.status = 200
                    return result
                with patch.dict(os.environ, KAFKA_REST_URL="http://kafka.invalid", AGENT_AUDIT_STREAM_TRANSPORT="kafka",
                                AUTHCLAW_CLICKHOUSE_ENABLED="false", AUTHCLAW_EVENT_DELIVERY_ATTEMPTS="2"), \
                     patch("services.event_pipeline.engine", database), \
                     patch("services.audit_transport.urllib.request.urlopen", side_effect=response) as request, \
                     patch.object(EventPipeline, "refresh_checkpoint"), patch("services.event_pipeline.time.sleep"):
                    pipeline = EventPipeline()
                    result = pipeline.deliver_event("event-1")
                    self.assertEqual(result["status"], "delivered" if succeeds else "dead_letter")
                    self.assertEqual(request.call_count, 1 if succeeds else 2)
                    updates = [call.args[1] for call in conn.execute.call_args_list
                               if "UPDATE event_delivery_records" in str(call.args[0])]
                    self.assertEqual(updates[-1]["status"], result["status"])
                    self.assertEqual(any("INSERT INTO event_dead_letters" in str(call.args[0])
                                         for call in conn.execute.call_args_list), not succeeds)
                    dead = int(not succeeds)
                    health = ObservabilityService()._queue_lag({"streams": {"audit": {"queued": 0, "dead_letter": dead}},
                        "checkpoints": [self.checkpoint(dead_letter_count=dead, pending_events=dead)]})
                    self.assertEqual(health["status"], "healthy" if succeeds else "degraded")
                    self.assertEqual(health["alertable"], not succeeds)
                    if not succeeds:
                        record.update(status="dead_letter", attempts=2)
                        body = json.dumps({"offsets": [acknowledged]}).encode()
                        self.assertEqual(pipeline.deliver_event("event-1", retry=True)["status"], "delivered")

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

import argparse
import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gateway_latency_benchmark as bench


def report(name: str, **overrides: object) -> bench.ScenarioReport:
    data = {
        "scenario": name,
        "requests": 3,
        "successes": 3,
        "failures": 0,
        "error_rate": 0.0,
        "status_counts": {"200": 3},
        "throughput_rps": 100.0,
        "min_ms": 1.0,
        "p50_ms": 25.0,
        "p95_ms": 45.0,
        "p99_ms": 49.0,
        "max_ms": 50.0,
        "mean_ms": 30.0,
        "first_byte_p50_ms": 10.0,
        "first_byte_p95_ms": 20.0,
        "first_byte_p99_ms": 25.0,
        "stream_event_count": 0,
        "stream_done_count": 0,
        "stream_invalid_event_count": 0,
        "stream_max_event_bytes": 0,
        "errors": [],
    }
    data.update(overrides)
    return bench.ScenarioReport(**data)


def args(**overrides: object) -> argparse.Namespace:
    data = {
        "provider_baseline_url": "http://provider.test",
        "require_provider_baseline": True,
        "max_failure_rate": 0.0,
        "p95_threshold_ms": 800.0,
        "p99_threshold_ms": 1000.0,
        "overhead_p50_threshold_ms": 50.0,
        "overhead_p95_threshold_ms": 50.0,
        "overhead_p99_threshold_ms": 50.0,
        "transform_overhead_p50_threshold_ms": 250.0,
        "transform_overhead_p95_threshold_ms": 250.0,
        "transform_overhead_p99_threshold_ms": 250.0,
        "stream_first_byte_overhead_p95_threshold_ms": 50.0,
        "stream_overhead_p50_threshold_ms": 50.0,
        "stream_overhead_p95_threshold_ms": 50.0,
        "stream_overhead_p99_threshold_ms": 50.0,
    }
    data.update(overrides)
    return argparse.Namespace(**data)


class GatewayLatencyBenchmarkTests(unittest.TestCase):
    def test_attach_overhead_records_p50_p95_p99_and_first_byte(self) -> None:
        gateway = [report("allow", p50_ms=70.0, p95_ms=95.0, p99_ms=120.0, first_byte_p95_ms=35.0)]
        baselines = {"allow": report("allow", p50_ms=25.0, p95_ms=45.0, p99_ms=90.0, first_byte_p95_ms=20.0)}

        bench.attach_overhead_reports(gateway, baselines)

        self.assertEqual(gateway[0].gateway_overhead_p50_ms, 45.0)
        self.assertEqual(gateway[0].gateway_overhead_p95_ms, 50.0)
        self.assertEqual(gateway[0].gateway_overhead_p99_ms, 30.0)
        self.assertEqual(gateway[0].first_byte_overhead_p95_ms, 15.0)

    def test_stream_evidence_rejects_fragmented_application_events(self) -> None:
        stream = io.BytesIO(
            b'data: {"candidates":[{"content":{"parts":[{"text":"ok"}]}}]}\n\n'
            b"data: {broken-json\n\n"
            b"data: [DONE]\n\n"
        )
        first = stream.read(1)

        evidence = bench.drain_stream_until_done(stream, first)

        self.assertEqual(evidence.event_count, 2)
        self.assertTrue(evidence.done_seen)
        self.assertEqual(evidence.invalid_event_count, 1)

    def test_threshold_failures_cover_overhead_and_stream_integrity(self) -> None:
        reports = [
            report("allow", gateway_overhead_p50_ms=10.0, gateway_overhead_p95_ms=55.0, gateway_overhead_p99_ms=70.0),
            report("block", gateway_overhead_p50_ms=200.0, gateway_overhead_p95_ms=300.0, gateway_overhead_p99_ms=400.0),
            report(
                "stream",
                gateway_overhead_p50_ms=5.0,
                gateway_overhead_p95_ms=15.0,
                gateway_overhead_p99_ms=25.0,
                first_byte_overhead_p95_ms=12.0,
                stream_event_count=2,
                stream_done_count=2,
                stream_invalid_event_count=1,
            ),
        ]

        failures = bench.threshold_failures(reports, {}, args())

        self.assertIn("allow gateway overhead p95 55.0ms exceeds 50.0ms", failures)
        self.assertIn("allow gateway overhead p99 70.0ms exceeds 50.0ms", failures)
        self.assertIn("stream stream DONE count 2 != 3", failures)
        self.assertIn("stream stream had 1 fragmented/invalid SSE data events", failures)
        self.assertFalse(any(failure.startswith("block gateway overhead") for failure in failures))


if __name__ == "__main__":
    unittest.main()

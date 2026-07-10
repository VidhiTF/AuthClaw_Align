import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ha_failover_evidence as ha


GOOD = {
    "availability_target_percent": 99.99,
    "data_write_topology": "active-standby",
    "database": {
        "promoted_read_replica_workflow": True,
        "replica_lag_seconds": 12,
        "promotion_started_at": "2026-07-08T10:00:00Z",
        "promotion_completed_at": "2026-07-08T10:02:10Z",
    },
    "route53": {
        "primary_record_withdrawn": True,
        "secondary_record_served": True,
        "failover_observed_seconds": 35,
    },
    "chaos": {
        "failure_modes": ["primary_region_unavailable", "database_primary_unavailable"],
    },
    "recovery": {
        "rto_seconds": 190,
        "write_probe_verified": True,
        "audit_chain_verified": True,
        "no_failed_requests_after_recovery": True,
        "health_checks": {
            "console": True,
            "backend": True,
            "gateway": True,
        },
    },
    "latency": {
        "post_failover": {
            "gateway_p95_ms": 300,
            "gateway_p99_ms": 520,
            "gateway_overhead_p95_ms": 42,
        },
    },
}


def errors(payload: dict) -> list[str]:
    return ha.validate_evidence(
        payload,
        max_rto_seconds=240,
        max_rpo_seconds=30,
        max_route53_seconds=60,
        max_gateway_p95_ms=900,
        max_gateway_p99_ms=1200,
        max_gateway_overhead_p95_ms=50,
    )


class HaFailoverEvidenceTests(unittest.TestCase):
    def test_accepts_complete_active_standby_evidence(self) -> None:
        self.assertEqual(errors(copy.deepcopy(GOOD)), [])

    def test_rejects_unclarified_active_active_writes(self) -> None:
        payload = copy.deepcopy(GOOD)
        payload["data_write_topology"] = "active-active"

        self.assertIn("data_write_topology must be active-standby", errors(payload))

    def test_rejects_missing_route53_failover_and_bad_rto(self) -> None:
        payload = copy.deepcopy(GOOD)
        payload["route53"]["secondary_record_served"] = False
        payload["recovery"]["rto_seconds"] = 360

        result = errors(payload)

        self.assertIn("secondary_record_served must be true", result)
        self.assertIn("rto_seconds 360 exceeds 240", result)

    def test_rejects_missing_correctness_and_latency_proof(self) -> None:
        payload = copy.deepcopy(GOOD)
        payload["recovery"]["audit_chain_verified"] = False
        payload["latency"]["post_failover"]["gateway_overhead_p95_ms"] = 55

        result = errors(payload)

        self.assertIn("audit_chain_verified must be true", result)
        self.assertIn("gateway_overhead_p95_ms 55 exceeds 50", result)


if __name__ == "__main__":
    unittest.main()

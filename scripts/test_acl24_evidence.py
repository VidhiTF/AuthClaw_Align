import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import acl24_evidence as evidence


GOOD = {
    "generated_at": "2026-07-23T12:30:00Z",
    "environment": "controlled-beta",
    "release": {
        "source_sha": "a" * 40,
        "alembic_revision": "034",
        "rds_instances": {"app": "arn:aws:rds:ap-south-1:123456789012:db:authclaw-beta-postgres"},
        "ecs_task_definitions": {
            "backend": "arn:aws:ecs:ap-south-1:123456789012:task-definition/authclaw-backend:34"
        },
        "alarms_ok": True,
        "agent_persistence_in_scope": False,
    },
    "audit_export": {
        "generated_at": "2026-07-23T08:55:00Z",
        "signed": True,
        "signature_verified": True,
        "pre_drill": True,
    },
    "backup_restore": {
        "snapshot_id": "acl24-beta-20260723",
        "snapshot_encrypted": True,
        "source_instance_id": "authclaw-beta-postgres",
        "restore_instance_id": "acl24-restore-20260723",
        "restore_isolated": True,
        "restore_publicly_accessible": False,
        "started_at": "2026-07-23T09:00:00Z",
        "completed_at": "2026-07-23T09:18:00Z",
        "restore_duration_seconds": 1080,
        "alembic_revision_matches": True,
        "sentinel_verified": True,
        "record_counts_match": True,
        "audit_chain_verified": True,
    },
    "rollback": {
        "application_succeeded": True,
        "database_succeeded": True,
        "database_rollback_isolated": True,
        "live_database_untouched": True,
        "services_stable": True,
        "pre_rollback_audit_verified": True,
        "post_rollback_audit_verified": True,
        "post_rollback_event_extended_chain": True,
        "recovery_seconds": 180,
        "smoke_checks": {"login": True, "gateway": True, "audit": True},
        "previous_task_definitions": {"backend": True, "gateway": True, "console": True},
        "database_target_id": "acl24-restore-20260723",
        "notes_reference": "ACL-24/rollback.log",
    },
    "load": {
        "scenarios": ["allow", "redact", "block", "stream"],
        "concurrency_ramp": [5, 10, 20],
        "scenario_results": {
            name: {
                "requests": 100,
                "p50_ms": 400,
                "p95_ms": 750,
                "p99_ms": 980,
                "throughput_rps": 25,
                "status_counts": {"200": 100},
                "error_rate": 0,
            }
            for name in ("allow", "redact", "block", "stream")
        },
        "saturation": {
            "ecs_cpu_percent": 72,
            "ecs_memory_percent": 68,
            "rds_cpu_percent": 64,
            "rds_database_connections": 24,
            "rds_freeable_memory_bytes": 536870912,
            "rds_read_latency_ms": 3.2,
            "rds_write_latency_ms": 4.1,
            "alb_5xx": 0,
            "alb_target_response_p95_ms": 510,
            "redis_cpu_percent": 38,
        },
        "recovery_seconds": 120,
        "health_checks": {"console": True, "backend": True, "gateway": True},
        "cloudwatch_windows": {"before": True, "during": True, "after": True},
        "alarms_ok": True,
        "audit_chain_verified": True,
    },
    "artifacts": {
        "redacted": True,
        "contains_raw_tenant_payloads": False,
        "sha256": {
            "audit_export_verification": "1" * 64,
            "benchmark": "2" * 64,
            "cloudwatch_metrics": "3" * 64,
            "rollback_log": "4" * 64,
        },
    },
    "ci": {"required_checks_green": True, "compatibility_tests_green": True},
}


class ACL24EvidenceTests(unittest.TestCase):
    def test_accepts_complete_safe_evidence(self) -> None:
        self.assertEqual(evidence.validate_evidence(copy.deepcopy(GOOD)), [])

    def test_rejects_restore_or_rollback_that_can_touch_live_data(self) -> None:
        payload = copy.deepcopy(GOOD)
        payload["backup_restore"]["restore_isolated"] = False
        payload["rollback"]["live_database_untouched"] = False

        errors = evidence.validate_evidence(payload)

        self.assertIn("restore_isolated must be true", errors)
        self.assertIn("live_database_untouched must be true", errors)

    def test_rejects_load_threshold_and_recovery_failures(self) -> None:
        payload = copy.deepcopy(GOOD)
        payload["load"]["scenario_results"]["redact"]["p95_ms"] = 901
        payload["load"]["scenario_results"]["redact"]["error_rate"] = 0.01
        payload["load"]["saturation"]["ecs_cpu_percent"] = 86
        payload["load"]["recovery_seconds"] = 301

        errors = evidence.validate_evidence(payload)

        self.assertIn("load.scenario_results.redact.p95_ms 901 exceeds 900", errors)
        self.assertIn("load.scenario_results.redact.error_rate 0.01 exceeds 0", errors)
        self.assertIn("ecs_cpu_percent 86 exceeds 85", errors)
        self.assertIn("recovery_seconds 301 exceeds 300", errors)

    def test_rejects_incomplete_or_unredacted_artifacts(self) -> None:
        payload = copy.deepcopy(GOOD)
        payload["load"]["scenarios"].remove("stream")
        payload["artifacts"]["redacted"] = False
        payload["artifacts"]["contains_raw_tenant_payloads"] = True
        del payload["artifacts"]["sha256"]["benchmark"]

        errors = evidence.validate_evidence(payload)

        self.assertIn("load.scenarios must include allow, redact, block, and stream", errors)
        self.assertIn("redacted must be true", errors)
        self.assertIn("contains_raw_tenant_payloads must be false", errors)
        self.assertIn("artifacts.sha256 is missing: benchmark", errors)

    def test_rejects_incomplete_drill_contract_and_missing_scoped_agent_restore(self) -> None:
        payload = copy.deepcopy(GOOD)
        payload["release"]["agent_persistence_in_scope"] = True
        payload["audit_export"]["signed"] = False
        payload["audit_export"]["generated_at"] = "2026-07-23T09:01:00Z"
        payload["backup_restore"]["restore_duration_seconds"] = 10
        del payload["load"]["scenario_results"]["allow"]["p50_ms"]
        payload["load"]["scenario_results"]["allow"]["status_counts"] = {"200": 99}
        payload["load"]["cloudwatch_windows"]["before"] = False

        errors = evidence.validate_evidence(payload)

        self.assertIn("signed must be true", errors)
        self.assertIn("audit export must be generated before the restore drill starts", errors)
        self.assertIn("restore_duration_seconds must match the restore timestamps", errors)
        self.assertIn("release.rds_instances.agent must be an RDS ARN when agent persistence is in scope", errors)
        self.assertIn("backup_restore.agent_database must be an object when agent persistence is in scope", errors)
        self.assertIn("load.scenario_results.allow.p50_ms must be numeric", errors)
        self.assertIn("load.scenario_results.allow.status_counts must sum to requests", errors)
        self.assertIn("cloudwatch_windows failed: before", errors)


if __name__ == "__main__":
    unittest.main()

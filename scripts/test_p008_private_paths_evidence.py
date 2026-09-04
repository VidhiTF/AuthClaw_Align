import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import p008_private_paths_evidence as p008


def endpoint() -> dict:
    return {
        "state": "available",
        "private_dns": True,
        "dns_resolves_to_endpoint_enis": True,
        "explicit_policy": True,
        "tls_deny": True,
        "availability_zone_count": 2,
    }


GOOD = {
    "deployment": {
        "account_id": "123456789012",
        "environment": "staging",
        "audit_transport": "kafka",
        "region": "us-east-1",
        "source_commit": "0123456789abcdef",
        "started_at": "2026-09-03T10:00:00Z",
        "completed_at": "2026-09-03T10:30:00Z",
    },
    "terraform_plan": {
        "reviewed": True,
        "applied_from_saved_plan": True,
        "replacement_resource_types": [],
        "plan_artifact": "s3://evidence/p008/plan.json",
        "reviewer": "platform-owner",
    },
    "endpoints": {
        "interface": {name: endpoint() for name in p008.ALWAYS_ON_INTERFACE_ENDPOINTS},
        "gateway": {
            "s3": {
                "state": "available",
                "all_private_route_tables": True,
                "route_verified": True,
                "explicit_policy": True,
                "tls_deny": True,
            }
        },
    },
    "task_probes": {
        "image_pull": True,
        "secret_injection": True,
        "cloudwatch_logs": True,
        "kms": True,
        "s3": True,
        "sts": True,
        "sqs": "not_selected",
        "no_static_aws_credentials": True,
        "regional_sts": True,
    },
    "nat_outage": {
        "approved": True,
        "routes_unavailable_during_probes": True,
        "routes_restored": True,
        "restore_verified": True,
        "change_ticket": "CHG-1001",
        "disabled_at": "2026-09-03T10:05:00Z",
        "restored_at": "2026-09-03T10:20:00Z",
    },
    "denial_tests": {name: True for name in p008.DENIAL_TARGETS},
    "flow_logs": {
        "covered_calls_avoided_nat": True,
        "unexplained_public_aws_destinations": [],
        "query_artifact": "s3://evidence/p008/flow-logs.json",
    },
    "rollback": {
        "rehearsed": True,
        "services_stable": True,
        "task_definitions_verified": True,
        "artifact": "s3://evidence/p008/rollback.json",
    },
    "artifacts": {
        "endpoint_inventory": "s3://evidence/p008/endpoints.json",
        "task_probes": "s3://evidence/p008/task-probes.json",
        "denial_tests": "s3://evidence/p008/denials.json",
        "nat_route_snapshot": "s3://evidence/p008/routes.json",
        "service_logs": "s3://evidence/p008/service-logs.json",
    },
    "approvals": {
        "security": {"name": "security-owner", "ticket": "SEC-1001", "approved_at": "2026-09-03T11:00:00Z"},
        "platform": {"name": "platform-owner", "ticket": "PLAT-1001", "approved_at": "2026-09-03T11:05:00Z"},
    },
}


class P008EvidenceTests(unittest.TestCase):
    def test_accepts_complete_kafka_evidence(self) -> None:
        self.assertEqual(p008.validate_evidence(copy.deepcopy(GOOD), audit_transport="kafka"), [])

    def test_accepts_complete_sqs_evidence(self) -> None:
        payload = copy.deepcopy(GOOD)
        payload["deployment"]["audit_transport"] = "sqs_fifo"
        payload["endpoints"]["interface"]["sqs"] = endpoint()
        payload["task_probes"]["sqs"] = True
        payload["denial_tests"]["sqs_queue"] = True
        self.assertEqual(p008.validate_evidence(payload, audit_transport="sqs_fifo"), [])

    def test_rejects_nat_not_restored_and_unexplained_egress(self) -> None:
        payload = copy.deepcopy(GOOD)
        payload["nat_outage"]["routes_restored"] = False
        payload["flow_logs"]["unexplained_public_aws_destinations"] = ["52.0.0.1"]
        errors = p008.validate_evidence(payload, audit_transport="kafka")
        self.assertIn("nat_outage.routes_restored must be true", errors)
        self.assertIn("flow_logs.unexplained_public_aws_destinations must be an empty list", errors)

    def test_rejects_missing_sts_and_foundation_replacement(self) -> None:
        payload = copy.deepcopy(GOOD)
        del payload["endpoints"]["interface"]["sts"]
        payload["terraform_plan"]["replacement_resource_types"] = ["aws_nat_gateway", "aws_vpc_endpoint"]
        errors = p008.validate_evidence(payload, audit_transport="kafka")
        self.assertTrue(any("interface endpoint set" in error for error in errors))
        self.assertIn("terraform plan replaces protected resources: aws_nat_gateway", errors)

    def test_rejects_sqs_evidence_for_kafka_and_missing_denial(self) -> None:
        payload = copy.deepcopy(GOOD)
        payload["task_probes"]["sqs"] = True
        payload["denial_tests"]["kms_key"] = False
        errors = p008.validate_evidence(payload, audit_transport="kafka")
        self.assertIn('task_probes.sqs must be "not_selected" for kafka', errors)
        self.assertIn("denial_tests.kms_key must be true", errors)

    def test_rejects_placeholders_transport_mismatch_and_bad_time_order(self) -> None:
        payload = copy.deepcopy(GOOD)
        payload["deployment"]["audit_transport"] = "sqs_fifo"
        payload["terraform_plan"]["reviewer"] = "replace-with-reviewer"
        payload["nat_outage"]["restored_at"] = "2026-09-03T09:59:00Z"
        errors = p008.validate_evidence(payload, audit_transport="kafka")
        self.assertIn("deployment.audit_transport must match --audit-transport", errors)
        self.assertIn("terraform_plan.reviewer must not contain placeholder evidence", errors)
        self.assertIn("nat_outage.restored_at must not precede nat_outage.disabled_at", errors)


if __name__ == "__main__":
    unittest.main()

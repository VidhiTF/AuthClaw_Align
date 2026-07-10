import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import compliance_hardening_evidence as hardening


GOOD = {
    "release_id": "release-2026-07-08",
    "generated_at": "2026-07-08T12:00:00Z",
    "ci_gates": {
        "codeql_sast": True,
        "python_dependency_audit": True,
        "node_dependency_audit": True,
        "go_vulnerability_audit": True,
        "secret_scan": True,
        "iac_scan": True,
        "container_scan": True,
    },
    "external_pentest": {
        "performed_by_external_vendor": True,
        "report_reference": "pentest/AuthClaw-External-Pentest-2026Q3.pdf",
        "completed_at": "2026-07-08T11:30:00Z",
        "open_critical_findings": 0,
        "open_high_findings": 0,
        "open_medium_findings": 0,
        "retest_passed": True,
    },
    "security_runbooks": {
        "incident_response": "infra/security/COMPLIANCE_HARDENING_RUNBOOK.md#incident-response",
        "vulnerability_management": "infra/security/COMPLIANCE_HARDENING_RUNBOOK.md#vulnerability-management",
        "access_review": "infra/security/COMPLIANCE_HARDENING_RUNBOOK.md#access-review",
        "backup_restore": "infra/security/COMPLIANCE_HARDENING_RUNBOOK.md#backup-and-restore",
        "key_rotation": "infra/security/COMPLIANCE_HARDENING_RUNBOOK.md#key-rotation",
    },
    "soc2_evidence": {
        "automated_collection_enabled": True,
        "controls": {
            "CC6.1": ["github-codeql", "access-review"],
            "CC6.6": ["gateway-contract-tests"],
            "CC7.1": ["trivy-fs", "gitleaks"],
            "CC7.2": ["red-team-run"],
            "CC7.3": ["findings-fix-cycle"],
            "A1.2": ["ha-failover-proof"],
        },
    },
    "control_evidence_pipeline": {
        "traceability_links_created": True,
        "mapped_controls": 6,
        "evidence_records": 12,
        "export_verified": True,
    },
    "red_team_thresholds": {
        "probe_count": 4,
        "failed_critical": 0,
        "failed_high": 0,
        "max_risk_score": 0,
        "latest_run_reference": "redteam-2026-07-08",
    },
    "audit_ready_release_checklist": {
        "external_pentest_closed": True,
        "security_gates_green": True,
        "soc2_evidence_complete": True,
        "control_traceability_complete": True,
        "red_team_thresholds_passed": True,
        "audit_export_verified": True,
        "release_owner_approved": True,
    },
}


class ComplianceHardeningEvidenceTests(unittest.TestCase):
    def test_accepts_complete_release_evidence(self) -> None:
        self.assertEqual(hardening.validate_evidence(copy.deepcopy(GOOD)), [])

    def test_rejects_open_pentest_findings(self) -> None:
        payload = copy.deepcopy(GOOD)
        payload["external_pentest"]["open_high_findings"] = 1

        self.assertIn("open_high_findings 1 exceeds 0", hardening.validate_evidence(payload))

    def test_rejects_missing_security_gate_and_soc2_control(self) -> None:
        payload = copy.deepcopy(GOOD)
        payload["ci_gates"]["container_scan"] = False
        payload["soc2_evidence"]["controls"]["CC7.2"] = []

        result = hardening.validate_evidence(payload)

        self.assertIn("container_scan must be true", result)
        self.assertIn("soc2_evidence.controls.CC7.2 must have evidence references", result)

    def test_rejects_red_team_threshold_failure(self) -> None:
        payload = copy.deepcopy(GOOD)
        payload["red_team_thresholds"]["failed_critical"] = 1
        payload["red_team_thresholds"]["max_risk_score"] = 0.75

        result = hardening.validate_evidence(payload)

        self.assertIn("failed_critical 1 exceeds 0", result)
        self.assertIn("max_risk_score 0.75 exceeds 0.0", result)


if __name__ == "__main__":
    unittest.main()

"""A failed post-mutation verification still requires the original rollback copy."""

import unittest
from unittest.mock import patch

from app.orchestrator.connectors import DocumentScanner
from app.orchestrator.graph import execute_remediation, rollback_remediation, verify_results
from tests.test_remediation_connector import FakeS3


class VerificationMismatchS3(FakeS3):
    def put_object(self, **kwargs):
        result = super().put_object(**kwargs)
        if (kwargs.get("Metadata") or {}).get("authclaw-remediated"):
            self.objects[kwargs["Key"]]["Body"] += b" unexpected change"
        return result


class VerificationReadFailureS3(FakeS3):
    def get_object(self, **kwargs):
        if (self.objects[kwargs["Key"]].get("Metadata") or {}).get("authclaw-remediated"):
            raise OSError("verification read unavailable")
        return super().get_object(**kwargs)


class RemediationFailureRollbackTests(unittest.TestCase):
    def test_failed_verification_rolls_back_without_retrying_mutation(self):
        self._assert_rollback(VerificationMismatchS3())

    def test_verification_read_error_preserves_rollback(self):
        self._assert_rollback(VerificationReadFailureS3())

    def _assert_rollback(self, s3):
        scanner = DocumentScanner()
        scanner.bucket = "approved-bucket"
        scanner.s3_client = s3
        original = scanner.s3_client.objects["tenant-a/doc.txt"]["Body"]
        plan = scanner.build_remediation_plan("tenant-a/doc.txt", "EMAIL_ADDRESS")
        state = {
            "workflow_id": "workflow-1",
            "tenant_id": "tenant-a",
            "remediation_plan": [{"finding_control": "tenant-a/doc.txt", **plan}],
        }

        with patch("app.orchestrator.connectors.DocumentScanner", return_value=scanner):
            executed = execute_remediation(state)
            self.assertEqual(executed["remediation_actions"][0]["status"], "FAILED")
            verified = verify_results(executed)
            self.assertEqual(verified["current_state"], "ROLLBACK_REMEDIATION")
            rolled_back = rollback_remediation(verified)

        self.assertEqual(rolled_back["rollback_result"]["rollback_successful"], 1)
        self.assertEqual(scanner.s3_client.objects["tenant-a/doc.txt"]["Body"], original)
        self.assertEqual(rolled_back["remediation_actions"][0]["attempts"], 1)

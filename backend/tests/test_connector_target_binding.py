"""An approved S3 target must survive connector configuration changes safely."""

import unittest

from app.orchestrator.connectors import DocumentScanner
from tests.test_remediation_connector import FakeS3


class ConnectorTargetBindingTests(unittest.TestCase):
    def setUp(self):
        self.scanner = DocumentScanner()
        self.scanner.bucket = "approved-bucket"
        self.scanner.s3_client = FakeS3()

    def test_apply_rejects_changed_bucket_without_writing(self):
        plan = self.scanner.build_remediation_plan("tenant-a/doc.txt", "EMAIL_ADDRESS")
        self.scanner.bucket = "different-bucket"

        with self.assertRaisesRegex(RuntimeError, "bucket"):
            self.scanner.execute_remediation("workflow-1", "action-1", plan)

        self.assertEqual(self.scanner.s3_client.version, 1)

    def test_apply_rejects_missing_approved_bucket(self):
        plan = self.scanner.build_remediation_plan("tenant-a/doc.txt", "EMAIL_ADDRESS")
        del plan["target"]["bucket"]

        with self.assertRaisesRegex(RuntimeError, "bucket"):
            self.scanner.execute_remediation("workflow-1", "action-1", plan)

        self.assertEqual(self.scanner.s3_client.version, 1)

    def test_rollback_rejects_changed_bucket_without_writing(self):
        plan = self.scanner.build_remediation_plan("tenant-a/doc.txt", "EMAIL_ADDRESS")
        result = self.scanner.execute_remediation("workflow-1", "action-1", plan)
        writes_before_rollback = self.scanner.s3_client.version
        self.scanner.bucket = "different-bucket"

        with self.assertRaisesRegex(RuntimeError, "bucket"):
            self.scanner.rollback_remediation({"rollback_ref": result["rollback_ref"]})

        self.assertEqual(self.scanner.s3_client.version, writes_before_rollback)

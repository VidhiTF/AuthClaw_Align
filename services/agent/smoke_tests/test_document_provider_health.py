import os
import unittest
from unittest.mock import MagicMock, patch

from document_processing import orchestrator
from services.tenant_context import tenant_context


class DocumentProviderHealthTests(unittest.TestCase):
    def test_configured_provider_outage_is_degraded(self):
        for status, payload in ((503, {}), (200, {"candidates": [{"content": {"parts": [{"text": "{}"}]}}]})):
            with self.subTest(status=status):
                response = MagicMock(status_code=status)
                response.json.return_value = payload
                connection = MagicMock()
                connection.execute.return_value.fetchone.return_value = (1,)
                database = MagicMock()
                database.connect.return_value.__enter__.return_value = connection
                text = "mfa rbac audit log retention consent erase patient ephi credit card routing"

                with tenant_context(7), patch.dict(os.environ, {
                        "GOOGLE_API_KEY": "configured-key", "GOOGLE_API_URL": "http://provider.invalid"}), \
                        patch.object(orchestrator, "engine", database), \
                        patch.object(orchestrator, "extract_document_text", return_value=text), \
                        patch.object(orchestrator, "extract_file_metadata", return_value={}), \
                        patch.object(orchestrator, "split_text_into_chunks", return_value=[]), \
                        patch.object(orchestrator, "scan_text_for_sensitive_data", return_value=[]), \
                        patch.object(orchestrator, "admit_provider_call"), \
                        patch.object(orchestrator, "create_document_audit"), \
                        patch.object(orchestrator.requests, "post", return_value=response), \
                        patch("rag.vector_store.save_document_chunks"), \
                        patch("document_processing.drift.record_compliance_snapshot"):
                    result = orchestrator.run_document_scan_pipeline(1, b"document", "policy.txt", tenant_id=7)

                self.assertEqual(result["status"], "completed")
                self.assertEqual(result["health"], "degraded")
                self.assertEqual(result["provider_review"], {"status": "unavailable"})


if __name__ == "__main__":
    unittest.main()

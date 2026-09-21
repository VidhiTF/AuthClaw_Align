import os
import json
import unittest
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

from document_processing import orchestrator
from services.quota_service import QuotaUnavailable
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

    def test_extraction_and_indexing_failures_are_degraded(self):
        for filename, contents, extraction, index_error, failed_stage, raises in (
                ("broken.pdf", b"not a pdf", None, None, "extraction", False),
                ("broken.xlsx", b"not excel", None, None, "extraction", False),
                ("policy.txt", b"policy", "policy", RuntimeError("index unavailable"), "indexing", False),
                ("quota.txt", b"policy", "policy", QuotaUnavailable("quota unavailable"), "indexing", True)):
            with self.subTest(stage=failed_stage):
                connection = MagicMock()
                connection.execute.return_value.fetchone.return_value = (1,)
                database = MagicMock()
                database.connect.return_value.__enter__.return_value = connection
                patches = [
                    patch.object(orchestrator, "engine", database),
                    patch.object(orchestrator, "extract_file_metadata", return_value={}),
                    patch.object(orchestrator, "split_text_into_chunks", return_value=[]),
                    patch.object(orchestrator, "scan_text_for_sensitive_data", return_value=[]),
                    patch.object(orchestrator, "create_document_audit"),
                    patch.object(orchestrator, "create_approval"),
                    patch("rag.vector_store.save_document_chunks", side_effect=index_error),
                    patch("services.event_pipeline.EventPipeline.record_event", return_value="alert-1"),
                    patch("services.event_pipeline.EventPipeline.deliver_event", return_value={"status": "delivered"}),
                ]
                if extraction is not None:
                    patches.append(patch.object(orchestrator, "extract_document_text", return_value=extraction))
                with tenant_context(7), patch.dict(os.environ, {"GOOGLE_API_KEY": ""}, clear=False), ExitStack() as stack:
                    for operation in patches:
                        stack.enter_context(operation)
                    if raises:
                        with self.assertRaises(QuotaUnavailable):
                            orchestrator.run_document_scan_pipeline(1, contents, filename, tenant_id=7)
                    else:
                        result = orchestrator.run_document_scan_pipeline(1, contents, filename, tenant_id=7)

                if not raises:
                    self.assertEqual(result["health"], "degraded")
                    self.assertEqual(result[failed_stage], {"status": "unavailable"})
                    outputs = json.loads(next(call.args[1]["outputs"] for call in connection.execute.call_args_list
                                              if isinstance(call.args[1], dict) and "outputs" in call.args[1]))
                    self.assertEqual(outputs[failed_stage], {"status": "unavailable"})
                if failed_stage == "indexing":
                    self.assertTrue(any("status = 'unavailable'" in str(call.args[0])
                                        for call in connection.execute.call_args_list))

    def test_empty_document_is_not_applicable(self):
        connection = MagicMock()
        connection.execute.return_value.fetchone.return_value = (1,)
        database = MagicMock()
        database.connect.return_value.__enter__.return_value = connection
        with tenant_context(7), patch.dict(os.environ, {"GOOGLE_API_KEY": ""}, clear=False), \
                patch.object(orchestrator, "engine", database), \
                patch.object(orchestrator, "extract_file_metadata", return_value={}), \
                patch.object(orchestrator, "scan_text_for_sensitive_data", return_value=[]), \
                patch.object(orchestrator, "create_document_audit"), \
                patch.object(orchestrator, "create_approval"), \
                patch("rag.vector_store.save_document_chunks") as save_chunks, \
                patch("services.event_pipeline.EventPipeline.record_event", return_value="alert-1"), \
                patch("services.event_pipeline.EventPipeline.deliver_event", return_value={"status": "delivered"}), \
                patch("document_processing.drift.record_compliance_snapshot"):
            result = orchestrator.run_document_scan_pipeline(1, b"", "empty.txt", tenant_id=7)

        self.assertEqual(result["health"], "not_applicable")
        self.assertEqual(result["extraction"], {"status": "not_applicable"})
        self.assertEqual(result["indexing"], {"status": "not_applicable"})
        save_chunks.assert_not_called()


if __name__ == "__main__":
    unittest.main()

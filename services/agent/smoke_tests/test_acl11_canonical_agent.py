import unittest

from services.canonical_agent_service import (
    CanonicalAgentService,
    build_agent_execution_context,
)


class FakeRemediationRuntime:
    def create_plan(self, tenant_id, finding_id):
        return {
            "id": 17,
            "tenant_id": tenant_id,
            "finding_id": finding_id,
            "status": "planned",
        }


class ACL11CanonicalAgentSmokeTests(unittest.TestCase):
    def setUp(self):
        self.service = CanonicalAgentService(
            rag_retriever=lambda query: f"context for {query}",
            remediation_runtime_factory=FakeRemediationRuntime,
        )

    def test_rag_execution_preserves_tenant_and_correlation_context(self):
        result = self.service.execute_rag(
            message="GDPR retention",
            tenant_id=42,
            correlation_id="corr-rag-1",
        )
        self.assertEqual(result["tenant_id"], 42)
        self.assertEqual(result["correlation_id"], "corr-rag-1")
        self.assertIn("GDPR retention", result["data"]["context"])

    def test_remediation_plan_is_tenant_scoped(self):
        result = self.service.create_remediation_plan(
            finding_id=9,
            tenant_id=42,
            correlation_id="corr-plan-1",
        )
        self.assertEqual(result["data"]["plan"]["tenant_id"], 42)
        self.assertEqual(result["data"]["plan"]["finding_id"], 9)
        self.assertEqual(result["correlation_id"], "corr-plan-1")

    def test_chat_response_uses_the_canonical_envelope(self):
        result = self.service.format_chat(
            formatted_result={"response": "ok", "request_id": "req-1"},
            tenant_id=42,
            correlation_id="corr-chat-1",
        )
        self.assertEqual(result["api_version"], "v1")
        self.assertEqual(result["operation"], "chat")
        self.assertEqual(result["correlation_id"], "corr-chat-1")

    def test_graph_context_contains_tenant_and_correlation_identifiers(self):
        context = build_agent_execution_context(
            tenant_id=42,
            request_id="req-chat-1",
            correlation_id="corr-chat-1",
            session_id=None,
        )
        self.assertEqual(context["tenant_id"], 42)
        self.assertEqual(context["request_id"], "req-chat-1")
        self.assertEqual(context["correlation_id"], "corr-chat-1")
        self.assertEqual(context["session_id"], "session-req-chat-1")

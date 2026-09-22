"""Verify metadata survives real LangGraph state boundaries."""

import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

from langgraph.graph import END, StateGraph

from state import AuthState, GRAPH_STATE_CONTRACT


def load_node(name, dependencies):
    path = Path(__file__).resolve().parents[1] / "nodes" / f"{name}_node.py"
    spec = importlib.util.spec_from_file_location(f"metadata_{name}", path)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, dependencies):
        spec.loader.exec_module(module)
    return getattr(module, f"{name}_node")


def one_node_graph(node):
    workflow = StateGraph(AuthState)
    workflow.add_node("node", node)
    workflow.set_entry_point("node")
    workflow.add_edge("node", END)
    return workflow.compile()


class GraphMetadataContractTests(unittest.TestCase):
    def test_inventory_only_references_declared_state(self):
        declared = set(AuthState.__annotations__)
        inventoried = set().union(*GRAPH_STATE_CONTRACT.values())
        self.assertEqual(set(), inventoried - declared)
        for required in {
            "username", "requester_id", "approval_reason", "policy_versions", "audit_record_id",
            "original_request_id", "provider_status", "provider_error", "idempotency_key",
        }:
            self.assertIn(required, declared)
            self.assertIn(required, inventoried)

    def test_identity_and_metadata_reach_security_and_audit(self):
        observations = {}

        class SecurityAgent:
            def inspect_input(self, text, username, tenant_id):
                observations["security_username"] = username
                return types.SimpleNamespace(
                    approved=True, findings=[], sanitized_text=text,
                )

        class AuditAgent:
            def record(self, state):
                observations["audit_username"] = state["username"]
                observations["audit_original_request_id"] = state["original_request_id"]
                state["audit_record_id"] = 918
                return state

        dependencies = {
            "memory": types.SimpleNamespace(add_message=lambda *_: None),
            "services.security_agent": types.SimpleNamespace(SecurityAgent=SecurityAgent),
            "services.audit_agent": types.SimpleNamespace(AuditAgent=AuditAgent),
            "verify_audit": types.SimpleNamespace(log_agent_event=lambda **_: None),
        }
        redact = load_node("redact", dependencies)
        audit = load_node("audit", dependencies)

        def add_metadata(state):
            state.update({
                "approval_reason": "sensitive_data",
                "policy_versions": [{"policy": "pii", "version": 7}],
                "provider_status": "ok",
            })
            return state

        workflow = StateGraph(AuthState)
        workflow.add_node("redact", redact)
        workflow.add_node("metadata", add_metadata)
        workflow.add_node("audit", audit)
        workflow.set_entry_point("redact")
        workflow.add_edge("redact", "metadata")
        workflow.add_edge("metadata", "audit")
        workflow.add_edge("audit", END)
        result = workflow.compile().invoke({
            "message": "hello",
            "username": "signed-user@example.com",
            "requester_id": "oidc|signed-user",
            "tenant_id": 42,
            "original_request_id": "req-original",
        })

        self.assertEqual("signed-user@example.com", observations["security_username"])
        self.assertEqual("signed-user@example.com", observations["audit_username"])
        self.assertEqual("req-original", observations["audit_original_request_id"])
        self.assertEqual("sensitive_data", result["approval_reason"])
        self.assertEqual([{"policy": "pii", "version": 7}], result["policy_versions"])
        self.assertEqual(918, result["audit_record_id"])
        self.assertEqual("req-original", result["original_request_id"])

    def test_specific_approval_reasons_survive_boundary(self):
        approval = load_node("approval", {
            "approval_store": types.SimpleNamespace(
                create_approval=lambda **_: {"approval_id": "approval-1"},
            ),
        })
        graph = one_node_graph(approval)
        sensitive = graph.invoke({
            "message": "sensitive", "risk_level": "HIGH",
            "security_policy_action": "require_approval",
            "tenant_id": 42, "request_id": "request-sensitive",
            "requester_id": "oidc|requester",
        })
        policy = graph.invoke({
            "message": "policy", "risk_level": "HIGH",
            "policy_decision": "REQUIRE_APPROVAL",
            "tenant_id": 42, "request_id": "request-policy",
            "requester_id": "oidc|requester",
        })
        self.assertEqual("sensitive_data", sensitive["approval_reason"])
        self.assertEqual("policy_violation", policy["approval_reason"])

    def test_provider_failure_state_contains_no_raw_exception(self):
        llm = load_node("llm", {
            "memory": types.SimpleNamespace(get_history=lambda *_: []),
            "providers": types.SimpleNamespace(get_provider=lambda: None),
            "redaction": types.SimpleNamespace(stream_redact_sensitive_tokens=lambda stream, **_: stream),
            "verify_audit": types.SimpleNamespace(log_agent_event=lambda **_: None),
        })

        class BrokenProvider:
            def generate(self, _prompt):
                raise RuntimeError("secret token sk-never-expose")

        result = one_node_graph(llm).invoke({
            "message": "hello", "allowed": True,
            "provider_client": BrokenProvider(),
        })
        serialized = repr(result)
        self.assertEqual("offline_fallback", result["provider_status"])
        self.assertEqual(
            {"code": "provider_failure", "detail": "The provider request failed."},
            result["provider_error"],
        )
        self.assertNotIn("sk-never-expose", serialized)

    def test_approved_execution_identity_reaches_provider(self):
        llm = load_node("llm", {
            "memory": types.SimpleNamespace(get_history=lambda *_: []),
            "providers": types.SimpleNamespace(get_provider=lambda: None),
            "redaction": types.SimpleNamespace(stream_redact_sensitive_tokens=lambda stream, **_: stream),
            "verify_audit": types.SimpleNamespace(log_agent_event=lambda **_: None),
        })
        calls = []
        order = []

        class Provider:
            def generate(self, prompt, **kwargs):
                order.append("provider")
                calls.append((prompt, kwargs))
                return "ok"

        def pre_effect_check():
            order.append("fence")

        result = one_node_graph(llm).invoke({
            "message": "execute", "allowed": True,
            "provider_client": Provider(),
            "request_id": "approval-exec-operation-17",
            "idempotency_key": "operation-17",
            "pre_effect_check": pre_effect_check,
        })

        self.assertEqual(result["provider_status"], "ok")
        self.assertEqual(order, ["fence", "provider"])
        self.assertEqual(calls[0][1], {
            "idempotency_key": "operation-17",
            "request_id": "approval-exec-operation-17",
        })


if __name__ == "__main__":
    unittest.main()

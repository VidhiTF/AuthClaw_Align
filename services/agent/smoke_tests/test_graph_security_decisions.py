"""Exercise actual node boundaries and the production LangGraph state schema."""

import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

from langgraph.graph import StateGraph, END
from state import AuthState


def load_node(name, dependencies):
    path = Path(__file__).resolve().parents[1] / "nodes" / f"{name}_node.py"
    spec = importlib.util.spec_from_file_location(f"regression_{name}", path)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, dependencies):
        spec.loader.exec_module(module)
    return getattr(module, f"{name}_node")


class GraphSecurityDecisionTests(unittest.TestCase):
    def run_graph(self, security_action="allow", policy_action="ALLOW"):
        findings = [] if security_action == "allow" else [{
            "action": security_action, "policy_name": "Tenant security policy",
        }]
        security = types.SimpleNamespace(SecurityAgent=lambda: types.SimpleNamespace(
            inspect_input=lambda *_: types.SimpleNamespace(
                approved=security_action != "block", findings=findings,
                sanitized_text="Please process this record",
            ),
            classify_risk=lambda *_: "LOW",
        ))
        policy = types.SimpleNamespace(PolicyAgent=lambda: types.SimpleNamespace(
            evaluate=lambda *_, **__: types.SimpleNamespace(
                approved=policy_action == "ALLOW", policy_decision=policy_action,
                category="sensitive_data" if policy_action != "ALLOW" else "",
                reason="Tenant policy", violated_policies=[], policy_versions=[],
            ),
        ))
        dependencies = {
            "memory": types.SimpleNamespace(add_message=lambda *_: None),
            "verify_audit": types.SimpleNamespace(log_agent_event=lambda **_: None),
            "services.security_agent": security,
            "services.policy_agent": policy,
            "approval_store": types.SimpleNamespace(create_approval=lambda **_: {"approval_id": "test-approval"}),
        }
        workflow = StateGraph(AuthState)
        for name in ("redact", "policy", "risk", "approval"):
            workflow.add_node(name, load_node(name, dependencies))
        workflow.set_entry_point("redact")
        workflow.add_edge("redact", "policy")
        workflow.add_conditional_edges("policy", lambda state: "risk" if state.get("allowed", True) else END)
        workflow.add_edge("risk", "approval")
        workflow.add_edge("approval", END)
        return workflow.compile().invoke({"message": "Please process this record", "tenant_id": 42})

    def test_security_block_survives_node_boundary(self):
        result = self.run_graph(security_action="block")
        self.assertFalse(result["allowed"])
        self.assertNotEqual(result.get("approval_status"), "APPROVED")

    def test_security_approval_survives_low_keyword_risk(self):
        result = self.run_graph(security_action="require_approval")
        self.assertEqual(result["approval_status"], "PENDING_APPROVAL")
        self.assertEqual(result["approval_id"], "test-approval")

    def test_policy_approval_survives_low_keyword_risk(self):
        result = self.run_graph(policy_action="REQUIRE_APPROVAL")
        self.assertEqual(result["approval_status"], "PENDING_APPROVAL")
        self.assertEqual(result["approval_id"], "test-approval")

    def test_allowed_request_still_auto_approves(self):
        self.assertEqual(self.run_graph()["approval_status"], "APPROVED")


if __name__ == "__main__":
    unittest.main()

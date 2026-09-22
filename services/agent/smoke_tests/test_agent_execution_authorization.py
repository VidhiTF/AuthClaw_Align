import unittest

from services.execution_auth import authorize_agent_operation
from services.rbac_matrix import agent_operation_allowed, resolve_rule, role_allowed


class AgentExecutionAuthorizationTests(unittest.TestCase):
    path = "/api/v1/agent/executions"

    def test_canonical_route_is_mapped(self):
        rule = resolve_rule("POST", self.path)
        self.assertIsNotNone(rule)
        self.assertEqual(rule.permission, "agent:execute")
        self.assertTrue(role_allowed("owner", "POST", self.path))
        self.assertTrue(role_allowed("Super Admin", "POST", self.path))

    def test_operations_use_least_privilege(self):
        expectations = {
            "owner": (True, True, True),
            "admin": (True, True, True),
            "compliance_officer": (True, False, False),
            "developer": (True, True, True),
            "operator": (True, True, True),
            "viewer": (True, False, False),
            "auditor": (True, False, False),
        }
        for role, expected in expectations.items():
            with self.subTest(role=role):
                actual = tuple(
                    agent_operation_allowed(role, operation)
                    for operation in ("chat", "rag", "remediation_plan")
                )
                self.assertEqual(actual, expected)

    def test_unknown_role_and_operation_are_denied(self):
        self.assertFalse(agent_operation_allowed("root", "chat"))
        self.assertFalse(agent_operation_allowed("owner", "shell"))

    def test_authorized_identity_is_explicit(self):
        identity = authorize_agent_operation(
            {"role": "Security Admin", "sub": "user-17"},
            "remediation_plan",
            42,
        )
        self.assertEqual(identity.tenant_id, 42)
        self.assertEqual(identity.user_id, "user-17")
        self.assertEqual(identity.role, "tenant_administrator")

    def test_missing_identity_and_denied_operation_fail_closed(self):
        with self.assertRaises(ValueError):
            authorize_agent_operation({"role": "owner"}, "chat", 42)
        with self.assertRaises(PermissionError):
            authorize_agent_operation(
                {"role": "viewer", "sub": "user-17"},
                "remediation_plan",
                42,
            )


if __name__ == "__main__":
    unittest.main()

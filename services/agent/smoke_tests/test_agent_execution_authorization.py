import unittest
from contextlib import contextmanager
from unittest.mock import patch

from services.execution_auth import authorize_agent_operation
from services.rbac_matrix import agent_operation_allowed, resolve_rule, role_allowed
from services.tenant_context import get_current_request_id


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
            "compliance_officer": (True, True, True),
            "developer": (True, False, False),
            "operator": (True, False, False),
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
        self.assertEqual(identity.role, "admin")

    def test_missing_identity_and_denied_operation_fail_closed(self):
        with self.assertRaises(ValueError):
            authorize_agent_operation({"role": "owner"}, "chat", 42)
        with self.assertRaises(PermissionError):
            authorize_agent_operation(
                {"role": "viewer", "sub": "user-17"},
                "remediation_plan",
                42,
            )

    def test_approval_mfa_database_context_retains_request_id(self):
        import main

        class Result:
            def mappings(self):
                return self

            def first(self):
                self.assert_request_context()
                return {
                    "id": 17,
                    "totp_secret": "encrypted",
                    "mfa_last_totp_counter": None,
                    "mfa_failed_attempts": 0,
                    "mfa_locked_until": None,
                }

            @staticmethod
            def assert_request_context():
                assert get_current_request_id() == "request-17"

        class Connection:
            def execute(self, statement, parameters):
                if str(statement).lstrip().upper().startswith("SELECT"):
                    return Result()
                self.updated = parameters
                return Result()

        class Engine:
            @contextmanager
            def begin(self):
                yield Connection()

        with (
            patch("database.engine", Engine()),
            patch.object(main, "decrypt_totp_secret", return_value="secret"),
            patch.object(main, "verify_totp_token_with_counter", return_value=123),
        ):
            counter = main._consume_approval_totp_counter(
                {"tenant_id": "42", "request_id": "request-17"},
                {"user_id": "17"},
                "654321",
            )

        self.assertEqual(counter, 123)

    def test_approval_mfa_lock_deadline_is_persisted_as_utc_timestamp(self):
        import main

        updates = []

        class Result:
            def mappings(self):
                return self

            def first(self):
                return {
                    "id": 17,
                    "totp_secret": "encrypted",
                    "mfa_last_totp_counter": 122,
                    "mfa_failed_attempts": 4,
                    "mfa_locked_until": None,
                }

        class Connection:
            def execute(self, statement, parameters):
                if str(statement).lstrip().upper().startswith("SELECT"):
                    return Result()
                updates.append(parameters)
                return Result()

        class Engine:
            @contextmanager
            def begin(self):
                yield Connection()

        with (
            patch("database.engine", Engine()),
            patch.object(main, "decrypt_totp_secret", return_value="secret"),
            patch.object(main, "verify_totp_token_with_counter", return_value=None),
            self.assertRaises(main.HTTPException),
        ):
            main._consume_approval_totp_counter(
                {"tenant_id": "42", "request_id": "request-17"},
                {"user_id": "17"},
                "000000",
            )

        self.assertEqual(updates[0]["attempts"], 0)
        self.assertIsNotNone(updates[0]["locked_until"])
        self.assertIsNone(updates[0]["locked_until"].tzinfo)


if __name__ == "__main__":
    unittest.main()

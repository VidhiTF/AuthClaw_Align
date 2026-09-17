import asyncio
import os
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock, patch

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

    def test_approval_actor_uses_immutable_subject_not_email_alias(self):
        import main

        actor = main.approval_actor_from_payload({
            "sub": "oidc|opaque-17",
            "email": "alice@example.com",
        })

        self.assertEqual(actor, "oidc|opaque-17")

    def test_approval_actor_rejects_missing_immutable_subject(self):
        import main

        with self.assertRaises(main.HTTPException) as raised:
            main.approval_actor_from_payload({"email": "alice@example.com"})

        self.assertEqual(raised.exception.status_code, 401)

    def test_self_approval_rejects_subject_even_when_email_differs(self):
        import main

        record = {
            "approval_id": "approval-17",
            "request_id": "request-17",
            "correlation_id": "correlation-17",
            "tenant_id": 42,
            "status": "pending",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "requested_by": "oidc|opaque-17",
            "metadata": {"requested_by": "oidc|different-user"},
        }
        audit = Mock()
        with (
            patch.object(main, "get_approval", return_value=record),
            patch.object(
                main,
                "_approval_authenticated_payload",
                return_value={
                    "tenant_id": 42,
                    "sub": "oidc|opaque-17",
                    "email": "alice@example.com",
                },
            ),
            patch.object(main, "get_policy", return_value={
                "approval": {"require_mfa": True, "require_separate_approver": True},
            }),
            patch.object(main, "append_approval_audit", audit),
            self.assertRaises(main.HTTPException) as raised,
        ):
            asyncio.run(main.approve_request("approval-17", object()))

        self.assertEqual(raised.exception.status_code, 403)
        self.assertEqual(record["status"], "pending")
        self.assertEqual(audit.call_args.kwargs["action"], "self_approval_rejected")

    def test_historical_email_requester_alias_cannot_self_approve(self):
        import main

        record = {
            "approval_id": "approval-email-alias",
            "request_id": "request-email-alias",
            "correlation_id": "correlation-email-alias",
            "tenant_id": 42,
            "status": "pending",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "metadata": {"requested_by": "alice@example.com"},
        }
        with (
            patch.object(main, "get_approval", return_value=record),
            patch.object(main, "_approval_authenticated_payload", return_value={
                "tenant_id": 42,
                "sub": "oidc|opaque-17",
                "email": "alice@example.com",
            }),
            patch.object(main, "get_policy", return_value={
                "approval": {"require_mfa": True, "require_separate_approver": True},
            }),
            patch.object(main, "append_approval_audit"),
            self.assertRaises(main.HTTPException) as raised,
        ):
            asyncio.run(main.approve_request("approval-email-alias", object()))

        self.assertEqual(raised.exception.status_code, 403)

    def test_distinct_canonical_approver_reaches_mfa_payload_processing(self):
        import main

        record = {
            "approval_id": "approval-distinct",
            "request_id": "request-distinct",
            "correlation_id": "correlation-distinct",
            "tenant_id": 42,
            "status": "pending",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "metadata": {"requested_by": "oidc|requester-17"},
        }
        reached_payload = RuntimeError("payload-processing-reached")
        with (
            patch.object(main, "get_approval", return_value=record),
            patch.object(main, "_approval_authenticated_payload", return_value={
                "tenant_id": 42,
                "sub": "oidc|approver-22",
                "email": "approver@example.com",
            }),
            patch.object(main, "get_policy", return_value={
                "approval": {"require_mfa": True, "require_separate_approver": True},
            }),
            patch.object(main, "parse_approval_action_payload", side_effect=reached_payload),
            self.assertRaisesRegex(RuntimeError, "payload-processing-reached"),
        ):
            asyncio.run(main.approve_request("approval-distinct", object()))

    def test_approval_tenant_context_must_exist_and_match_exactly(self):
        import main

        for record_tenant, actor_tenant in ((None, 42), (42, None), (42, 84)):
            with self.subTest(record_tenant=record_tenant, actor_tenant=actor_tenant):
                with self.assertRaises(main.HTTPException) as raised:
                    main.ensure_approval_tenant_access(
                        {"tenant_id": record_tenant},
                        {"tenant_id": actor_tenant},
                    )
                self.assertEqual(raised.exception.status_code, 404)

        main.ensure_approval_tenant_access({"tenant_id": 42}, {"tenant_id": 42})

    def test_approval_missing_requester_fails_before_mfa(self):
        import main

        record = {
            "approval_id": "approval-18",
            "request_id": "request-18",
            "correlation_id": "correlation-18",
            "tenant_id": 42,
            "status": "pending",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "metadata": {},
        }
        audit = Mock()
        with (
            patch.object(main, "get_approval", return_value=record),
            patch.object(
                main,
                "_approval_authenticated_payload",
                return_value={"tenant_id": 42, "sub": "oidc|approver-22"},
            ),
            patch.object(main, "get_policy", return_value={
                "approval": {"require_mfa": True, "require_separate_approver": True},
            }),
            patch.object(main, "append_approval_audit", audit),
            patch.object(main, "_verify_approval_stage_mfa") as verify_mfa,
            self.assertRaises(main.HTTPException) as raised,
        ):
            asyncio.run(main.approve_request("approval-18", object()))

        self.assertEqual(raised.exception.status_code, 403)
        self.assertEqual(record["status"], "pending")
        verify_mfa.assert_not_called()
        self.assertEqual(audit.call_args.kwargs["action"], "approval_identity_missing")

    def test_create_approval_requires_requester_tenant_and_request_context(self):
        import approval_store

        required = {
            "requested_by": "oidc|opaque-17",
            "tenant_id": 42,
            "request_id": "request-17",
        }
        for missing in required:
            kwargs = dict(required)
            kwargs[missing] = None
            with (
                self.subTest(missing=missing),
                patch.object(approval_store, "_persist_record"),
                patch.object(approval_store, "append_approval_audit"),
                self.assertRaises(ValueError),
            ):
                approval_store.create_approval(
                    query="Delete sensitive records",
                    risk_level="HIGH",
                    **kwargs,
                )

    def test_created_approval_requester_is_immutable_and_authoritative(self):
        import approval_store

        with (
            patch.object(approval_store, "_persist_record"),
            patch.object(approval_store, "append_approval_audit"),
        ):
            record = approval_store.create_approval(
                query="Delete sensitive records",
                risk_level="HIGH",
                tenant_id=42,
                request_id="request-immutable",
                requested_by="oidc|requester-17",
            )

        record["metadata"]["requested_by"] = "oidc|different-user"
        self.assertEqual(record["requested_by"], "oidc|requester-17")
        with self.assertRaisesRegex(ValueError, "immutable"):
            record["requested_by"] = "oidc|different-user"
        with self.assertRaisesRegex(ValueError, "immutable"):
            record.update(requested_by="oidc|different-user")
        with self.assertRaisesRegex(ValueError, "immutable"):
            record.pop("requested_by")

    def test_requester_column_is_persisted_but_never_updated_on_conflict(self):
        import approval_store

        connection = Mock()
        engine = Mock()
        engine.connect.return_value.__enter__ = Mock(return_value=connection)
        engine.connect.return_value.__exit__ = Mock(return_value=False)
        with patch.object(approval_store, "engine", engine):
            approval_store._persist_record({"requested_by": "oidc|requester-17"})

        statement = str(connection.execute.call_args.args[0])
        parameters = connection.execute.call_args.args[1]
        self.assertIn("requested_by", statement)
        self.assertNotIn("requested_by = EXCLUDED.requested_by", statement)
        self.assertEqual(parameters["requested_by"], "oidc|requester-17")
        migrations = (
            Path(__file__).resolve().parents[1] / "database" / "migrations.py"
        ).read_text()
        self.assertIn(
            "ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS requested_by VARCHAR(255)",
            migrations,
        )

    def test_document_override_propagates_requester_tenant_and_request_context(self):
        from document_processing import orchestrator

        class Result:
            def __init__(self, row=None):
                self.row = row

            def fetchone(self):
                return self.row

        class Connection:
            def execute(self, statement, _parameters=None):
                sql = str(statement)
                if "FROM knowledge_documents" in sql:
                    return Result((71,))
                if "INSERT INTO document_scans" in sql:
                    return Result((81,))
                return Result()

            def commit(self):
                return None

        class Engine:
            @contextmanager
            def connect(self):
                yield Connection()

        create = Mock(return_value={"approval_id": "document-approval-17"})
        finding = {
            "finding_type": "Secret",
            "matched_pattern": "AWS_ACCESS_KEY",
            "matched_text": "redacted",
            "risk_level": "CRITICAL",
        }
        with (
            patch.object(orchestrator, "engine", Engine()),
            patch.object(orchestrator, "extract_document_text", return_value="sensitive document"),
            patch.object(orchestrator, "extract_file_metadata", return_value={}),
            patch.object(orchestrator, "split_text_into_chunks", return_value=["sensitive document"]),
            patch.object(orchestrator, "scan_text_for_sensitive_data", return_value=[finding]),
            patch.object(orchestrator, "create_document_audit"),
            patch.object(orchestrator, "create_approval", create),
            patch("rag.vector_store.save_document_chunks"),
            patch("document_processing.alerts.trigger_security_alert"),
            patch("document_processing.drift.record_compliance_snapshot"),
            patch.dict(os.environ, {"GOOGLE_API_KEY": "dummy"}),
        ):
            result = orchestrator.run_document_scan_pipeline(
                17,
                b"sensitive document",
                "payroll.pdf",
                tenant_id=42,
                request_id="request-17",
                requested_by="oidc|opaque-17",
            )

        self.assertEqual(result["status"], "pending_approval")
        self.assertEqual(create.call_args.kwargs["tenant_id"], 42)
        self.assertEqual(create.call_args.kwargs["request_id"], "request-17")
        self.assertEqual(create.call_args.kwargs["requested_by"], "oidc|opaque-17")
        self.assertEqual(create.call_args.kwargs["metadata"]["document_id"], 17)

    def test_manual_document_sync_propagates_authenticated_subject(self):
        import main

        with (
            patch.object(
                main,
                "optional_user_from_request",
                return_value={"sub": "oidc|manual-requester", "email": "manual@example.com"},
            ),
            patch(
                "document_processing.monitoring.trigger_manual_sync",
                return_value={"status": "success"},
            ) as trigger,
        ):
            result = main.sync_cloud_connectors(object())

        self.assertEqual(result, {"status": "success"})
        trigger.assert_called_once_with("oidc|manual-requester")

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

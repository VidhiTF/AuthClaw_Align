import asyncio
import copy
import hashlib
import json
import os
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

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

    def test_validated_api_key_has_unique_non_secret_service_identity(self):
        from services.gateway_service import GatewayService

        raw_key = "test-only-api-key"
        expected = f"api-key:{hashlib.sha256(raw_key.encode('utf-8')).hexdigest()}"
        service = GatewayService(graph=Mock(), resolve_tenant=Mock(), decode_jwt=Mock())

        self.assertEqual(service._requester_id_from_api_key(raw_key), expected)
        self.assertNotIn(raw_key, expected)

    def test_validated_api_key_principal_can_create_high_risk_approval(self):
        import main

        raw_key = "test-only-api-key"
        expected = f"api-key:{hashlib.sha256(raw_key.encode('utf-8')).hexdigest()}"
        request = SimpleNamespace(
            headers={"X-API-Key": raw_key},
            state=SimpleNamespace(verified_service_principal=None),
        )
        with patch.object(main, "resolve_tenant", return_value=42):
            self.assertEqual(main._tenant_id_from_request_headers(request), 42)

        principal = main.optional_user_from_request(request)
        self.assertEqual(principal["tenant_id"], 42)
        self.assertEqual(principal["role"], "owner")
        self.assertEqual(main.approval_actor_from_payload(principal), expected)
        self.assertEqual(request.state.quota_user_id, "service:tenant")
        self.assertTrue(principal["sub"].startswith("api-key:"))
        self.assertNotIn(raw_key, principal["sub"])

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

        engine = Mock()
        engine.begin.return_value.__enter__ = Mock(return_value=Mock())
        engine.begin.return_value.__exit__ = Mock(return_value=False)
        with (
            patch.object(approval_store, "engine", engine),
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
        engine.begin.return_value.__enter__ = Mock(return_value=connection)
        engine.begin.return_value.__exit__ = Mock(return_value=False)
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

    def test_already_approved_request_is_rejected_before_mfa_or_mutation(self):
        import main

        record = {
            "approval_id": "approval-resolved",
            "tenant_id": 42,
            "status": "approved",
        }
        with (
            patch.object(main, "get_approval", return_value=record),
            patch.object(
                main,
                "_approval_authenticated_payload",
                return_value={"tenant_id": 42, "sub": "oidc|checker-2"},
            ),
            patch.object(main, "_verify_approval_stage_mfa") as verify_mfa,
            patch.object(main, "approve_approval_atomic") as approve_atomic,
            self.assertRaises(main.HTTPException) as raised,
        ):
            asyncio.run(main.approve_request("approval-resolved", object()))

        self.assertEqual(raised.exception.status_code, 400)
        verify_mfa.assert_not_called()
        approve_atomic.assert_not_called()

    def test_atomic_approval_allows_exactly_one_concurrent_winner(self):
        import approval_store

        shared = {
            "approval_id": "approval-race",
            "request_id": "request-race",
            "correlation_id": "correlation-race",
            "tenant_id": 42,
            "status": "pending",
            "requested_by": "oidc|requester",
            "created_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "comments": "[]",
            "metadata": "{}",
            "reason": "high_risk",
        }
        audit_rows = []
        transaction_lock = threading.Lock()

        class Row:
            def __init__(self, mapping):
                self._mapping = mapping

        class Result:
            def __init__(self, row=None, scalar_value=None, rowcount=0):
                self._row = row
                self._scalar = scalar_value
                self.rowcount = rowcount

            def fetchone(self):
                return self._row

            def scalar(self):
                return self._scalar

        class Connection:
            def execute(self, statement, parameters):
                sql = " ".join(str(statement).split()).upper()
                if sql.startswith("UPDATE GATEWAY_APPROVALS SET STATUS = 'APPROVED'"):
                    if shared["status"] != "pending":
                        return Result(rowcount=0)
                    shared.update({
                        "status": "approved",
                        "approved_at": parameters["approved_at"],
                        "approved_by": parameters["approved_by"],
                        "mfa_verified": parameters["mfa_verified"],
                        "approval_mfa_verified": parameters["mfa_verified"],
                        "approval_mfa_binding_hash": parameters["binding_hash"],
                        "approval_mfa_counter": parameters["counter"],
                        "execution_expires_at": parameters["execution_expires_at"],
                        "last_action_at": parameters["approved_at"],
                    })
                    return Result(Row(copy.deepcopy(shared)), rowcount=1)
                if sql.startswith("UPDATE GATEWAY_APPROVALS SET STATUS = 'EXPIRED'"):
                    return Result(rowcount=0)
                if sql.startswith("SELECT STATUS FROM GATEWAY_APPROVALS"):
                    return Result(scalar_value=shared["status"])
                if sql.startswith("UPDATE GATEWAY_APPROVALS SET COMMENTS"):
                    shared["comments"] = parameters["comments"]
                    return Result(rowcount=1)
                if sql.startswith("INSERT INTO APPROVAL_AUDIT_EVENTS"):
                    audit_rows.append(dict(parameters))
                    return Result(rowcount=1)
                raise AssertionError(sql)

        class Engine:
            @contextmanager
            def begin(self):
                with transaction_lock:
                    yield Connection()

        winners = []
        conflicts = []

        def decide(approver, counter):
            try:
                winners.append(approval_store.approve_approval_atomic(
                    dict(shared),
                    approver=approver,
                    approved_at=approval_store.datetime.now(approval_store.timezone.utc),
                    mfa_verified=True,
                    mfa_binding_hash=f"binding-{counter}",
                    mfa_counter=counter,
                    execution_expires_at=approval_store.datetime.now(approval_store.timezone.utc),
                ))
            except approval_store.ApprovalStateConflict as exc:
                conflicts.append(exc)

        with (
            patch.object(approval_store, "engine", Engine()),
            patch.dict(approval_store._approvals, {}, clear=True),
        ):
            first = threading.Thread(target=decide, args=("oidc|checker-1", 101))
            second = threading.Thread(target=decide, args=("oidc|checker-2", 202))
            first.start()
            second.start()
            first.join()
            second.join()

        self.assertEqual(len(winners), 1)
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(len(audit_rows), 1)
        self.assertEqual(shared["approved_by"], winners[0]["approved_by"])

    def test_audit_failure_rolls_back_atomic_approval_and_does_not_cache(self):
        import approval_store

        shared = {
            "approval_id": "approval-audit-failure",
            "request_id": "request-audit-failure",
            "correlation_id": "correlation-audit-failure",
            "tenant_id": 42,
            "status": "pending",
            "requested_by": "oidc|requester",
            "created_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "comments": "[]",
            "metadata": "{}",
            "reason": "high_risk",
        }

        class Row:
            _mapping = shared

        class Result:
            rowcount = 1

            def fetchone(self):
                return Row()

        class Connection:
            def execute(self, statement, parameters):
                sql = " ".join(str(statement).split()).upper()
                if sql.startswith("UPDATE GATEWAY_APPROVALS SET STATUS = 'APPROVED'"):
                    shared["status"] = "approved"
                    return Result()
                if sql.startswith("INSERT INTO APPROVAL_AUDIT_EVENTS"):
                    raise RuntimeError("audit denied by RLS")
                return Result()

        class Engine:
            @contextmanager
            def begin(self):
                before = copy.deepcopy(shared)
                try:
                    yield Connection()
                except Exception:
                    shared.clear()
                    shared.update(before)
                    raise

        with (
            patch.object(approval_store, "engine", Engine()),
            patch.dict(approval_store._approvals, {}, clear=True),
            self.assertRaises(approval_store.ApprovalPersistenceError),
        ):
            approval_store.approve_approval_atomic(
                dict(shared),
                approver="oidc|checker",
                approved_at=approval_store.datetime.now(approval_store.timezone.utc),
                mfa_verified=True,
                mfa_binding_hash="binding",
                mfa_counter=303,
                execution_expires_at=approval_store.datetime.now(approval_store.timezone.utc),
            )

        self.assertEqual(shared["status"], "pending")
        self.assertNotIn("approval-audit-failure", approval_store._approvals)

    def test_approval_expiring_during_mfa_is_atomically_expired_and_audited(self):
        import approval_store

        shared = {
            "approval_id": "approval-expired-during-mfa",
            "request_id": "request-expired-during-mfa",
            "correlation_id": "correlation-expired-during-mfa",
            "tenant_id": 42,
            "status": "pending",
            "requested_by": "oidc|requester",
            "created_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2026-01-01T00:01:00+00:00",
            "comments": "[]",
            "metadata": "{}",
            "reason": "high_risk",
        }
        audit_rows = []

        class Row:
            @property
            def _mapping(self):
                return copy.deepcopy(shared)

        class Result:
            def __init__(self, row=None, rowcount=0):
                self._row = row
                self.rowcount = rowcount

            def fetchone(self):
                return self._row

        class Connection:
            def execute(self, statement, parameters):
                sql = " ".join(str(statement).split()).upper()
                if sql.startswith("UPDATE GATEWAY_APPROVALS SET STATUS = 'APPROVED'"):
                    return Result()
                if sql.startswith("UPDATE GATEWAY_APPROVALS SET STATUS = 'EXPIRED'"):
                    shared["status"] = "expired"
                    shared["last_action_at"] = parameters["approved_at"]
                    return Result(Row(), rowcount=1)
                if sql.startswith("UPDATE GATEWAY_APPROVALS SET COMMENTS"):
                    shared["comments"] = parameters["comments"]
                    return Result(rowcount=1)
                if sql.startswith("INSERT INTO APPROVAL_AUDIT_EVENTS"):
                    audit_rows.append(dict(parameters))
                    return Result(rowcount=1)
                raise AssertionError(sql)

        class Engine:
            @contextmanager
            def begin(self):
                yield Connection()

        with (
            patch.object(approval_store, "engine", Engine()),
            patch.dict(approval_store._approvals, {}, clear=True),
            self.assertRaises(approval_store.ApprovalStateConflict) as raised,
        ):
            approval_store.approve_approval_atomic(
                dict(shared),
                approver="oidc|checker",
                approved_at=approval_store.datetime(2026, 1, 1, 0, 2, tzinfo=approval_store.timezone.utc),
                mfa_verified=True,
                mfa_binding_hash="binding",
                mfa_counter=404,
                execution_expires_at=approval_store.datetime(2026, 1, 1, 0, 12, tzinfo=approval_store.timezone.utc),
            )

        self.assertEqual(raised.exception.current_status, "expired")
        self.assertEqual(shared["status"], "expired")
        self.assertEqual([row["action"] for row in audit_rows], ["expired"])

    def test_execution_audit_failure_rolls_back_single_use_transition(self):
        import approval_store

        shared = {
            "approval_id": "approval-execution-audit-failure",
            "request_id": "request-execution-audit-failure",
            "correlation_id": "correlation-execution-audit-failure",
            "tenant_id": 42,
            "status": "approved",
            "requested_by": "oidc|requester",
            "approved_by": "oidc|checker",
            "created_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "execution_expires_at": "2099-01-01T00:10:00+00:00",
            "execution_token_used_at": None,
            "comments": "[]",
            "metadata": "{}",
            "reason": "high_risk",
        }

        class Row:
            @property
            def _mapping(self):
                return copy.deepcopy(shared)

        class Result:
            rowcount = 1

            def fetchone(self):
                return Row()

        class Connection:
            def execute(self, statement, parameters):
                sql = " ".join(str(statement).split()).upper()
                if sql.startswith("UPDATE GATEWAY_APPROVALS SET STATUS = 'EXECUTING'"):
                    shared.update({
                        "status": "executing",
                        "execution_token_hash": parameters["token_hash"],
                        "execution_token_used_at": parameters["transition_at"],
                        "execution_mfa_verified": True,
                        "execution_mfa_binding_hash": parameters["binding_hash"],
                        "execution_mfa_counter": parameters["counter"],
                        "executed_by": parameters["actor"],
                    })
                    return Result()
                if sql.startswith("INSERT INTO APPROVAL_AUDIT_EVENTS"):
                    raise RuntimeError("audit denied by RLS")
                return Result()

        class Engine:
            @contextmanager
            def begin(self):
                before = copy.deepcopy(shared)
                try:
                    yield Connection()
                except Exception:
                    shared.clear()
                    shared.update(before)
                    raise

        with (
            patch.object(approval_store, "engine", Engine()),
            patch.dict(approval_store._approvals, {}, clear=True),
            self.assertRaises(approval_store.ApprovalPersistenceError),
        ):
            approval_store.begin_approval_execution_atomic(
                dict(shared),
                actor="oidc|checker",
                transition_at=approval_store.datetime.now(approval_store.timezone.utc),
                execution_token_hash="token-hash",
                execution_operation_id="operation-17",
                reconcile_after=approval_store.datetime.now(approval_store.timezone.utc),
                mfa_binding_hash="binding",
                mfa_counter=505,
            )

        self.assertEqual(shared["status"], "approved")
        self.assertIsNone(shared["execution_token_used_at"])
        self.assertNotIn("approval-execution-audit-failure", approval_store._approvals)

    def test_terminal_audit_failure_rolls_back_success_and_failure_states(self):
        import approval_store

        for final_status in ("executed", "execution_failed", "execution_indeterminate"):
            with self.subTest(final_status=final_status):
                shared = {
                    "approval_id": f"approval-terminal-{final_status}",
                    "request_id": f"request-terminal-{final_status}",
                    "correlation_id": f"correlation-terminal-{final_status}",
                    "tenant_id": 42,
                    "status": "executing",
                    "requested_by": "oidc|requester",
                    "approved_by": "oidc|checker",
                    "executed_by": "oidc|checker",
                    "execution_token_hash": "token-hash",
                    "execution_token_used_at": "2026-01-01T00:05:00+00:00",
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "expires_at": "2099-01-01T00:00:00+00:00",
                    "comments": "[]",
                    "metadata": "{}",
                    "reason": "high_risk",
                }

                class Row:
                    @property
                    def _mapping(self):
                        return copy.deepcopy(shared)

                class Result:
                    rowcount = 1

                    def fetchone(self):
                        return Row()

                class Connection:
                    def execute(self, statement, parameters):
                        sql = " ".join(str(statement).split()).upper()
                        if sql.startswith("UPDATE GATEWAY_APPROVALS SET STATUS = :FINAL_STATUS"):
                            shared["status"] = parameters["final_status"]
                            shared["last_action_at"] = parameters["transition_at"]
                            if parameters["final_status"] == "executed":
                                shared["executed_at"] = parameters["transition_at"]
                            return Result()
                        if sql.startswith("INSERT INTO APPROVAL_AUDIT_EVENTS"):
                            raise RuntimeError("audit denied by RLS")
                        return Result()

                class Engine:
                    @contextmanager
                    def begin(self):
                        before = copy.deepcopy(shared)
                        try:
                            yield Connection()
                        except Exception:
                            shared.clear()
                            shared.update(before)
                            raise

                with (
                    patch.object(approval_store, "engine", Engine()),
                    patch.dict(approval_store._approvals, {}, clear=True),
                    self.assertRaises(approval_store.ApprovalPersistenceError),
                ):
                    approval_store.finish_approval_execution_atomic(
                        dict(shared),
                        actor="oidc|checker",
                        final_status=final_status,
                        transition_at=approval_store.datetime.now(approval_store.timezone.utc),
                    )

                self.assertEqual(shared["status"], "executing")
                self.assertNotIn(shared["approval_id"], approval_store._approvals)

    def test_stale_execution_is_audited_as_indeterminate(self):
        import approval_store

        shared = {
            "approval_id": "approval-stale-execution",
            "request_id": "request-stale-execution",
            "tenant_id": 42,
            "status": "executing",
            "executed_by": "oidc|checker",
            "execution_operation_id": "operation-stale-17",
            "execution_reconcile_after": "2026-01-01T00:01:00+00:00",
            "created_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "comments": "[]",
            "metadata": "{}",
        }
        audit_rows = []

        class Row:
            @property
            def _mapping(self):
                return copy.deepcopy(shared)

        class Result:
            rowcount = 1

            def fetchone(self):
                return Row()

            def scalar(self):
                return shared["status"]

        class Connection:
            def execute(self, statement, parameters):
                sql = " ".join(str(statement).split()).upper()
                if sql.startswith(
                    "UPDATE GATEWAY_APPROVALS SET STATUS = 'EXECUTION_INDETERMINATE'"
                ):
                    self.assert_operation(parameters)
                    shared["status"] = "execution_indeterminate"
                    return Result()
                if sql.startswith("INSERT INTO APPROVAL_AUDIT_EVENTS"):
                    audit_rows.append(dict(parameters))
                    return Result()
                if sql.startswith("UPDATE GATEWAY_APPROVALS SET COMMENTS"):
                    shared["comments"] = parameters["comments"]
                    return Result()
                raise AssertionError(sql)

            @staticmethod
            def assert_operation(parameters):
                assert parameters["operation_id"] == "operation-stale-17"

        class Engine:
            @contextmanager
            def begin(self):
                yield Connection()

        with (
            patch.object(approval_store, "engine", Engine()),
            patch.dict(approval_store._approvals, {}, clear=True),
        ):
            result = approval_store.reconcile_stale_approval_execution_atomic(
                dict(shared),
                actor="oidc|checker",
                transition_at=approval_store.datetime(2026, 1, 1, 0, 2),
            )

        self.assertEqual(result["status"], "execution_indeterminate")
        self.assertEqual([row["action"] for row in audit_rows], ["execution_indeterminate"])
        self.assertIn("operation-stale-17", audit_rows[0]["metadata"])

    def test_read_does_not_reconcile_a_live_execution(self):
        import approval_store

        record = {
            "approval_id": "approval-live-execution",
            "tenant_id": 42,
            "status": "executing",
            "execution_operation_id": "operation-live-17",
            "execution_reconcile_after": "2026-01-01T00:01:00+00:00",
            "created_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "comments": [],
            "metadata": {},
        }

        with patch.dict(
            approval_store._approvals,
            {record["approval_id"]: record},
            clear=True,
        ):
            result = approval_store.get_approval(record["approval_id"])

        self.assertEqual(result["status"], "executing")

    def test_execution_dispatch_fields_survive_database_reload(self):
        import approval_store

        mapping = {
            "approval_id": "approval-dispatch-fields",
            "tenant_id": 42,
            "status": "executing",
            "comments": "[]",
            "metadata": "{}",
            "execution_operation_id": "operation-42",
            "execution_provider_operation_id": "provider-request-42",
            "execution_outcome": '{"status":"succeeded"}',
            "execution_reconcile_after": approval_store.datetime(2026, 1, 1, 0, 1),
        }
        row = SimpleNamespace(_mapping=mapping)

        record = approval_store._row_to_record(row)

        self.assertEqual(record["execution_operation_id"], "operation-42")
        self.assertEqual(record["execution_provider_operation_id"], "provider-request-42")
        self.assertEqual(record["execution_outcome"], {"status": "succeeded"})
        self.assertEqual(record["execution_reconcile_after"], "2026-01-01T00:01:00")

    def test_external_success_with_terminal_audit_failure_never_returns_success(self):
        import main

        record = {
            "approval_id": "approval-crash-window",
            "request_id": "request-crash-window",
            "correlation_id": "correlation-crash-window",
            "tenant_id": 42,
            "status": "approved",
            "requested_by": "oidc|requester",
            "approved_by": "oidc|checker",
            "created_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "execution_expires_at": "2099-01-01T00:10:00+00:00",
            "metadata": {},
            "query": "Apply the approved change",
            "risk_level": "HIGH",
        }
        dispatched = {**record, "status": "executing", "execution_operation_id": "operation-crash-17"}
        provider = Mock(return_value=SimpleNamespace(
            result={"response": "effect applied"}, request_id="provider-operation-17",
            provider_operation_id="approval-exec-operation-crash-17",
            provider="test", model="test", route_id="route", decision="ALLOW", trace=[],
            outcome=main.GatewayExecutionOutcome.SUCCEEDED,
        ))
        request = SimpleNamespace(headers={"Authorization": "Bearer test"})

        class Engine:
            @contextmanager
            def begin(self):
                yield object()

        with (
            patch("database.engine", Engine()),
            patch.object(main, "get_approval", return_value=record),
            patch.object(main, "_approval_authenticated_payload", return_value={
                "sub": "oidc|checker", "tenant_id": 42,
            }),
            patch.object(main, "parse_approval_action_payload", AsyncMock(return_value={
                "_body_present": True, "mfa_code": "redacted",
            })),
            patch.object(main, "_verify_approval_stage_mfa", return_value=(True, "binding", 7)),
            patch.object(main, "begin_approval_execution_atomic", return_value=dispatched) as begin,
            patch.object(main, "get_gateway_service", return_value=SimpleNamespace(
                execute_approval=provider,
            )),
            patch.object(
                main, "finish_approval_execution_atomic",
                side_effect=main.ApprovalPersistenceError("audit unavailable"),
            ),
            self.assertRaises(main.ApprovalPersistenceError),
        ):
            asyncio.run(main.execute_request(record["approval_id"], request))

        self.assertTrue(begin.call_args.kwargs["execution_operation_id"])
        self.assertEqual(
            provider.call_args.kwargs["idempotency_key"], "operation-crash-17"
        )
        provider.assert_called_once()

    def test_execution_terminal_state_and_audit_match_provider_outcome(self):
        import main

        base = {
            "approval_id": "approval-truthful-outcome",
            "request_id": "request-truthful-outcome",
            "correlation_id": "correlation-truthful-outcome",
            "tenant_id": 42,
            "status": "approved",
            "requested_by": "oidc|requester",
            "approved_by": "oidc|checker",
            "created_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "execution_expires_at": "2099-01-01T00:10:00+00:00",
            "metadata": {},
            "query": "Apply the approved change",
            "risk_level": "HIGH",
        }
        request = SimpleNamespace(headers={"Authorization": "Bearer test"})

        class Engine:
            @contextmanager
            def begin(self):
                yield object()

        scenarios = (
            ("policy_denied", main.GatewayExecutionOutcome.POLICY_DENIED, None, "execution_failed", 403, False),
            ("execution_error", main.GatewayExecutionOutcome.EXECUTION_ERROR, None, "execution_failed", 502, False),
            ("provider_unavailable", None, main.GatewayProviderUnavailableError(
                "offline fallback", request_id="request-offline",
                provider_operation_id="provider-offline", trace=["offline_fallback"],
            ), "execution_indeterminate", 503, False),
            ("succeeded", main.GatewayExecutionOutcome.SUCCEEDED, None, "executed", None, True),
        )
        evidence = []
        for label, outcome, provider_error, expected_status, response_status, expected_executed in scenarios:
            dispatched = {
                **base,
                "status": "executing",
                "execution_operation_id": f"operation-{label}",
            }
            execution = SimpleNamespace(
                result={"response": "effect applied"},
                request_id=f"request-{label}",
                provider_operation_id=(
                    f"provider-{label}" if expected_executed else None
                ),
                provider="test",
                model="test",
                route_id="route",
                decision="ALLOW" if expected_executed else "DENY",
                trace=[],
                outcome=outcome,
            )
            terminal_calls = []

            def finish(record, **kwargs):
                terminal_calls.append(kwargs)
                return {
                    **record,
                    "status": kwargs["final_status"],
                    "executed_at": "2026-01-01T00:05:00+00:00",
                }

            with (
                self.subTest(outcome=label),
                patch("database.engine", Engine()),
                patch.object(main, "get_approval", return_value=dict(base)),
                patch.object(main, "_approval_authenticated_payload", return_value={
                    "sub": "oidc|checker", "tenant_id": 42,
                }),
                patch.object(main, "parse_approval_action_payload", AsyncMock(return_value={
                    "_body_present": True, "mfa_code": "redacted",
                })),
                patch.object(main, "_verify_approval_stage_mfa", return_value=(True, "binding", 7)),
                patch.object(main, "begin_approval_execution_atomic", return_value=dispatched),
                patch.object(main, "get_gateway_service", return_value=SimpleNamespace(
                    execute_approval=Mock(
                        return_value=execution if provider_error is None else None,
                        side_effect=provider_error,
                    ),
                )),
                patch.object(main, "finish_approval_execution_atomic", side_effect=finish),
                patch("startup.audit.log_approval_event"),
                patch("verify_audit.create_audit_block"),
            ):
                response = asyncio.run(main.execute_request(base["approval_id"], request))

            terminal = terminal_calls[0]
            self.assertEqual(terminal["final_status"], expected_status)
            self.assertEqual(terminal["execution_outcome"]["allowed"], expected_executed)
            self.assertEqual(terminal["execution_outcome"]["executed"], expected_executed)
            self.assertEqual(terminal["audit_metadata"]["allowed"], expected_executed)
            self.assertEqual(terminal["audit_metadata"]["executed"], expected_executed)
            if response_status is None:
                self.assertEqual(response["message"], "Executed Successfully")
                self.assertEqual(terminal["audit_metadata"]["outcome"], "succeeded")
            else:
                self.assertEqual(response.status_code, response_status)
                self.assertEqual(terminal["audit_metadata"]["outcome"], label)
            evidence.append({
                "scenario": label,
                "http_status": response_status or 200,
                "final_status": terminal["final_status"],
                "execution_outcome": terminal["execution_outcome"],
                "immutable_audit_metadata": terminal["audit_metadata"],
            })

        if evidence_dir := os.getenv("ENT022_EVIDENCE_DIR"):
            Path(evidence_dir).mkdir(parents=True, exist_ok=True)
            Path(evidence_dir, "agent-terminal-outcomes.json").write_text(
                json.dumps(evidence, indent=2, sort_keys=True), encoding="utf-8"
            )

    def test_create_approval_failure_never_enters_process_cache(self):
        import approval_store

        class Connection:
            def execute(self, _statement, _parameters):
                raise RuntimeError("approval table unavailable")

        class Engine:
            @contextmanager
            def begin(self):
                yield Connection()

        with (
            patch.object(approval_store, "engine", Engine()),
            patch.dict(approval_store._approvals, {}, clear=True),
        ):
            with self.assertRaises(approval_store.ApprovalPersistenceError):
                approval_store.create_approval(
                    query="Delete sensitive records",
                    risk_level="HIGH",
                    tenant_id=42,
                    request_id="request-persistence-failure",
                    requested_by="oidc|requester",
                )
            self.assertEqual(approval_store._approvals, {})

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

    def test_inactive_suspended_and_mfa_disabled_users_cannot_approve_or_execute(self):
        import main

        class EmptyResult:
            def mappings(self):
                return self

            def first(self):
                return None

        class Connection:
            def __init__(self):
                self.statements = []

            def execute(self, statement, _parameters=None):
                self.statements.append(" ".join(str(statement).split()).lower())
                return EmptyResult()

        connection = Connection()

        class Engine:
            @contextmanager
            def begin(self):
                yield connection

        base = {
            "approval_id": "approval-current-state",
            "request_id": "request-current-state",
            "correlation_id": "correlation-current-state",
            "tenant_id": 42,
            "requested_by": "oidc|requester",
            "approved_by": "oidc|approver",
            "created_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "execution_expires_at": "2099-01-01T00:10:00+00:00",
            "metadata": {},
            "query": "perform privileged action",
            "risk_level": "HIGH",
        }
        identity = {"sub": "oidc|approver", "user_id": "17", "tenant_id": 42}
        request = SimpleNamespace(headers={})

        for account_state in ("disabled", "suspended", "mfa_disabled"):
            for stage in ("approval", "execution"):
                record = {
                    **base,
                    "status": "pending" if stage == "approval" else "approved",
                }
                transition = Mock()
                with (
                    self.subTest(account_state=account_state, stage=stage),
                    patch("database.engine", Engine()),
                    patch.object(main, "get_approval", return_value=record),
                    patch.object(main, "_approval_authenticated_payload", return_value=identity),
                    patch.object(main, "parse_approval_action_payload", AsyncMock(return_value={
                        "_body_present": True, "mfa_code": "654321",
                    })),
                    patch.object(main, "get_policy", return_value={"approval": {
                        "require_mfa": True, "require_separate_approver": True,
                    }}),
                    patch.object(main, "approve_approval_atomic", transition)
                    if stage == "approval"
                    else patch.object(main, "begin_approval_execution_atomic", transition),
                    patch.object(main, "append_approval_audit"),
                    patch("startup.audit.log_approval_event"),
                ):
                    response = asyncio.run(
                        main.approve_request(record["approval_id"], request)
                        if stage == "approval"
                        else main.execute_request(record["approval_id"], request)
                    )

                self.assertEqual(response.status_code, 400)
                transition.assert_not_called()

        user_queries = [sql for sql in connection.statements if "from tenant_users" in sql]
        self.assertTrue(user_queries)
        self.assertTrue(all("u.status = 'active'" in sql for sql in user_queries))
        self.assertTrue(all("u.mfa_enabled is true" in sql for sql in user_queries))

    def test_control_plane_assertion_satisfies_agent_mfa_without_local_user_mapping(self):
        import main

        record = {
            "approval_id": "approval-external-17",
            "tenant_id": 42,
            "requested_action": "delete",
            "query": "delete sensitive records",
            "risk_level": "HIGH",
            "reason": "high_risk",
            "metadata": {},
        }
        identity = {
            "auth_source": "control_plane",
            "tenant_id": 42,
            "sub": "control-plane-user-17",
            "mfa_assertion_id": "a" * 32,
            "mfa_operation": "POST /approve/approval-external-17",
        }
        with patch.object(main, "_consume_approval_totp_counter") as local_totp:
            verified, binding, replay_token = main._verify_approval_stage_mfa(
                record,
                identity,
                {},
                "approval",
                "2099-01-01T00:00:00+00:00",
            )

        self.assertTrue(verified)
        self.assertEqual(len(binding), 64)
        self.assertGreater(replay_token, 0)
        local_totp.assert_not_called()

    def test_control_plane_assertion_cannot_cross_approval_or_stage(self):
        import main

        record = {"approval_id": "approval-17", "tenant_id": 42, "metadata": {}}
        identity = {
            "auth_source": "control_plane",
            "tenant_id": 42,
            "sub": "control-plane-user-17",
            "mfa_assertion_id": "b" * 32,
            "mfa_operation": "POST /approve/other-approval",
        }
        with self.assertRaises(main.HTTPException) as raised:
            main._verify_approval_stage_mfa(
                record, identity, {}, "approval", "2099-01-01T00:00:00+00:00"
            )
        self.assertEqual(raised.exception.status_code, 401)

    def test_non_control_plane_identity_cannot_inject_mfa_assertion_claims(self):
        import main

        with self.assertRaises(main.HTTPException) as raised:
            main._verify_approval_stage_mfa(
                {"approval_id": "approval-17", "tenant_id": 42, "metadata": {}},
                {
                    "tenant_id": 42,
                    "sub": "agent-user-17",
                    "mfa_assertion_id": "c" * 32,
                    "mfa_operation": "POST /approve/approval-17",
                },
                {},
                "approval",
                "2099-01-01T00:00:00+00:00",
            )
        self.assertEqual(raised.exception.status_code, 401)
        self.assertEqual(raised.exception.detail, "MFA code is required")

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

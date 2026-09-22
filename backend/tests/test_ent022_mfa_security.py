from pathlib import Path
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock
import uuid

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints import apikeys, auth, users, workflows
from app.core.auth import hash_key
from app.core.crypto import decrypt_secret, encrypt_secret
from app.db.models import ComplianceWorkflow, PendingApproval
from app.orchestrator import runner as workflow_runner
from app.orchestrator.runner import ComplianceWorkflowRunner, _create_approval_in_db
from app.services.remediation_approval import build_action_payload, compute_action_hash


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_production_mfa_configuration_has_no_static_default_or_bypass():
    policy = (REPOSITORY_ROOT / "services/agent/policies.yaml").read_text(encoding="utf-8")
    validation = (REPOSITORY_ROOT / "services/agent/startup/validation.py").read_text(encoding="utf-8")
    agent = (REPOSITORY_ROOT / "services/agent/main.py").read_text(encoding="utf-8")
    example = (REPOSITORY_ROOT / ".env.full.example").read_text(encoding="utf-8")

    assert "default_mfa_code" not in policy
    assert "default_mfa_code" not in validation
    assert "DISABLE_MFA_FOR_TESTING" not in agent
    assert "AUTHCLAW_ALLOW_TEST_MFA_BYPASS" not in agent
    assert "AUTHCLAW_LITE_DEMO_TOTP_SECRET=" in example
    assert not any(
        line.startswith("AUTHCLAW_LITE_DEMO_TOTP_SECRET=") and line.split("=", 1)[1].strip()
        for line in example.splitlines()
    )


def test_control_plane_mfa_assertion_uses_canonical_user_factor_and_audit(monkeypatch):
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    user = SimpleNamespace(
        id=user_id,
        tenant_id=tenant_id,
        mfa_enabled=True,
        mfa_secret=encrypt_secret("JBSWY3DPEHPK3PXP"),
    )
    request = MagicMock(headers={"x-request-id": "request-agent-mfa"})
    request.state.credential_kind = "session"
    monkeypatch.setattr(auth, "revalidate_tenant_credential", lambda *_: None)
    request.state.tenant_id = tenant_id
    request.state.user_id = user_id
    db = MagicMock()
    db.query.return_value.filter.return_value.with_for_update.return_value.first.return_value = user
    verified = MagicMock(return_value=True)
    published = MagicMock(return_value=None)
    monkeypatch.setattr(auth, "verify_mfa_challenge", verified)
    monkeypatch.setattr(auth.event_backbone, "publish_audit_event", published)

    response = auth.create_agent_mfa_assertion(
        auth.AgentMFAAssertionRequest(
            code="654321",
            method="POST",
            path="/approve/approval-17",
            body_sha256="a" * 64,
        ),
        request,
        db,
    )

    assert response.operation == "POST /approve/approval-17"
    assert response.body_sha256 == "a" * 64
    assert len(response.assertion_id) == 32
    assert "654321" not in str(response)
    assert verified.call_args.kwargs["tenant_id"] == str(tenant_id)
    assert verified.call_args.kwargs["operation"] == "agent_approval"
    event = published.call_args.args[2]
    assert event["actor_id"] == str(user_id)
    assert event["assertion_id"] == response.assertion_id
    assert event["body_sha256"] == "a" * 64
    assert event["execution_trace"] == [{
        "event": "agent_mfa_assertion_issued",
        "assertion_id": response.assertion_id,
        "operation": "POST /approve/approval-17",
        "body_sha256": "a" * 64,
    }]
    assert "654321" not in str(event)
    db.commit.assert_called_once()


def test_api_key_administration_requires_interactive_replay_protected_mfa(monkeypatch):
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    user = SimpleNamespace(
        id=user_id,
        tenant_id=tenant_id,
        role="owner",
        is_active=True,
        mfa_enabled=True,
        mfa_secret="encrypted-factor",
    )
    request = SimpleNamespace(
        state=SimpleNamespace(
            credential_kind="session", tenant_id=tenant_id, user_id=user_id
        ),
        headers={"x-request-id": "api-key-mfa"},
    )
    db = MagicMock()
    db.query.return_value.filter.return_value.with_for_update.return_value.first.return_value = user
    verify = MagicMock(return_value=True)
    monkeypatch.setattr(
        apikeys,
        "revalidate_tenant_credential",
        lambda *_: SimpleNamespace(role="owner", scopes=["admin", "read", "write"]),
    )
    monkeypatch.setattr(apikeys, "_get_redis", MagicMock(return_value=object()))
    monkeypatch.setattr(apikeys, "verify_mfa_challenge", verify)

    assert apikeys._verify_api_key_mfa(
        request, db, code="654321", operation="api_key_issue"
    ) is user
    assert verify.call_args.args[2] == "654321"
    assert verify.call_args.kwargs["operation"] == "api_key_issue"

    request.state.credential_kind = "api_key"
    with pytest.raises(HTTPException, match="Interactive tenant session") as exc:
        apikeys._verify_api_key_mfa(
            request, db, code="654321", operation="api_key_rotate"
        )
    assert exc.value.status_code == 403


def test_api_key_audit_is_atomic_and_contains_no_factor_or_secret(monkeypatch):
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    request = SimpleNamespace(
        state=SimpleNamespace(tenant_id=tenant_id, user_id=user_id),
        headers={"x-request-id": "api-key-audit"},
    )
    key = SimpleNamespace(id=uuid.uuid4(), scopes=["admin", "read"])
    published = MagicMock(return_value=None)
    monkeypatch.setattr(apikeys.event_backbone, "publish_audit_event", published)

    apikeys._commit_api_key_audit(
        MagicMock(), request, key=key, action="issued"
    )

    event = published.call_args.args[2]
    assert event["action"] == "api_key:issued"
    assert event["mfa_verified"] is True
    assert event["execution_trace"][0]["api_key_id"] == str(key.id)
    assert "654321" not in str(event)
    assert "ak_" not in str(event)


def test_api_key_issue_revalidates_locked_actor_before_commit(monkeypatch):
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    actor = SimpleNamespace(
        id=user_id,
        tenant_id=tenant_id,
        role="owner",
        is_active=True,
        mfa_enabled=True,
        mfa_secret="encrypted-factor",
    )
    request = SimpleNamespace(
        state=SimpleNamespace(
            credential_kind="session",
            credential_hash="session-hash",
            tenant_id=tenant_id,
            user_id=user_id,
        ),
        headers={"x-request-id": "concurrent-demotion"},
    )
    db = MagicMock()
    db.query.return_value.filter.return_value.with_for_update.return_value.first.return_value = actor
    db.flush.side_effect = lambda: setattr(db.add.call_args.args[0], "id", uuid.uuid4())
    authority = iter((
        SimpleNamespace(role="owner", scopes=["admin", "read"]),
        SimpleNamespace(role="viewer", scopes=["read"]),
    ))
    monkeypatch.setattr(apikeys, "revalidate_tenant_credential", lambda *_: next(authority))
    monkeypatch.setattr(apikeys, "verify_mfa_challenge", MagicMock(return_value=True))
    monkeypatch.setattr(apikeys, "_get_redis", MagicMock(return_value=object()))
    audit = MagicMock()
    monkeypatch.setattr(apikeys, "_commit_api_key_audit", audit)

    with pytest.raises(HTTPException, match="Active tenant owner") as exc:
        apikeys.generate_api_key(
            request,
            apikeys.APIKeyCreate(name="raced", scopes=["read"], mfa_code="654321"),
            db,
        )

    assert exc.value.status_code == 403
    assert db.refresh.call_count == 2
    db.rollback.assert_called()
    audit.assert_not_called()


def test_api_key_rotation_locks_the_target_credential(monkeypatch):
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    key_id = uuid.uuid4()
    old_key = SimpleNamespace(
        id=key_id,
        tenant_id=tenant_id,
        name="existing",
        description=None,
        scopes=["read"],
        is_active=True,
        revoked_at=None,
        rotated_at=None,
    )
    request = SimpleNamespace(
        state=SimpleNamespace(tenant_id=tenant_id, user_id=user_id, api_key_id=None),
        headers={"x-request-id": "rotation-lock"},
    )
    db = MagicMock()
    query = db.query.return_value
    query.filter.return_value.with_for_update.return_value.first.return_value = old_key
    def assign_generated_fields():
        new_key = db.add.call_args.args[0]
        new_key.id = uuid.uuid4()
        new_key.created_at = datetime.now(timezone.utc)

    db.flush.side_effect = assign_generated_fields
    actor = SimpleNamespace(role="owner", is_active=True)
    monkeypatch.setattr(apikeys, "_verify_api_key_mfa", MagicMock(return_value=actor))
    monkeypatch.setattr(apikeys, "_revalidate_locked_api_key_actor", MagicMock())
    monkeypatch.setattr(apikeys, "_commit_api_key_audit", MagicMock())
    monkeypatch.setattr(apikeys, "create_notification", MagicMock())

    apikeys.rotate_api_key(
        key_id,
        request,
        apikeys.APIKeyRotate(mfa_code="654321"),
        db,
    )

    query.filter.return_value.with_for_update.assert_called_once_with()
    assert old_key.is_active is False


def test_api_key_revocation_requires_mfa_locks_and_audits(monkeypatch):
    tenant_id = uuid.uuid4()
    key = SimpleNamespace(
        id=uuid.uuid4(), tenant_id=tenant_id, name="revoke-me", scopes=["read"],
        is_active=True, revoked_at=None, rotated_at=None,
    )
    request = SimpleNamespace(
        state=SimpleNamespace(tenant_id=tenant_id, user_id=uuid.uuid4(), api_key_id=None),
        headers={"x-request-id": "revocation-lock"},
    )
    db = MagicMock()
    query = db.query.return_value
    query.filter.return_value.with_for_update.return_value.first.return_value = key
    actor = SimpleNamespace(role="owner", is_active=True)
    verify = MagicMock(return_value=actor)
    audit = MagicMock()
    monkeypatch.setattr(apikeys, "_verify_api_key_mfa", verify)
    monkeypatch.setattr(apikeys, "_revalidate_locked_api_key_actor", MagicMock())
    monkeypatch.setattr(apikeys, "_commit_api_key_audit", audit)
    monkeypatch.setattr(apikeys, "create_notification", MagicMock())

    apikeys.revoke_api_key(
        key.id, request, apikeys.APIKeyRevoke(mfa_code="654321"), db
    )

    assert verify.call_args.kwargs["operation"] == "api_key_revoke"
    query.filter.return_value.with_for_update.assert_called_once_with()
    audit.assert_called_once_with(db, request, key=key, action="revoked")
    assert key.is_active is False
    assert key.revoked_at is not None
    db.commit.assert_not_called()


def test_workflow_mfa_uses_only_json_body(monkeypatch):
    user = SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        mfa_enabled=True,
        mfa_secret="encrypted-factor",
    )
    verify = MagicMock(return_value=True)
    monkeypatch.setattr(workflows, "verify_mfa_challenge", verify)
    monkeypatch.setattr(workflows, "_get_redis", MagicMock(return_value=object()))

    unsafe_requests = [
        SimpleNamespace(query_params={"totp_code": "654321"}, headers={}),
        SimpleNamespace(query_params={}, headers={"X-MFA-Code": "654321"}),
        SimpleNamespace(query_params={}, headers={"X-TOTP-Code": "654321"}),
    ]
    for request in unsafe_requests:
        with pytest.raises(HTTPException, match="JSON request body") as exc:
            workflows._verify_mfa_if_enabled(
                user, request, workflows.ApprovalRequest(totp_code="123456")
            )
        assert exc.value.status_code == 400
    verify.assert_not_called()

    request = SimpleNamespace(query_params={}, headers={"x-request-id": "request-body-mfa"})
    verified, timestamp = workflows._verify_mfa_if_enabled(
        user,
        request,
        workflows.ApprovalRequest(totp_code="123456"),
    )

    assert verified is True
    assert timestamp is not None
    assert verify.call_args.args[2] == "123456"


def test_production_edge_blocks_and_redacts_legacy_mfa_transports():
    edge = (REPOSITORY_ROOT / "infra/terraform/edge.tf").read_text(encoding="utf-8")
    tls_proxy = (
        REPOSITORY_ROOT
        / "infra/terraform/modules/regional_stack/tls-nginx.conf.tftpl"
    ).read_text(encoding="utf-8")

    assert 'name     = "block-mfa-credentials-outside-body"' in edge
    assert 'single_query_argument { name = "totp_code" }' in edge
    assert 'single_header { name = "x-mfa-code" }' in edge
    assert 'single_header { name = "x-totp-code" }' in edge
    assert "sampled_requests_enabled   = false" in edge
    assert "access_log off;" in tls_proxy


def test_self_approval_is_rejected_and_audited():
    actor_id = uuid.uuid4()
    approval = SimpleNamespace(
        requester_id=actor_id,
        id=uuid.uuid4(),
        action_hash="action-hash",
        action_id="workflow-1",
        action_type="remediation",
    )
    db = MagicMock()

    with pytest.raises(HTTPException, match="different authorized user") as exc:
        workflows._enforce_separate_approver(
            db, approval, str(uuid.uuid4()), actor_id
        )

    assert exc.value.status_code == 403
    audit = db.add.call_args.args[0]
    assert audit.action == "SELF_APPROVAL_REJECTED"
    assert audit.mfa_verified is False
    db.commit.assert_called_once()


def test_graph_workflow_records_authenticated_requester_and_rejects_self_approval():
    tenant_id = uuid.uuid4()
    requester_id = uuid.uuid4()
    db = MagicMock()
    workflow_query = MagicMock()
    approval_query = MagicMock()
    workflow_query.filter.return_value.with_for_update.return_value.first.side_effect = (
        lambda: next(
            call.args[0]
            for call in db.add.call_args_list
            if isinstance(call.args[0], ComplianceWorkflow)
        )
    )
    approval_query.filter.return_value.order_by.return_value.first.return_value = None
    db.query.side_effect = (
        lambda model: workflow_query if model is ComplianceWorkflow else approval_query
    )
    runner = ComplianceWorkflowRunner.__new__(ComplianceWorkflowRunner)
    runner.db = db

    class ApprovalGraph:
        @staticmethod
        def invoke(state):
            state["_create_approval"](
                state["tenant_id"], state["workflow_id"], [{"action": "redact"}]
            )
            return state

    runner.graph = ApprovalGraph()
    result = runner.start(
        tenant_id=str(tenant_id),
        framework="HIPAA",
        requester_id=str(requester_id),
        request_id="request-graph-maker",
    )

    approval = next(
        call.args[0]
        for call in db.add.call_args_list
        if isinstance(call.args[0], PendingApproval)
    )
    assert result["requester_id"] == str(requester_id)
    assert approval.requester_id == requester_id
    assert "SELECT id FROM users" not in " ".join(str(call) for call in db.execute.call_args_list)

    with pytest.raises(HTTPException) as exc:
        workflows._enforce_separate_approver(
            db, approval, str(tenant_id), requester_id
        )
    assert exc.value.status_code == 403


def test_graph_approval_creation_fails_closed_without_requester():
    db = MagicMock()

    with pytest.raises(ValueError, match="requester identity is required"):
        _create_approval_in_db(
            db,
            str(uuid.uuid4()),
            str(uuid.uuid4()),
            [{"action": "redact"}],
            requester_id="",
        )

    db.add.assert_not_called()
    db.execute.assert_not_called()


def test_remediation_approval_creation_links_workflow_in_same_commit():
    tenant_id = uuid.uuid4()
    workflow_id = str(uuid.uuid4())
    requester_id = uuid.uuid4()
    workflow = SimpleNamespace(
        approval_id=None,
        state_data={"requester_id": str(requester_id)},
        current_state="COMPLETE",
        execution_status="COMPLETED",
        approval_status=None,
        updated_at=None,
    )
    db = MagicMock()
    workflow_query = MagicMock()
    approval_query = MagicMock()
    workflow_query.filter.return_value.with_for_update.return_value.first.return_value = workflow
    approval_query.filter.return_value.order_by.return_value.first.return_value = None
    db.query.side_effect = (
        lambda model: workflow_query if model is ComplianceWorkflow else approval_query
    )

    approval_id = _create_approval_in_db(
        db,
        str(tenant_id),
        workflow_id,
        [{"action": "redact"}],
        str(requester_id),
    )

    approval = next(
        call.args[0] for call in db.add.call_args_list
        if isinstance(call.args[0], PendingApproval)
    )
    assert str(approval.id) == approval_id
    assert workflow.approval_id == approval.id
    assert workflow.current_state == "AWAITING_APPROVAL"
    assert workflow.execution_status == "PAUSED"
    assert workflow.state_data["approval_id"] == approval_id
    db.commit.assert_called_once()


def test_remediation_approval_creation_relinks_existing_valid_orphan():
    tenant_id = uuid.uuid4()
    workflow_id = str(uuid.uuid4())
    requester_id = uuid.uuid4()
    plan = [{"action": "redact"}]
    action_payload = build_action_payload(workflow_id, plan)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=20)
    existing = SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        action_type="remediation",
        action_id=workflow_id,
        action_payload=action_payload,
        expires_at=expires_at,
        action_hash=compute_action_hash(
            tenant_id=str(tenant_id),
            action_payload=action_payload,
            expires_at=expires_at,
        ),
        status="PENDING",
    )
    workflow = SimpleNamespace(
        approval_id=None,
        state_data={},
        approval_status=None,
        updated_at=None,
    )
    db = MagicMock()
    workflow_query = MagicMock()
    approval_query = MagicMock()
    workflow_query.filter.return_value.with_for_update.return_value.first.return_value = workflow
    approval_query.filter.return_value.order_by.return_value.first.return_value = existing
    db.query.side_effect = (
        lambda model: workflow_query if model is ComplianceWorkflow else approval_query
    )

    approval_id = _create_approval_in_db(
        db, str(tenant_id), workflow_id, plan, str(requester_id)
    )

    assert approval_id == str(existing.id)
    assert workflow.approval_id == existing.id
    assert workflow.state_data["approval_id"] == str(existing.id)
    db.add.assert_not_called()
    db.commit.assert_called_once()


def test_approval_consumption_waits_for_workflow_transition_commit(monkeypatch):
    tenant_id = uuid.uuid4()
    actor_id = uuid.uuid4()
    approval = SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        action_type="remediation",
        action_id="workflow-atomic",
        action_payload={"plan": [{"action": "redact", "destructive": False}]},
        action_hash="a" * 64,
        status="APPROVED",
        requester_id=uuid.uuid4(),
        approver_id=actor_id,
        mfa_verified=True,
        mfa_timestamp=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        consumed_at=None,
        consumed_by_id=None,
        resolution_reason=None,
    )
    db = MagicMock()
    db.query.return_value.filter.return_value.with_for_update.return_value.first.return_value = approval
    monkeypatch.setattr(
        workflow_runner,
        "evaluate_approval",
        lambda **_kwargs: SimpleNamespace(allowed=True, status="APPROVED", reason="allowed"),
    )

    status = workflow_runner._check_approval_in_db(
        db,
        str(approval.id),
        str(tenant_id),
        str(actor_id),
        approval.action_id,
        approval.action_payload["plan"],
    )

    assert status == "APPROVED"
    assert approval.status == "CONSUMED"
    db.flush.assert_called_once()
    db.commit.assert_not_called()


def test_resume_failure_before_workflow_advance_rolls_back_consumption(monkeypatch):
    tenant_id = uuid.uuid4()
    workflow_id = str(uuid.uuid4())
    workflow = SimpleNamespace(
        workflow_id=workflow_id,
        tenant_id=tenant_id,
        execution_status="PAUSED",
        current_state="AWAITING_APPROVAL",
        state_data={"requester_id": str(uuid.uuid4()), "request_id": "atomic-retry"},
        remediation_plan=[{"action": "redact"}],
        error_message=None,
        updated_at=None,
    )
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = workflow
    db.query.return_value.filter.return_value.with_for_update.return_value.first.return_value = workflow
    runner = ComplianceWorkflowRunner.__new__(ComplianceWorkflowRunner)
    runner.db = db
    monkeypatch.setattr(workflow_runner, "workflow_advisory_lock", lambda *_args: __import__("contextlib").nullcontext())
    monkeypatch.setattr(workflow_runner, "awaiting_approval", MagicMock(side_effect=RuntimeError("injected after approval consumption")))
    monkeypatch.setattr(workflow_runner, "emit_audit_event", MagicMock())

    with pytest.raises(RuntimeError, match="injected"):
        runner.resume(workflow_id, str(tenant_id), str(uuid.uuid4()))

    db.rollback.assert_called_once()
    db.commit.assert_called_once()
    assert workflow.execution_status == "PAUSED"


def test_historical_workflow_without_requester_cannot_resume():
    tenant_id = uuid.uuid4()
    workflow_id = uuid.uuid4()
    workflow = SimpleNamespace(
        execution_status="PAUSED",
        state_data={},
    )
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = workflow
    connection = db.get_bind.return_value.engine.connect.return_value
    connection.execute.return_value.scalar.return_value = True
    runner = ComplianceWorkflowRunner.__new__(ComplianceWorkflowRunner)
    runner.db = db

    with pytest.raises(ValueError, match="requester identity is unavailable"):
        runner.resume(str(workflow_id), str(tenant_id), actor_id=str(uuid.uuid4()))

    assert workflow.execution_status == "PAUSED"
    db.commit.assert_not_called()


def test_remediation_preserves_workflow_requester_and_binds_current_initiator(monkeypatch):
    from app.orchestrator import runner as workflow_runner

    tenant_id = uuid.uuid4()
    workflow_id = str(uuid.uuid4())
    original_requester = uuid.uuid4()
    remediation_requester = uuid.uuid4()
    approval_id = uuid.uuid4()
    workflow = SimpleNamespace(
        workflow_id=workflow_id,
        execution_status="COMPLETED",
        remediation_plan=[{"action": "redact"}],
        state_data={"requester_id": str(original_requester)},
        current_state="COMPLETED",
        approval_status=None,
        approval_id=None,
        updated_at=None,
        request_id="request-original",
    )
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = workflow
    request = MagicMock()
    request.state.tenant_id = tenant_id
    request.state.user_id = remediation_requester
    create_approval = MagicMock(return_value=str(approval_id))
    monkeypatch.setattr(workflow_runner, "_create_approval_in_db", create_approval)
    monkeypatch.setattr(workflow_runner, "emit_audit_event", MagicMock())
    monkeypatch.setattr(workflows, "check_worker_throttle", lambda *_args, **_kwargs: (True, 0))
    monkeypatch.setattr(workflows, "_tenant_tier", lambda *_args: "enterprise")
    monkeypatch.setattr(workflows, "create_notification", MagicMock())
    monkeypatch.setattr(workflows, "flag_modified", MagicMock())

    status_payload = {
        "workflow_id": workflow_id,
        "tenant_id": str(tenant_id),
        "framework": "HIPAA",
        "current_state": "AWAITING_APPROVAL",
        "execution_status": "PAUSED",
    }
    fake_runner = MagicMock()
    fake_runner.get_status.return_value = status_payload
    monkeypatch.setattr(workflows, "ComplianceWorkflowRunner", MagicMock(return_value=fake_runner))

    workflows.remediate_workflow(workflow_id, request, db, _auth=None)

    assert workflow.state_data["requester_id"] == str(original_requester)
    assert workflow.state_data["remediation_requester_id"] == str(remediation_requester)
    assert create_approval.call_args.kwargs["requester_id"] == str(remediation_requester)


def test_remediation_denies_historical_workflow_without_requester():
    tenant_id = uuid.uuid4()
    workflow_id = str(uuid.uuid4())
    workflow = SimpleNamespace(
        execution_status="COMPLETED",
        remediation_plan=[{"action": "redact"}],
        state_data={},
    )
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = workflow
    request = MagicMock()
    request.state.tenant_id = tenant_id
    request.state.user_id = uuid.uuid4()

    with pytest.raises(HTTPException, match="requester identity is unavailable") as exc:
        workflows.remediate_workflow(workflow_id, request, db, _auth=None)

    assert exc.value.status_code == 409
    db.commit.assert_not_called()


def test_mfa_lifecycle_audit_contains_identifiers_but_no_secret(monkeypatch):
    captured = {}

    def publish(_producer, tenant_id, event, *, db):
        captured.update({"tenant_id": tenant_id, "event": event, "db": db})
        return None

    monkeypatch.setattr(users.event_backbone, "publish_audit_event", publish)
    request = MagicMock(headers={"x-request-id": "req-1"})
    request.state.tenant_id = uuid.uuid4()
    request.state.user_id = uuid.uuid4()
    subject_id = uuid.uuid4()
    db = MagicMock()

    users._commit_mfa_audit(
        db,
        request,
        action="enrollment_confirmed",
        subject_id=subject_id,
        reason="totp_possession_confirmed",
    )

    event = captured["event"]
    assert event["subject_id"] == str(subject_id)
    assert event["actor_id"] == str(request.state.user_id)
    assert event["action"] == "mfa:enrollment_confirmed"
    assert "secret" not in str(event).lower()
    assert "totp_possession_confirmed" in str(event)


def test_pending_factor_requires_confirmation_before_activation(monkeypatch):
    user_id = uuid.uuid4()
    tenant_id = uuid.uuid4()
    pending_secret = "JBSWY3DPEHPK3PXP"
    user = SimpleNamespace(
        id=user_id,
        tenant_id=tenant_id,
        email="owner@example.com",
        role="owner",
        mfa_enabled=False,
        mfa_secret=None,
        mfa_backup_codes=None,
        mfa_last_totp_step=None,
        mfa_pending_secret=encrypt_secret(pending_secret),
        mfa_pending_last_totp_step=None,
        mfa_pending_backup_codes=[hash_key("mfa-backup:recovery")],
        mfa_pending_expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        mfa_enrolled_at=None,
    )
    request = MagicMock(headers={"x-request-id": "req-confirm"})
    request.state.credential_kind = "session"
    monkeypatch.setattr(users, "revalidate_tenant_credential", lambda *_: None)
    request.state.user_id = user_id
    request.state.tenant_id = tenant_id
    db = MagicMock()
    db.query.return_value.filter.return_value.with_for_update.return_value.first.return_value = user

    def verify(_client, pending, _code, **_kwargs):
        pending.mfa_pending_last_totp_step = 42
        return True

    monkeypatch.setattr(users, "verify_mfa_challenge", verify)
    monkeypatch.setattr(users, "_commit_mfa_audit", lambda db, *_args, **_kwargs: db.commit())

    response = users.confirm_my_mfa(
        users.MFAConfirmRequest(code="654321"), request, db
    )

    assert response.mfa_enabled is True
    assert decrypt_secret(user.mfa_secret) == pending_secret
    assert user.mfa_last_totp_step == 42
    assert user.mfa_pending_secret is None
    assert user.mfa_pending_backup_codes is None
    db.commit.assert_called_once()


def test_separate_owner_recovery_revokes_sessions(monkeypatch):
    tenant_id = uuid.uuid4()
    actor_id = uuid.uuid4()
    target_id = uuid.uuid4()
    actor = SimpleNamespace(
        id=actor_id, tenant_id=tenant_id, email="owner@example.com", role="owner",
        mfa_enabled=True, mfa_secret=encrypt_secret("JBSWY3DPEHPK3PXP"),
    )
    target = SimpleNamespace(
        id=target_id, tenant_id=tenant_id, email="admin@example.com", role="admin",
        mfa_enabled=True, mfa_secret=encrypt_secret("KRSXG5DSNFXGOIDB"),
        mfa_backup_codes=["hash"], mfa_last_totp_step=10,
        mfa_pending_secret=None, mfa_pending_last_totp_step=None,
        mfa_pending_backup_codes=None,
        mfa_pending_expires_at=None, mfa_enrolled_at=datetime.now(timezone.utc),
    )
    request = MagicMock(headers={"x-request-id": "req-recovery"})
    request.state.credential_kind = "session"
    monkeypatch.setattr(users, "revalidate_tenant_credential", lambda *_: None)
    request.state.user_id = actor_id
    request.state.tenant_id = tenant_id
    db = MagicMock()
    locked = db.query.return_value.filter.return_value.order_by.return_value.with_for_update.return_value
    locked.all.return_value = [actor, target]
    monkeypatch.setattr(users, "verify_mfa_challenge", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(users, "_commit_mfa_audit", lambda db, *_args, **_kwargs: db.commit())

    response = users.reset_user_mfa(
        target_id, users.MFAAdminResetRequest(code="654321"), request, db
    )

    assert response.mfa_enabled is False
    assert target.mfa_secret is None
    assert target.mfa_backup_codes is None
    statement = str(db.execute.call_args.args[0])
    assert "authn.revoke_user_sessions" in statement
    revoked = db.query.return_value.filter.return_value.update.call_args
    assert revoked.args[0]["is_active"] is False
    assert revoked.args[0]["revoked_at"] is not None
    db.commit.assert_called_once()

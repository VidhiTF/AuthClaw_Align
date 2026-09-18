from pathlib import Path
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock
import uuid

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints import auth, users, workflows
from app.core.auth import hash_key
from app.core.crypto import decrypt_secret, encrypt_secret
from app.db.models import PendingApproval
from app.orchestrator.runner import ComplianceWorkflowRunner, _create_approval_in_db


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
    assert event["body_sha256"] == "a" * 64
    assert "654321" not in str(event)
    db.commit.assert_called_once()


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
    db.commit.assert_called_once()

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import uuid

from app.services.remediation_approval import (
    build_action_payload,
    compute_action_hash,
    evaluate_approval,
    mark_altered_approval_and_workflow,
    normalize_remediation_plan,
)


TENANT_ID = str(uuid.uuid4())
APPROVER_ID = str(uuid.uuid4())
WORKFLOW_ID = str(uuid.uuid4())
NOW = datetime(2026, 7, 20, 10, 0, tzinfo=timezone.utc)


def _plan():
    return [
        {
            "action": "Redact a sensitive S3 object",
            "target": {"type": "s3_object", "uri": "s3://bucket/object.txt"},
            "destructive": True,
            "diff": {"preview": ["- raw value", "+ [REDACTED]"]},
            "steps": ["Create backup", "Redact", "Verify"],
        }
    ]


def _approval(**overrides):
    expires_at = overrides.pop("expires_at", NOW + timedelta(minutes=30))
    payload = overrides.pop("action_payload", build_action_payload(WORKFLOW_ID, _plan()))
    values = {
        "tenant_id": TENANT_ID,
        "action_id": WORKFLOW_ID,
        "action_payload": payload,
        "action_hash": compute_action_hash(
            tenant_id=TENANT_ID,
            action_payload=payload,
            expires_at=expires_at,
        ),
        "status": "APPROVED",
        "approver_id": APPROVER_ID,
        "expires_at": expires_at,
        "consumed_at": None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _evaluate(approval, **overrides):
    values = {
        "approval": approval,
        "tenant_id": TENANT_ID,
        "actor_id": APPROVER_ID,
        "workflow_id": WORKFLOW_ID,
        "current_plan": _plan(),
        "now": NOW,
    }
    values.update(overrides)
    return evaluate_approval(**values)


def test_plan_exposes_change_risk_and_rollback():
    item = normalize_remediation_plan(_plan())[0]
    assert item["proposed_change"]["summary"] == "Redact a sensitive S3 object"
    assert item["risk"]["level"] == "high"
    assert item["rollback"]["strategy"]


def test_action_hash_is_stable_and_detects_changes():
    approval = _approval()
    reordered = {
        "plan": approval.action_payload["plan"],
        "workflow_id": WORKFLOW_ID,
        "schema_version": "acl-18.v1",
    }
    assert compute_action_hash(
        tenant_id=TENANT_ID,
        action_payload=reordered,
        expires_at=approval.expires_at,
    ) == approval.action_hash

    reordered["plan"][0]["action"] = "Different action"
    assert compute_action_hash(
        tenant_id=TENANT_ID,
        action_payload=reordered,
        expires_at=approval.expires_at,
    ) != approval.action_hash


def test_valid_approval_is_allowed_once():
    decision = _evaluate(_approval())
    assert decision.allowed is True
    assert decision.status == "APPROVED"


def test_expired_replayed_altered_and_unapproved_actions_are_rejected():
    expired = _evaluate(_approval(expires_at=NOW - timedelta(seconds=1)))
    replayed = _evaluate(_approval(status="CONSUMED", consumed_at=NOW))
    altered = _evaluate(_approval(), current_plan=[{"action": "Altered"}])
    unapproved = _evaluate(_approval(status="PENDING"))

    assert (expired.allowed, expired.status) == (False, "EXPIRED")
    assert (replayed.allowed, replayed.status) == (False, "REPLAYED")
    assert (altered.allowed, altered.status) == (False, "ALTERED")
    assert (unapproved.allowed, unapproved.status) == (False, "UNAPPROVED")


def test_approval_is_bound_to_tenant_user_and_workflow():
    wrong_tenant = _evaluate(_approval(), tenant_id=str(uuid.uuid4()))
    wrong_user = _evaluate(_approval(), actor_id=str(uuid.uuid4()))
    wrong_workflow = _evaluate(_approval(), workflow_id=str(uuid.uuid4()))

    assert wrong_tenant.status == "TENANT_MISMATCH"
    assert wrong_user.status == "USER_MISMATCH"
    assert wrong_workflow.status == "ACTION_MISMATCH"


def test_altered_approval_persists_terminal_safe_workflow_state():
    approval = SimpleNamespace(
        status="PENDING",
        resolution_reason=None,
    )
    workflow = SimpleNamespace(
        current_state="AWAITING_APPROVAL",
        execution_status="PAUSED",
        approval_status="PENDING",
        state_data={
            "current_state": "AWAITING_APPROVAL",
            "execution_status": "PAUSED",
            "approval_status": "PENDING",
            "remediation_state": "NOT_STARTED",
        },
        completed_at=None,
        updated_at=NOW,
    )

    reason = mark_altered_approval_and_workflow(
        approval=approval,
        workflow=workflow,
        now=NOW,
    )

    assert approval.status == "ALTERED"
    assert approval.resolution_reason == reason
    assert workflow.approval_status == "ALTERED"
    assert workflow.current_state == "COMPLETE"
    assert workflow.execution_status == "COMPLETED"
    assert workflow.state_data["approval_status"] == "ALTERED"
    assert workflow.state_data["remediation_state"] == "NOT_STARTED"
    assert workflow.completed_at == NOW

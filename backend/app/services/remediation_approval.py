"""Canonical remediation-plan binding and one-time approval decisions."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


APPROVAL_SCHEMA_VERSION = "acl-18.v1"
ALTERED_APPROVAL_REASON = "Remediation plan or approval binding changed before approval"


@dataclass(frozen=True)
class ApprovalDecision:
    allowed: bool
    status: str
    reason: str


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def normalize_remediation_plan(plan: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return a review-ready plan without changing the executable connector fields."""
    normalized: list[dict[str, Any]] = []
    for source in plan:
        item = dict(source)
        target = item.get("target") or {}
        proposed_change = item.get("proposed_change") or {
            "summary": item.get("action") or item.get("diff", {}).get("summary", ""),
            "target": target,
            "steps": item.get("steps") or [],
            "preview": item.get("diff", {}).get("preview") or [],
        }
        risk = item.get("risk") or {
            "level": "high" if item.get("destructive") else item.get("priority", "medium"),
            "destructive": bool(item.get("destructive")),
            "impact": (
                "The approved target will be mutated and may affect production data."
                if item.get("destructive")
                else "The approved target may change during remediation."
            ),
        }
        rollback = item.get("rollback") or {
            "strategy": "Restore the pre-change backup created before mutation.",
            "trigger": "Verification failure or an operator-requested rollback.",
            "evidence": "Rollback result and restored-target verification are audited.",
        }
        item.update(
            {
                "proposed_change": proposed_change,
                "risk": risk,
                "rollback": rollback,
            }
        )
        normalized.append(item)
    return normalized


def build_action_payload(workflow_id: str, plan: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": APPROVAL_SCHEMA_VERSION,
        "workflow_id": workflow_id,
        "plan": normalize_remediation_plan(plan),
    }


def compute_action_hash(
    *,
    tenant_id: str,
    action_payload: dict[str, Any],
    expires_at: datetime,
) -> str:
    """Hash the immutable tenant, action and expiry approval boundary."""
    binding = {
        "tenant_id": str(tenant_id),
        "action_payload": action_payload,
        "expires_at": _utc(expires_at).isoformat(timespec="microseconds"),
    }
    canonical = json.dumps(
        binding,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def mark_altered_approval_and_workflow(
    *,
    approval: Any,
    workflow: Any | None,
    now: datetime | None = None,
) -> str:
    """Synchronize a tampered approval with a terminal-safe workflow state."""
    current_time = _utc(now or datetime.now(timezone.utc))
    approval.status = "ALTERED"
    approval.resolution_reason = ALTERED_APPROVAL_REASON

    if workflow:
        workflow.approval_status = "ALTERED"
        workflow.current_state = "COMPLETE"
        workflow.execution_status = "COMPLETED"
        workflow.completed_at = current_time
        workflow.updated_at = current_time
        state_data = dict(workflow.state_data or {})
        state_data.update(
            {
                "approval_status": "ALTERED",
                "current_state": "COMPLETE",
                "execution_status": "COMPLETED",
                "remediation_state": "NOT_STARTED",
                "updated_at": current_time.isoformat(),
                "completed_at": current_time.isoformat(),
            }
        )
        workflow.state_data = state_data

    return ALTERED_APPROVAL_REASON


def evaluate_approval(
    *,
    approval: Any,
    tenant_id: str,
    actor_id: str | None,
    workflow_id: str,
    current_plan: list[dict[str, Any]],
    now: datetime | None = None,
) -> ApprovalDecision:
    """Evaluate whether an approval may be consumed for exactly one execution."""
    current_time = _utc(now or datetime.now(timezone.utc))
    if str(approval.tenant_id) != str(tenant_id):
        return ApprovalDecision(False, "TENANT_MISMATCH", "Approval belongs to another tenant")
    if approval.action_id != workflow_id:
        return ApprovalDecision(False, "ACTION_MISMATCH", "Approval is bound to another workflow")
    if approval.expires_at and _utc(approval.expires_at) <= current_time:
        return ApprovalDecision(False, "EXPIRED", "Approval has expired")
    if approval.status == "CONSUMED" or getattr(approval, "consumed_at", None):
        return ApprovalDecision(False, "REPLAYED", "Approval has already been consumed")
    if approval.status != "APPROVED":
        return ApprovalDecision(False, "UNAPPROVED", f"Approval status is {approval.status}")
    if not actor_id or str(approval.approver_id) == str(actor_id):
        return ApprovalDecision(False, "USER_MISMATCH", "The approver cannot execute their own approval")

    expected_payload = build_action_payload(workflow_id, current_plan)
    stored_payload = approval.action_payload or {}
    if stored_payload != expected_payload:
        return ApprovalDecision(False, "ALTERED", "Remediation plan changed after approval was created")
    expected_hash = compute_action_hash(
        tenant_id=tenant_id,
        action_payload=stored_payload,
        expires_at=approval.expires_at,
    )
    if not approval.action_hash or approval.action_hash != expected_hash:
        return ApprovalDecision(False, "ALTERED", "Approval action hash is invalid")
    return ApprovalDecision(True, "APPROVED", "Approval is valid for one execution")

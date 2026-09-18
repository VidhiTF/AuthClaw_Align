"""
Compliance workflow API endpoints

Provides REST endpoints for managing LangGraph compliance workflows:
  POST /v1/workflows       - Start a new compliance workflow
  GET  /v1/workflows/{id}  - Get workflow status
  POST /v1/workflows/{id}/resume - Resume a paused workflow
  POST /v1/workflows/{id}/approve - Approve a workflow's remediation plan
  POST /v1/workflows/recover - Recover interrupted workflows
"""

import logging
import uuid
from typing import Annotated, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Discriminator, Field, Tag, TypeAdapter, ValidationError, field_validator
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.core.auth import (
    get_tenant_db,
    require_scopes,
)
from app.api.v1.endpoints.onboarding import _get_redis
from app.core.startup_checks import is_production
from app.db.models import PendingApproval, ComplianceWorkflow, User, ApprovalAudit, Tenant
from app.orchestrator.runner import ComplianceWorkflowRunner
from app.services.notifications import create_notification
from app.services.remediation_approval import (
    build_action_payload,
    compute_action_hash,
    mark_altered_approval_and_workflow,
)
from app.services.worker_throttle import check_worker_throttle
from app.services.abuse_controls import verify_mfa_challenge
from app.schemas.workflows import (
    RedTeamExecutionResult,
    RedTeamFinding,
    WorkflowExecutionResult,
    WorkflowFinding,
    WorkflowRemediationAction,
    WorkflowRemediationPlan,
    WorkflowRollbackResult,
)
from datetime import datetime, timedelta, timezone

logger = logging.getLogger("api.workflows")
router = APIRouter()


class WorkflowCreateRequest(BaseModel):
    framework: str = Field(..., description="Compliance framework: HIPAA, GDPR, SOC2")
    request_id: Optional[str] = Field(None, description="Optional request correlation ID")


class ApprovalRequest(BaseModel):
    totp_code: Optional[str] = Field(None, description="TOTP code or backup code for MFA validation")


class WorkflowResponseBase(BaseModel):
    workflow_id: str
    tenant_id: str
    framework: str
    current_state: str
    execution_status: str
    risk_score: Optional[float] = None
    remediation_state: Optional[str] = None
    remediation_actions: Optional[list[WorkflowRemediationAction]] = None
    rollback_result: Optional[WorkflowRollbackResult] = None
    approval_status: Optional[str] = None
    approval_id: Optional[str] = None
    error_message: Optional[str] = None
    retry_count: Optional[int] = 0
    started_at: Optional[str] = None
    updated_at: Optional[str] = None
    completed_at: Optional[str] = None


class WorkflowResponse(WorkflowResponseBase):
    framework: str = Field(..., json_schema_extra={"not": {"const": "RED_TEAM"}})
    findings: Optional[list[WorkflowFinding]] = None
    remediation_plan: Optional[list[WorkflowRemediationPlan]] = None
    execution_result: Optional[WorkflowExecutionResult] = None

    @field_validator("framework")
    @classmethod
    def compliance_framework(cls, value):
        if value == "RED_TEAM":
            raise ValueError("RED_TEAM requires its own response contract")
        return value


class RedTeamWorkflowResponse(WorkflowResponseBase):
    framework: Literal["RED_TEAM"]
    findings: Optional[list[RedTeamFinding]] = None
    remediation_plan: Optional[list[str]] = None
    execution_result: Optional[RedTeamExecutionResult] = None


def _workflow_variant(value):
    framework = value.get("framework") if isinstance(value, dict) else getattr(value, "framework", None)
    return "red_team" if framework == "RED_TEAM" else "compliance"


# A callable discriminator preserves legacy compliance framework strings while
# selecting RED_TEAM explicitly, including when serializing model instances.
WorkflowResponseVariant = Annotated[
    Annotated[WorkflowResponse, Tag("compliance")] | Annotated[RedTeamWorkflowResponse, Tag("red_team")],
    Discriminator(_workflow_variant),
]
_workflow_response_adapter = TypeAdapter(WorkflowResponseVariant)


def _workflow_response(result: dict) -> WorkflowResponseVariant:
    try:
        return _workflow_response_adapter.validate_python(result)
    except ValidationError:
        # Validation errors embed input values; never log persisted payloads.
        logger.error("Workflow response contract validation failed")
        raise HTTPException(status_code=500, detail="Internal server error") from None


class RecoveryResponse(BaseModel):
    recovered: int
    results: list


class GatewayApprovalResponse(BaseModel):
    id: str
    action_id: str
    action_type: str
    action_description: str
    action_payload: dict
    status: str
    requester_id: str
    approver_id: Optional[str] = None
    action_hash: Optional[str] = None
    consumed_at: Optional[str] = None
    expires_at: str
    created_at: str


def _approval_response(approval: PendingApproval) -> GatewayApprovalResponse:
    return GatewayApprovalResponse(
        id=str(approval.id),
        action_id=approval.action_id,
        action_type=approval.action_type,
        action_description=approval.action_description,
        action_payload=approval.action_payload or {},
        status=approval.status,
        requester_id=str(approval.requester_id),
        approver_id=str(approval.approver_id) if approval.approver_id else None,
        action_hash=approval.action_hash,
        consumed_at=approval.consumed_at.isoformat() if approval.consumed_at else None,
        expires_at=approval.expires_at.isoformat(),
        created_at=approval.created_at.isoformat(),
    )


def _enforce_separate_approver(
    db: Session,
    approval: PendingApproval,
    tenant_id: str,
    actor_id: uuid.UUID,
) -> None:
    """Reject maker/checker conflicts without resolving the pending approval."""
    if approval.requester_id != actor_id:
        return
    db.add(
        ApprovalAudit(
            id=uuid.uuid4(),
            tenant_id=uuid.UUID(tenant_id),
            approval_id=approval.id,
            actor_id=actor_id,
            action="SELF_APPROVAL_REJECTED",
            action_hash=approval.action_hash,
            reason="The requesting actor cannot approve this privileged action",
            details={"action_id": approval.action_id, "action_type": approval.action_type},
            mfa_verified=False,
            mfa_timestamp=None,
        )
    )
    db.commit()
    raise HTTPException(
        status_code=403,
        detail="A privileged action must be approved by a different authorized user",
    )


def _tenant_tier(db: Session, tenant_id: str) -> str:
    tenant = db.query(Tenant).filter(Tenant.id == uuid.UUID(tenant_id)).first()
    return tenant.tier if tenant else "starter"


@router.post("", response_model=WorkflowResponse, status_code=201)
def create_workflow(
    body: WorkflowCreateRequest,
    request: Request,
    db: Session = Depends(get_tenant_db),
    _auth=require_scopes(["write"]),
):
    """Start a new compliance workflow."""
    tenant_id = str(request.state.tenant_id)
    framework = body.framework.upper()

    if framework not in ("HIPAA", "GDPR", "SOC2"):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported framework: {framework}. Must be HIPAA, GDPR, or SOC2.",
        )
    allowed, retry_after = check_worker_throttle(tenant_id, "scan", tier=_tenant_tier(db, tenant_id))
    if not allowed:
        raise HTTPException(status_code=429, detail=f"Scan worker throttle exceeded. Retry after {retry_after:.0f}s.")

    try:
        runner = ComplianceWorkflowRunner(db)
        result = runner.start(
            tenant_id=tenant_id,
            framework=framework,
            requester_id=str(request.state.user_id),
            request_id=body.request_id,
        )
    except Exception as exc:
        logger.error("Failed to create workflow: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
    return _workflow_response(result)


@router.post("/{workflow_id}/resume", response_model=WorkflowResponseVariant)
def resume_workflow(
    workflow_id: str,
    request: Request,
    db: Session = Depends(get_tenant_db),
    _auth=require_scopes(["write"]),
):
    """Resume a paused workflow (typically after approval)."""
    tenant_id = str(request.state.tenant_id)

    try:
        runner = ComplianceWorkflowRunner(db)
        result = runner.resume(workflow_id, tenant_id, actor_id=str(request.state.user_id))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to resume workflow: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
    return _workflow_response(result)


def _auto_expire_stale(db: Session, tenant_id: str, actor_id: uuid.UUID) -> None:
    """Helper to auto-expire stale PENDING approvals and write immutable logs."""
    now = datetime.now(timezone.utc)
    stale = db.query(PendingApproval).filter(
        PendingApproval.tenant_id == uuid.UUID(tenant_id),
        PendingApproval.status == "PENDING",
        PendingApproval.expires_at < now
    ).all()
    
    for approval in stale:
        approval.status = "EXPIRED"
        wf = db.query(ComplianceWorkflow).filter(
            ComplianceWorkflow.approval_id == approval.id
        ).first()
        if wf:
            wf.approval_status = "EXPIRED"
            wf.execution_status = "COMPLETED"
            
        audit = ApprovalAudit(
            id=uuid.uuid4(),
            tenant_id=uuid.UUID(tenant_id),
            approval_id=approval.id,
            actor_id=actor_id,
            action="EXPIRED",
            action_hash=approval.action_hash,
            reason="Approval expired before a human decision",
            details={"action_id": approval.action_id, "status": "EXPIRED"},
            mfa_verified=False,
            mfa_timestamp=None,
        )
        db.add(audit)
    if stale:
        db.commit()


def _record_altered_approval_rejection(
    db: Session,
    *,
    approval: PendingApproval,
    workflow: Optional[ComplianceWorkflow],
    tenant_id: str,
    actor_id: uuid.UUID,
    workflow_id: str,
) -> None:
    """Reject a tampered approval and persist a terminal-safe workflow state."""
    reason = mark_altered_approval_and_workflow(
        approval=approval,
        workflow=workflow,
    )
    if workflow:
        flag_modified(workflow, "state_data")

    db.add(
        ApprovalAudit(
            id=uuid.uuid4(),
            tenant_id=uuid.UUID(tenant_id),
            approval_id=approval.id,
            actor_id=actor_id,
            action="ALTERED_REJECTED",
            action_hash=approval.action_hash,
            reason=reason,
            details={"workflow_id": workflow_id},
            mfa_verified=False,
            mfa_timestamp=None,
        )
    )
    db.commit()


def _verify_mfa_if_enabled(
    user: User,
    request: Request,
    body: Optional["ApprovalRequest"],
    required: bool = False,
    operation: str = "workflow_approval",
) -> tuple[bool, Optional[datetime]]:
    """Shared MFA verification for all HITL approval endpoints.

    Returns (mfa_verified, mfa_timestamp).
    Raises HTTPException if production approval execution is attempted without
    enrolled MFA, or if an enrolled user's supplied code is missing or invalid.
    """
    if not (user.mfa_enabled and user.mfa_secret):
        if required:
            raise HTTPException(
                status_code=403,
                detail="Fresh MFA enrollment is required before approving destructive remediation",
            )
        # Local/demo can approve before enrollment; production requires MFA setup first.
        if is_production():
            raise HTTPException(
                status_code=403,
                detail="MFA enrollment required before approving workflows in production",
            )
        return False, None

    header_names = {str(name).lower() for name in request.headers.keys()}
    if (
        "totp_code" in request.query_params
        or "x-mfa-code" in header_names
        or "x-totp-code" in header_names
    ):
        raise HTTPException(
            status_code=400,
            detail="MFA credentials must be provided in the JSON request body",
        )

    # Secrets are accepted only in the request body so URLs and headers cannot
    # retain them in proxy, access-log, or APM metadata.
    totp_code = body.totp_code if body else None

    if not totp_code:
        raise HTTPException(
            status_code=400,
            detail="MFA token required: your account has MFA enabled",
        )

    if verify_mfa_challenge(
        _get_redis(),
        user,
        totp_code,
        tenant_id=str(user.tenant_id),
        operation=operation,
        request_id=request.headers.get("x-request-id", ""),
    ):
        return True, datetime.now(timezone.utc)

    raise HTTPException(
        status_code=400,
        detail="Invalid MFA token or backup code",
    )


def _approval_requires_fresh_mfa(approval: PendingApproval) -> bool:
    plan = (approval.action_payload or {}).get("plan") or []
    return any(bool(item.get("destructive")) for item in plan if isinstance(item, dict))


def _has_fresh_mfa(mfa_verified: bool, mfa_timestamp: Optional[datetime]) -> bool:
    if not mfa_verified or not mfa_timestamp:
        return False
    timestamp = mfa_timestamp
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp >= datetime.now(timezone.utc) - timedelta(minutes=30)


@router.post("/mfa/setup", status_code=200)
def mfa_setup(
    request: Request,
    body: Optional[ApprovalRequest] = None,
    db: Session = Depends(get_tenant_db),
    _auth=require_scopes(["admin"]),
):
    """Retired unsafe one-step enrollment path."""
    raise HTTPException(
        status_code=410,
        detail="Use /v1/users/me/mfa/setup and /v1/users/me/mfa/confirm",
    )


@router.post("/approvals/expire-stale", status_code=200)
def expire_stale_approvals(
    request: Request,
    db: Session = Depends(get_tenant_db),
    _auth=require_scopes(["admin"]),
):
    """Explicitly trigger expiration of all stale pending approvals."""
    tenant_id = str(request.state.tenant_id)
    user_id = request.state.user_id
    
    now = datetime.now(timezone.utc)
    stale = db.query(PendingApproval).filter(
        PendingApproval.tenant_id == uuid.UUID(tenant_id),
        PendingApproval.status == "PENDING",
        PendingApproval.expires_at < now
    ).all()
    
    expired_count = len(stale)
    if expired_count > 0:
        _auto_expire_stale(db, tenant_id, user_id)
        
    return {"expired_count": expired_count}


@router.get("/approvals", response_model=list[GatewayApprovalResponse])
def list_gateway_approvals(
    request: Request,
    db: Session = Depends(get_tenant_db),
    _auth=require_scopes(["read"]),
):
    """List gateway HITL approvals for AuthClaw Lite."""
    tenant_id = str(request.state.tenant_id)
    approvals = db.query(PendingApproval).filter(
        PendingApproval.tenant_id == uuid.UUID(tenant_id),
        PendingApproval.action_type == "gateway_policy_egress",
    ).order_by(PendingApproval.created_at.desc()).limit(50).all()
    return [_approval_response(approval) for approval in approvals]


@router.post("/approvals/{approval_id}/approve", response_model=GatewayApprovalResponse)
def approve_gateway_approval(
    approval_id: str,
    request: Request,
    body: Optional[ApprovalRequest] = None,
    db: Session = Depends(get_tenant_db),
    _auth=require_scopes(["admin"]),
):
    """Approve a gateway HITL approval so the waiting request may continue (MFA challenged)."""
    tenant_id = str(request.state.tenant_id)
    user_id = request.state.user_id
    _auto_expire_stale(db, tenant_id, user_id)

    approval = db.query(PendingApproval).filter(
        PendingApproval.tenant_id == uuid.UUID(tenant_id),
        PendingApproval.id == uuid.UUID(approval_id),
        PendingApproval.action_type == "gateway_policy_egress",
    ).with_for_update().first()
    if not approval:
        raise HTTPException(status_code=404, detail="Approval not found")
    if approval.status != "PENDING":
        raise HTTPException(status_code=400, detail=f"Approval already resolved: {approval.status}")
    _enforce_separate_approver(db, approval, tenant_id, user_id)

    # Verify MFA for the approving user (enforced when MFA is enabled on their account)
    user = db.query(User).filter(
        User.id == user_id,
        User.tenant_id == uuid.UUID(tenant_id),
    ).with_for_update().first()
    if not user:
        raise HTTPException(status_code=404, detail="Approver user record not found")
    mfa_verified, mfa_timestamp = _verify_mfa_if_enabled(
        user, request, body, required=True, operation="gateway_approval"
    )

    approval.status = "APPROVED"
    approval.approver_id = user_id
    approval.approved_at = datetime.now(timezone.utc)
    approval.updated_at = datetime.now(timezone.utc)
    approval.mfa_verified = mfa_verified
    approval.mfa_timestamp = mfa_timestamp

    # Write immutable audit entry (was previously missing for gateway approvals)
    audit = ApprovalAudit(
        id=uuid.uuid4(),
        tenant_id=uuid.UUID(tenant_id),
        approval_id=approval.id,
        actor_id=user_id,
        action="APPROVED",
        mfa_verified=mfa_verified,
        mfa_timestamp=mfa_timestamp,
    )
    db.add(audit)
    db.commit()
    db.refresh(approval)
    return _approval_response(approval)


@router.post("/approvals/{approval_id}/reject", response_model=GatewayApprovalResponse)
def reject_gateway_approval(
    approval_id: str,
    request: Request,
    db: Session = Depends(get_tenant_db),
    _auth=require_scopes(["admin"]),
):
    """Reject a gateway HITL approval so the waiting request is blocked."""
    tenant_id = str(request.state.tenant_id)
    user_id = request.state.user_id
    _auto_expire_stale(db, tenant_id, user_id)

    approval = db.query(PendingApproval).filter(
        PendingApproval.tenant_id == uuid.UUID(tenant_id),
        PendingApproval.id == uuid.UUID(approval_id),
        PendingApproval.action_type == "gateway_policy_egress",
    ).first()
    if not approval:
        raise HTTPException(status_code=404, detail="Approval not found")
    if approval.status != "PENDING":
        raise HTTPException(status_code=400, detail=f"Approval already resolved: {approval.status}")

    approval.status = "REJECTED"
    approval.approver_id = user_id
    approval.approved_at = datetime.now(timezone.utc)
    approval.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(approval)
    return _approval_response(approval)


@router.get("", response_model=list[WorkflowResponseVariant])
def list_workflows(
    request: Request,
    db: Session = Depends(get_tenant_db),
    _auth=require_scopes(["read"]),
):
    """List recent workflows inside the authenticated tenant boundary."""
    tenant_id = str(request.state.tenant_id)
    rows = (
        db.query(ComplianceWorkflow.workflow_id)
        .filter(ComplianceWorkflow.tenant_id == uuid.UUID(tenant_id))
        .order_by(ComplianceWorkflow.started_at.desc())
        .limit(50)
        .all()
    )
    runner = ComplianceWorkflowRunner(db)
    return [
        _workflow_response(result)
        for row in rows
        if (result := runner.get_status(row.workflow_id, tenant_id)) is not None
    ]


@router.get("/{workflow_id}", response_model=WorkflowResponseVariant)
def get_workflow(
    workflow_id: str,
    request: Request,
    db: Session = Depends(get_tenant_db),
    _auth=require_scopes(["read"]),
):
    """Get workflow status by ID."""
    tenant_id = str(request.state.tenant_id)

    runner = ComplianceWorkflowRunner(db)
    result = runner.get_status(workflow_id, tenant_id)

    if not result:
        raise HTTPException(status_code=404, detail="Workflow not found")

    return _workflow_response(result)


@router.post("/{workflow_id}/approve", response_model=WorkflowResponseVariant)
def approve_workflow(
    workflow_id: str,
    request: Request,
    body: Optional[ApprovalRequest] = None,
    db: Session = Depends(get_tenant_db),
    _auth=require_scopes(["admin"]),
):
    """Approve a workflow's remediation plan and resume execution (MFA challenged)."""
    tenant_id = str(request.state.tenant_id)
    user_id = request.state.user_id
    
    # Run auto-expiry checks
    _auto_expire_stale(db, tenant_id, user_id)

    runner = ComplianceWorkflowRunner(db)
    status_dict = runner.get_status(workflow_id, tenant_id)

    if not status_dict:
        raise HTTPException(status_code=404, detail="Workflow not found")

    if status_dict.get("execution_status") != "PAUSED":
        raise HTTPException(
            status_code=400,
            detail=f"Workflow is not awaiting approval (status={status_dict.get('execution_status')})",
        )

    approval_id = status_dict.get("approval_id")
    if not approval_id:
        raise HTTPException(status_code=400, detail="No approval associated with this workflow")

    approval = db.query(PendingApproval).filter(
        PendingApproval.tenant_id == uuid.UUID(tenant_id),
        PendingApproval.id == uuid.UUID(approval_id),
        PendingApproval.action_id == workflow_id,
        PendingApproval.action_type == "remediation",
    ).with_for_update().first()
    
    if not approval:
        raise HTTPException(status_code=404, detail="Approval record not found")

    if approval.status != "PENDING":
        raise HTTPException(
            status_code=400,
            detail=f"Approval request is already resolved (status={approval.status})",
        )
    _enforce_separate_approver(db, approval, tenant_id, user_id)

    wf = db.query(ComplianceWorkflow).filter(
        ComplianceWorkflow.workflow_id == workflow_id,
        ComplianceWorkflow.tenant_id == uuid.UUID(tenant_id),
    ).first()
    expected_payload = build_action_payload(workflow_id, (wf.remediation_plan if wf else []) or [])
    expected_hash = compute_action_hash(
        tenant_id=tenant_id,
        action_payload=approval.action_payload or {},
        expires_at=approval.expires_at,
    )
    if approval.action_payload != expected_payload or approval.action_hash != expected_hash:
        _record_altered_approval_rejection(
            db,
            approval=approval,
            workflow=wf,
            tenant_id=tenant_id,
            actor_id=user_id,
            workflow_id=workflow_id,
        )
        raise HTTPException(status_code=409, detail="Approval action binding is invalid")

    # Validate MFA if enabled on user (uses shared helper)
    user = db.query(User).filter(
        User.id == user_id,
        User.tenant_id == uuid.UUID(tenant_id),
    ).with_for_update().first()
    if not user:
        raise HTTPException(status_code=404, detail="Approver user record not found")

    requires_fresh_mfa = _approval_requires_fresh_mfa(approval)
    mfa_verified, mfa_timestamp = _verify_mfa_if_enabled(
        user,
        request,
        body,
        required=requires_fresh_mfa,
        operation="destructive_remediation" if requires_fresh_mfa else "workflow_approval",
    )
    if requires_fresh_mfa and not _has_fresh_mfa(mfa_verified, mfa_timestamp):
        raise HTTPException(status_code=403, detail="Fresh MFA is required for destructive remediation")

    # Update PendingApproval (non-transferable, bound to current user)
    approval.status = "APPROVED"
    approval.approver_id = user_id
    approval.approved_at = datetime.now(timezone.utc)
    approval.mfa_verified = mfa_verified
    approval.mfa_timestamp = mfa_timestamp

    # Sync workflow status
    wf = db.query(ComplianceWorkflow).filter(
        ComplianceWorkflow.workflow_id == workflow_id,
        ComplianceWorkflow.tenant_id == uuid.UUID(tenant_id),
    ).first()
    if wf:
        wf.approval_status = "APPROVED"
        
    # Write to immutable ApprovalAudit log
    audit = ApprovalAudit(
        id=uuid.uuid4(),
        tenant_id=uuid.UUID(tenant_id),
        approval_id=approval.id,
        actor_id=user_id,
        action="APPROVED",
        action_hash=approval.action_hash,
        reason="Human approver authorized the immutable remediation plan",
        details={"workflow_id": workflow_id, "expires_at": approval.expires_at.isoformat()},
        mfa_verified=mfa_verified,
        mfa_timestamp=mfa_timestamp,
    )
    db.add(audit)
    db.commit()

    # Resume workflow execution
    try:
        result = runner.resume(workflow_id, tenant_id, actor_id=str(user_id))
        remediation_state = str(result.get("remediation_state") or "")
        if remediation_state in {"SUCCEEDED", "FAILED", "PARTIAL_FAILED", "ROLLBACK_FAILED"}:
            failed = remediation_state != "SUCCEEDED"
            create_notification(
                db,
                tenant_id=uuid.UUID(tenant_id),
                type="remediation_failed" if failed else "remediation_completed",
                severity="critical" if failed else "info",
                title="Remediation failed" if failed else "Remediation completed",
                body=f"{workflow_id} finished with remediation state {remediation_state}.",
                link="/agent",
            )
    except Exception as exc:
        logger.error("Failed to approve/resume workflow: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
    return _workflow_response(result)


@router.post("/{workflow_id}/reject", response_model=WorkflowResponseVariant)
def reject_workflow(
    workflow_id: str,
    request: Request,
    db: Session = Depends(get_tenant_db),
    _auth=require_scopes(["admin"]),
):
    """Reject a workflow's remediation plan."""
    tenant_id = str(request.state.tenant_id)
    user_id = request.state.user_id

    runner = ComplianceWorkflowRunner(db)
    status_dict = runner.get_status(workflow_id, tenant_id)

    if not status_dict:
        raise HTTPException(status_code=404, detail="Workflow not found")

    if status_dict.get("execution_status") != "PAUSED":
        raise HTTPException(
            status_code=400,
            detail=f"Workflow is not awaiting approval (status={status_dict.get('execution_status')})",
        )

    approval_id = status_dict.get("approval_id")
    if not approval_id:
        raise HTTPException(status_code=400, detail="No approval associated with this workflow")

    approval = db.query(PendingApproval).filter(
        PendingApproval.tenant_id == uuid.UUID(tenant_id),
        PendingApproval.id == uuid.UUID(approval_id),
        PendingApproval.action_id == workflow_id,
        PendingApproval.action_type == "remediation",
    ).first()

    if not approval:
        raise HTTPException(status_code=404, detail="Approval record not found")

    if approval.status != "PENDING":
        raise HTTPException(
            status_code=400,
            detail=f"Approval request is already resolved (status={approval.status})",
        )

    # Reject
    approval.status = "REJECTED"
    approval.approver_id = user_id
    approval.approved_at = datetime.now(timezone.utc)

    # Sync workflow status
    wf = db.query(ComplianceWorkflow).filter(
        ComplianceWorkflow.workflow_id == workflow_id,
        ComplianceWorkflow.tenant_id == uuid.UUID(tenant_id),
    ).first()
    if wf:
        wf.approval_status = "REJECTED"

    # Write to ApprovalAudit
    audit = ApprovalAudit(
        id=uuid.uuid4(),
        tenant_id=uuid.UUID(tenant_id),
        approval_id=approval.id,
        actor_id=user_id,
        action="REJECTED",
        action_hash=approval.action_hash,
        reason="Human approver rejected the remediation plan",
        details={"workflow_id": workflow_id},
        mfa_verified=False,
        mfa_timestamp=None,
    )
    db.add(audit)
    db.commit()

    # Resume workflow (which wraps up since it's rejected)
    try:
        result = runner.resume(workflow_id, tenant_id, actor_id=str(user_id))
    except Exception as exc:
        logger.error("Failed to reject/resume workflow: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
    return _workflow_response(result)


@router.post("/{workflow_id}/remediate", response_model=WorkflowResponseVariant)
def remediate_workflow(
    workflow_id: str,
    request: Request,
    db: Session = Depends(get_tenant_db),
    _auth=require_scopes(["write"]),
):
    """Transition a completed scan into remediation mode and generate approval request."""
    tenant_id = str(request.state.tenant_id)

    # Fetch workflow record
    wf = db.query(ComplianceWorkflow).filter(
        ComplianceWorkflow.workflow_id == workflow_id,
        ComplianceWorkflow.tenant_id == uuid.UUID(tenant_id),
    ).first()

    if not wf:
        raise HTTPException(status_code=404, detail="Workflow not found")

    if wf.execution_status != "COMPLETED":
        raise HTTPException(
            status_code=400,
            detail=f"Workflow is not in COMPLETED state (current={wf.execution_status})",
        )

    if not wf.remediation_plan:
        raise HTTPException(
            status_code=400,
            detail="No remediation plan is available for this workflow",
        )

    state_data = dict(wf.state_data or {})
    workflow_requester_id = str(state_data.get("requester_id") or "").strip()
    try:
        uuid.UUID(workflow_requester_id)
    except (TypeError, ValueError, AttributeError):
        raise HTTPException(
            status_code=409,
            detail="Workflow requester identity is unavailable; remediation is denied",
        )

    remediation_requester_id = str(request.state.user_id)
    existing_remediation_requester = str(
        state_data.get("remediation_requester_id") or ""
    ).strip()
    if existing_remediation_requester and existing_remediation_requester != remediation_requester_id:
        raise HTTPException(
            status_code=409,
            detail="Workflow remediation requester identity is immutable",
        )
    allowed, retry_after = check_worker_throttle(tenant_id, "remediation", tier=_tenant_tier(db, tenant_id))
    if not allowed:
        raise HTTPException(status_code=429, detail=f"Remediation worker throttle exceeded. Retry after {retry_after:.0f}s.")

    # Dynamically create pending approval
    from app.orchestrator.runner import _create_approval_in_db, emit_audit_event
    approval_id = _create_approval_in_db(
        db,
        tenant_id,
        workflow_id,
        wf.remediation_plan,
        requester_id=remediation_requester_id,
    )

    # Transition workflow to PAUSED/AWAITING_APPROVAL
    wf.execution_status = "PAUSED"
    wf.current_state = "AWAITING_APPROVAL"
    wf.approval_status = "PENDING"
    wf.approval_id = uuid.UUID(approval_id)

    # Update state_data
    state_data.update({
        "current_state": "AWAITING_APPROVAL",
        "remediation_requester_id": remediation_requester_id,
        "execution_status": "PAUSED",
        "remediation_state": "NOT_STARTED",
        "remediation_actions": [],
        "rollback_result": {},
        "approval_status": "PENDING",
        "approval_id": approval_id,
    })
    wf.state_data = state_data
    flag_modified(wf, "state_data")
    wf.updated_at = datetime.now(timezone.utc)

    db.commit()
    create_notification(
        db,
        tenant_id=uuid.UUID(tenant_id),
        type="approval_requested",
        severity="warning",
        title="Approval requested",
        body=f"Workflow {workflow_id} is waiting for remediation approval.",
        link="/agent",
    )

    emit_audit_event(
        workflow_id, tenant_id, wf.request_id or "",
        "COMPLETE→AWAITING_APPROVAL", "create_approval", "pending"
    )

    runner = ComplianceWorkflowRunner(db)
    result = runner.get_status(workflow_id, tenant_id)
    return _workflow_response(result)


@router.post("/recover", response_model=RecoveryResponse)
def recover_workflows(
    request: Request,
    db: Session = Depends(get_tenant_db),
    _auth=require_scopes(["admin"]),
):
    """Recover all interrupted workflows for the current tenant."""
    tenant_id = str(request.state.tenant_id)

    runner = ComplianceWorkflowRunner(db)
    results = runner.recover_interrupted(tenant_id, actor_id=str(request.state.user_id))

    return RecoveryResponse(
        recovered=len([r for r in results if r["status"] == "recovered"]),
        results=results,
    )

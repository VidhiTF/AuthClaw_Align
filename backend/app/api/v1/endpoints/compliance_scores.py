"""Live compliance scoring endpoints."""

from __future__ import annotations

from typing import Any
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.auth import get_tenant_db, get_tenant_score_db, require_permission, require_scopes
from app.db.models import PendingApproval, User
from app.services import compliance_scoring, control_assessments

router = APIRouter()


class EvidenceAssessmentResponse(BaseModel):
    state: str
    reason_codes: list[str]
    required_count: int
    qualified_count: int
    as_of: str
    valid_until: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)


class ActivityDiagnosticsResponse(BaseModel):
    authoritative: bool = False
    score: float
    evidence: list[str]
    gaps: list[str]


class ControlScoreResponse(BaseModel):
    id: str
    name: str
    description: str
    weight: float
    score: float
    status: str
    evidence: list[str]
    activity_diagnostics: ActivityDiagnosticsResponse | None = None
    gaps: list[str]
    exceptions: list[dict[str, Any]] = Field(default_factory=list)
    product_owners: list[str] = Field(default_factory=list)
    operational_owners: list[str] = Field(default_factory=list)
    implementation_status: str = "not_mapped"
    evidence_sources: list[str] = Field(default_factory=list)
    collection_frequency: str = "Not mapped"
    traceability: dict[str, Any] | None = None
    evidence_assessment: EvidenceAssessmentResponse | None = None
    calculation_version: str = "legacy_unversioned"


class FrameworkScoreResponse(BaseModel):
    framework: str
    score: float
    readiness_level: str
    controls: list[ControlScoreResponse]
    metrics: dict[str, Any]
    generated_at: str
    calculation_version: str = "legacy_unversioned"


class TrustSummaryCountsResponse(BaseModel):
    verified: int
    in_progress: int
    planned: int


class TrustSummaryEvidenceAssessmentResponse(BaseModel):
    state: str
    reason_codes: list[str]
    required_count: int
    qualified_count: int
    as_of: str
    valid_until: str | None = None


class TrustSummaryControlResponse(BaseModel):
    framework: str
    id: str
    name: str
    score: float
    status: str
    evidence_assessment: TrustSummaryEvidenceAssessmentResponse | None = None
    gaps: list[str] = Field(default_factory=list)


class TrustSummaryResponse(BaseModel):
    generated_at: str
    counts: TrustSummaryCountsResponse
    verified: list[TrustSummaryControlResponse]
    in_progress: list[TrustSummaryControlResponse]
    planned: list[TrustSummaryControlResponse]
    calculation_version: str = "legacy_unversioned"


class ComplianceScoreResponse(BaseModel):
    overall_score: float
    readiness_level: str
    frameworks: list[FrameworkScoreResponse]
    generated_at: str
    trust_summary: TrustSummaryResponse | None = None
    calculation_version: str = "legacy_unversioned"


class AssessmentReviewRequest(BaseModel):
    approve: bool
    action_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason: str = Field(min_length=20, max_length=2000)
    totp_code: str = Field(min_length=6, max_length=128, repr=False)


class AssessmentApprovalResponse(BaseModel):
    approval_id: UUID
    requester_id: UUID
    status: str
    action_hash: str
    expires_at: datetime
    calculation_version: str
    assessment: control_assessments.AssessmentProposal


class AssessmentDecisionResponse(BaseModel):
    approval_id: UUID
    status: str
    evidence_id: UUID | None = None
    calculation_version: str


def _assessment_response(approval: PendingApproval) -> dict:
    return {"approval_id": approval.id, "requester_id": approval.requester_id,
            "status": approval.status, "action_hash": approval.action_hash,
            "expires_at": approval.expires_at, **{
                key: approval.action_payload[key] for key in ("calculation_version", "assessment")}}


def _assessment_actor(db: Session, request: Request) -> User:
    user_id = getattr(request.state, "user_id", None)
    if getattr(request.state, "credential_kind", None) != "session" or not user_id:
        raise HTTPException(status_code=403, detail="An authenticated tenant user session is required")
    user = db.query(User).filter(User.id == user_id, User.tenant_id == request.state.tenant_id,
                                 User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=403, detail="Authenticated tenant user required")
    return user


@router.post("/assessments", response_model=AssessmentApprovalResponse, status_code=201,
             dependencies=[require_permission("tenant.users.manage"), require_scopes(["write"])])
def propose_control_assessment(payload: control_assessments.AssessmentProposal, request: Request,
                               db: Session = Depends(get_tenant_db)):
    actor = _assessment_actor(db, request)
    try:
        approval = control_assessments.propose_assessment(db, str(request.state.tenant_id), str(actor.id), payload)
        response = _assessment_response(approval)
        db.commit()
        return response
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/assessments/{approval_id}", response_model=AssessmentApprovalResponse,
            dependencies=[require_permission("tenant.audit.read"), require_scopes(["read"])])
def get_control_assessment(approval_id: UUID, request: Request, db: Session = Depends(get_tenant_db)):
    _assessment_actor(db, request)
    approval = db.query(PendingApproval).filter(PendingApproval.id == approval_id,
        PendingApproval.tenant_id == request.state.tenant_id,
        PendingApproval.action_type == "control_assessment").first()
    if not approval:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return _assessment_response(approval)


@router.post("/assessments/{approval_id}/review", response_model=AssessmentDecisionResponse,
             dependencies=[require_permission("tenant.high_risk.approve"), require_scopes(["write"])])
def review_control_assessment(approval_id: UUID, payload: AssessmentReviewRequest, request: Request,
                              db: Session = Depends(get_tenant_db)):
    from app.api.v1.endpoints.workflows import _verify_mfa_if_enabled
    actor = _assessment_actor(db, request)
    approval = db.query(PendingApproval).filter(PendingApproval.id == approval_id,
        PendingApproval.tenant_id == request.state.tenant_id,
        PendingApproval.action_type == "control_assessment").with_for_update().first()
    if not approval:
        raise HTTPException(status_code=404, detail="Assessment not found")
    if approval.action_hash != payload.action_hash:
        raise HTTPException(status_code=409, detail="Review the current assessment before deciding")
    try:
        actor = control_assessments.lock_review_principals(db, request.state.tenant_id,
                                                          approval.requester_id, actor.id)
        _, timestamp = _verify_mfa_if_enabled(actor, request, payload, required=True,
                                              operation="control_assessment_review")
        evidence = control_assessments.review_assessment(db, str(request.state.tenant_id), str(approval_id),
            str(actor.id), payload.approve, payload.reason, timestamp)
        response = {"approval_id": approval_id, "status": "CONSUMED" if evidence else "REJECTED",
                    "evidence_id": evidence.id if evidence else None,
                    "calculation_version": control_assessments.CALCULATION_VERSION}
        db.commit()
        return response
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("", response_model=ComplianceScoreResponse, dependencies=[require_scopes(["read"])])
def get_compliance_scores(
    request: Request,
    persist_snapshot: bool = Query(default=True),
    db: Session = Depends(get_tenant_score_db),
):
    return compliance_scoring.score_all_frameworks(
        db,
        str(request.state.tenant_id),
        persist=persist_snapshot,
        include_traceability=True,
    )


@router.get("/history/trend", dependencies=[require_scopes(["read"])])
def get_compliance_score_history(
    request: Request,
    framework: str | None = None,
    days: int = Query(default=30, ge=1, le=365),
    db: Session = Depends(get_tenant_db),
):
    return {
        "items": compliance_scoring.score_history(
            db,
            str(request.state.tenant_id),
            framework=framework,
            days=days,
        )
    }


@router.get("/{framework}", response_model=FrameworkScoreResponse, dependencies=[require_scopes(["read"])])
def get_framework_score(
    framework: str,
    request: Request,
    persist_snapshot: bool = Query(default=True),
    db: Session = Depends(get_tenant_score_db),
):
    try:
        score = compliance_scoring.score_framework(db, str(request.state.tenant_id), framework)
        if persist_snapshot:
            compliance_scoring.upsert_score_snapshot(db, str(request.state.tenant_id), score)
        return score
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

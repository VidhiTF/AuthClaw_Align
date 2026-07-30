"""Live compliance scoring endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.auth import get_tenant_db, require_scopes
from app.services import compliance_scoring

router = APIRouter()


class ControlScoreResponse(BaseModel):
    id: str
    name: str
    description: str
    weight: float
    score: float
    status: str
    evidence: list[str]
    gaps: list[str]
    exceptions: list[dict[str, Any]] = Field(default_factory=list)
    product_owners: list[str] = Field(default_factory=list)
    operational_owners: list[str] = Field(default_factory=list)
    implementation_status: str = "not_mapped"
    evidence_sources: list[str] = Field(default_factory=list)
    collection_frequency: str = "Not mapped"
    traceability: dict[str, Any] | None = None


class FrameworkScoreResponse(BaseModel):
    framework: str
    score: float
    readiness_level: str
    controls: list[ControlScoreResponse]
    metrics: dict[str, Any]
    generated_at: str


class TrustSummaryCountsResponse(BaseModel):
    verified: int
    in_progress: int
    planned: int


class TrustSummaryControlResponse(BaseModel):
    framework: str
    id: str
    name: str
    score: float
    status: str


class TrustSummaryResponse(BaseModel):
    generated_at: str
    counts: TrustSummaryCountsResponse
    verified: list[TrustSummaryControlResponse]
    in_progress: list[TrustSummaryControlResponse]
    planned: list[TrustSummaryControlResponse]


class ComplianceScoreResponse(BaseModel):
    overall_score: float
    readiness_level: str
    frameworks: list[FrameworkScoreResponse]
    generated_at: str
    trust_summary: TrustSummaryResponse | None = None


@router.get("", response_model=ComplianceScoreResponse, dependencies=[require_scopes(["read"])])
def get_compliance_scores(
    request: Request,
    persist_snapshot: bool = Query(default=True),
    db: Session = Depends(get_tenant_db),
):
    return compliance_scoring.score_all_frameworks(
        db,
        str(request.state.tenant_id),
        persist=persist_snapshot,
        include_traceability=False,
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
    db: Session = Depends(get_tenant_db),
):
    try:
        score = compliance_scoring.score_framework(db, str(request.state.tenant_id), framework)
        if persist_snapshot:
            compliance_scoring.upsert_score_snapshot(db, str(request.state.tenant_id), score)
        return score
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

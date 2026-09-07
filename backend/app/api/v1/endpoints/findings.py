"""Findings API endpoints."""

from typing import Any, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, field_validator
from sqlalchemy.orm import Session

from app.core.auth import get_current_tenant, get_tenant_db, require_roles, require_scopes
from app.db.models import FindingStatus
from app.services import findings_service

router = APIRouter()


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    workflow_id: Optional[str]
    evidence_id: Optional[UUID]
    framework: str
    finding_key: str
    title: str
    description: Optional[str]
    severity: str
    status: str
    finding_type: str
    risk_score: float
    remediation_summary: Optional[str]
    owner_user_id: Optional[UUID]
    created_at: Any
    updated_at: Any
    resolved_at: Optional[Any]
    evidence_created_at: Optional[Any] = None

class FindingListResponse(BaseModel):
    items: List[FindingResponse]
    total: int
    page: int
    page_size: int


class DashboardSummaryResponse(BaseModel):
    open_findings: int
    critical_findings: int
    resolved_findings: int
    average_risk_score: float
    severity_distribution: dict


class StatusUpdateRequest(BaseModel):
    status: FindingStatus
    remediation_summary: Optional[str] = None

    @field_validator("status", mode="before")
    @classmethod
    def normalize_status(cls, value):
        if isinstance(value, str):
            return value.strip().upper()
        return value


class AssignOwnerRequest(BaseModel):
    owner_user_id: Optional[str]


@router.get("", response_model=FindingListResponse, dependencies=[require_scopes(["read"])])
def list_findings(
    framework: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    finding_type: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_tenant_db),
    tenant_id: str = Depends(get_current_tenant),
):
    """List findings with optional filtering."""
    records, total = findings_service.list_findings(
        db,
        tenant_id=tenant_id,
        framework=framework,
        severity=severity,
        status=status,
        finding_type=finding_type,
        page=page,
        page_size=page_size,
    )
    return {
        "items": records,
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/summary/dashboard", response_model=DashboardSummaryResponse, dependencies=[require_scopes(["read"])])
def get_dashboard_summary(
    db: Session = Depends(get_tenant_db),
    tenant_id: str = Depends(get_current_tenant),
):
    """Get high-level metrics for the findings dashboard."""
    return findings_service.get_dashboard_summary(db, tenant_id=tenant_id)


@router.get("/summary/charts", dependencies=[require_scopes(["read"])])
def get_charts_data(
    db: Session = Depends(get_tenant_db),
    tenant_id: str = Depends(get_current_tenant),
):
    """Get chart data for the dashboard."""
    return {
        "severity_breakdown": findings_service.severity_breakdown(db, tenant_id),
        "status_breakdown": findings_service.status_breakdown(db, tenant_id),
        "framework_breakdown": findings_service.framework_breakdown(db, tenant_id),
        "trend_summary": findings_service.trend_summary(db, tenant_id),
    }


@router.get("/{finding_id}", response_model=FindingResponse, dependencies=[require_scopes(["read"])])
def get_finding(
    finding_id: str,
    db: Session = Depends(get_tenant_db),
    tenant_id: str = Depends(get_current_tenant),
):
    """Get a specific finding by ID."""
    finding = findings_service.get_finding(db, tenant_id=tenant_id, finding_id=finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.get("/workflow/{workflow_id}", response_model=List[FindingResponse], dependencies=[require_scopes(["read"])])
def get_findings_by_workflow(
    workflow_id: str,
    db: Session = Depends(get_tenant_db),
    tenant_id: str = Depends(get_current_tenant),
):
    """Get all findings associated with a specific workflow."""
    return findings_service.get_findings_by_workflow(db, tenant_id=tenant_id, workflow_id=workflow_id)


@router.patch(
    "/{finding_id}/status",
    response_model=FindingResponse,
    dependencies=[require_roles(["owner", "admin"]), require_scopes(["write"])],
)
def update_status(
    finding_id: str,
    req: StatusUpdateRequest,
    db: Session = Depends(get_tenant_db),
    tenant_id: str = Depends(get_current_tenant),
):
    """Update the status of a finding."""
    if req.status in findings_service.TERMINAL_FINDING_STATUSES:
        remediation_summary = req.remediation_summary or f"Status changed to {req.status.value}"
        finding = findings_service.resolve_finding(
            db,
            tenant_id=tenant_id,
            finding_id=finding_id,
            status=req.status,
            remediation_summary=remediation_summary,
        )
    else:
        finding = findings_service.update_status(
            db, tenant_id=tenant_id, finding_id=finding_id, status=req.status
        )
        
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch(
    "/{finding_id}/assign",
    response_model=FindingResponse,
    dependencies=[require_roles(["owner", "admin"]), require_scopes(["write"])],
)
def assign_owner(
    finding_id: str,
    req: AssignOwnerRequest,
    db: Session = Depends(get_tenant_db),
    tenant_id: str = Depends(get_current_tenant),
):
    """Assign an owner to a finding."""
    finding = findings_service.assign_owner(
        db, tenant_id=tenant_id, finding_id=finding_id, owner_user_id=req.owner_user_id
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding

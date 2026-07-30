"""
Evidence repository API endpoints

GET  /v1/evidence                          — Paginated list with optional filters
GET  /v1/evidence/{evidence_id}            — Single evidence record + links
GET  /v1/evidence/workflow/{workflow_id}   — All evidence for a workflow
GET  /v1/evidence/framework/{framework}    — All evidence for a framework (paginated)

All endpoints enforce tenant_id isolation via existing auth middleware.
All responses are read-only — evidence records are immutable once created.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.auth import get_tenant_db, require_scopes
from app.core.evidence_integrity import verify_evidence_integrity
from app.services import evidence_service

logger = logging.getLogger("api.evidence")
router = APIRouter()


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class EvidenceLinkResponse(BaseModel):
    id: str
    linked_type: str
    linked_id: str
    created_at: datetime

    class Config:
        from_attributes = True


class EvidenceRecordResponse(BaseModel):
    id: str
    tenant_id: str
    workflow_id: Optional[str] = None
    framework: str
    source_type: str
    source_reference: Optional[str] = None
    evidence_type: str
    evidence_data: Dict[str, Any]
    severity: str
    created_at: datetime
    integrity_hash: str
    integrity_algorithm: str
    integrity_version: int
    integrity_verified: bool
    links: List[EvidenceLinkResponse] = Field(default_factory=list)

    class Config:
        from_attributes = True


class EvidenceListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[EvidenceRecordResponse]


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def _serialize_record(record, include_links: bool = False) -> dict:
    """Convert an EvidenceRecord ORM object to a dict safe for JSON responses."""
    data = {
        "id": str(record.id),
        "tenant_id": str(record.tenant_id),
        "workflow_id": record.workflow_id,
        "framework": record.framework,
        "source_type": record.source_type,
        "source_reference": record.source_reference,
        "evidence_type": record.evidence_type,
        "evidence_data": record.evidence_data or {},
        "severity": record.severity,
        "created_at": record.created_at,
        "integrity_hash": record.integrity_hash,
        "integrity_algorithm": record.integrity_algorithm,
        "integrity_version": record.integrity_version,
        "integrity_verified": verify_evidence_integrity(record),
        "links": [],
    }
    if include_links and hasattr(record, "links") and record.links:
        data["links"] = [
            {
                "id": str(lnk.id),
                "linked_type": lnk.linked_type,
                "linked_id": lnk.linked_id,
                "created_at": lnk.created_at,
            }
            for lnk in record.links
        ]
    return data


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=EvidenceListResponse)
def list_evidence(
    request: Request,
    framework: Optional[str] = Query(None, description="Filter by framework: GDPR, HIPAA, SOC2"),
    evidence_type: Optional[str] = Query(None, description="Filter by evidence type"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    db: Session = Depends(get_tenant_db),
    _auth=require_scopes(["read"]),
):
    """
    Paginated list of evidence records for the current tenant.

    Optional query parameters:
    - framework:      GDPR | HIPAA | SOC2
    - evidence_type:  pii_detected | policy_violation | approval_record | audit_log | scan_result
    - severity:       critical | high | medium | low | info
    - page / page_size
    """
    tenant_id = str(request.state.tenant_id)

    records, total = evidence_service.list_evidence(
        db,
        tenant_id=tenant_id,
        framework=framework,
        evidence_type=evidence_type,
        severity=severity,
        page=page,
        page_size=page_size,
    )

    return EvidenceListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[_serialize_record(r) for r in records],
    )


@router.get("/workflow/{workflow_id}", response_model=List[EvidenceRecordResponse])
def list_evidence_by_workflow(
    workflow_id: str,
    request: Request,
    db: Session = Depends(get_tenant_db),
    _auth=require_scopes(["read"]),
):
    """
    All evidence records for a given workflow, newest first.
    Tenant-isolated — cross-tenant workflow IDs return an empty list.
    """
    tenant_id = str(request.state.tenant_id)
    records = evidence_service.get_by_workflow(db, tenant_id=tenant_id, workflow_id=workflow_id)
    return [_serialize_record(r, include_links=True) for r in records]


@router.get("/framework/{framework}", response_model=EvidenceListResponse)
def list_evidence_by_framework(
    framework: str,
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_tenant_db),
    _auth=require_scopes(["read"]),
):
    """
    Paginated evidence for a specific compliance framework.
    Framework is case-insensitive (normalised to uppercase internally).
    """
    tenant_id = str(request.state.tenant_id)

    valid_frameworks = {"GDPR", "HIPAA", "SOC2"}
    if framework.upper() not in valid_frameworks:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown framework '{framework}'. Supported: {', '.join(valid_frameworks)}",
        )

    records, total = evidence_service.get_by_framework(
        db,
        tenant_id=tenant_id,
        framework=framework,
        page=page,
        page_size=page_size,
    )

    return EvidenceListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[_serialize_record(r) for r in records],
    )


@router.get("/{evidence_id}", response_model=EvidenceRecordResponse)
def get_evidence(
    evidence_id: str,
    request: Request,
    db: Session = Depends(get_tenant_db),
    _auth=require_scopes(["read"]),
):
    """
    Retrieve a single evidence record with its traceability links.
    Returns 404 if not found or tenant mismatch.
    """
    tenant_id = str(request.state.tenant_id)

    record = evidence_service.get_evidence(db, tenant_id=tenant_id, evidence_id=evidence_id)
    if not record:
        raise HTTPException(status_code=404, detail="Evidence record not found")

    return _serialize_record(record, include_links=True)

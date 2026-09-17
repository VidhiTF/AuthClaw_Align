"""
Evidence repository API endpoints

GET  /v1/evidence                          — Paginated list with optional filters
GET  /v1/evidence/{evidence_id}            — Single evidence record + links
GET  /v1/evidence/{evidence_id}/download   — Authorized evidence file stream
GET  /v1/evidence/workflow/{workflow_id}   — All evidence for a workflow
GET  /v1/evidence/framework/{framework}    — All evidence for a framework (paginated)

All endpoints enforce tenant_id isolation via existing auth middleware.
All responses are read-only — evidence records are immutable once created.
"""

import base64
import binascii
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import quote
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.auth import get_tenant_db, require_roles, require_scopes
from app.core.evidence_integrity import verify_evidence_integrity
from app.services import evidence_service

logger = logging.getLogger("api.evidence")
router = APIRouter()

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MEDIA_TYPE = re.compile(r"[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+\Z")


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


def _download_metadata(
    record, tenant_id: str, operation: str = "download"
) -> tuple[str, str, str, str]:
    """Return the storage binding for a downloadable, tenant-owned record."""
    data = record.evidence_data if isinstance(record.evidence_data, dict) else {}
    storage = data.get("storage") if isinstance(data.get("storage"), dict) else {}
    bucket = str(storage.get("bucket") or "")
    object_key = str(storage.get("object_key") or "")
    checksum = str(storage.get("sha256") or "").lower()
    retention_class = str(storage.get("retention_class") or "")
    policy = storage.get("access_policy")
    prefix = f"tenant-{tenant_id}/"
    invalid_key = (
        not object_key
        or "\\" in object_key
        or any(part in {"", ".", ".."} for part in object_key.split("/"))
    )
    if (
        str(record.tenant_id) != tenant_id
        or not bucket
        or invalid_key
        or not object_key.startswith(prefix)
        or not _SHA256.fullmatch(checksum)
        or not retention_class
        or not isinstance(policy, dict)
        or policy.get(f"allow_{operation}") is not True
    ):
        raise HTTPException(status_code=404, detail="Evidence file not found")
    return bucket, object_key, checksum, str(storage.get("content_type") or "")


def _audit_access(record, request: Request, operation: str, db: Session = None) -> None:
    """Persist an evidence-access audit event before returning protected data."""
    from app.services import event_backbone

    tenant_id = str(record.tenant_id)
    actor_id = str(getattr(request.state, "user_id", ""))
    try:
        UUID(actor_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=401, detail="Evidence actor is unavailable"
        ) from exc
    event = event_backbone.audit_event(
        event_type="evidence_access",
        tenant_id=tenant_id,
        subject_id=str(record.id),
        identity_action=f"{operation}:{uuid4()}",
        action=f"evidence:{operation}",
        reason=f"Evidence {operation} authorized",
        provider="evidence_api",
        request_id=request.headers.get("x-request-id", ""),
        actor_id=actor_id,
        actor_type="user",
        frameworks=[record.framework],
        trace=[
            f"evidence_id={record.id}",
            f"actor_id={actor_id}",
            f"purpose={operation}",
        ],
    )
    if event_backbone.publish_audit_event(None, tenant_id, event, db=db):
        raise HTTPException(status_code=503, detail="Evidence audit unavailable")


def _s3_client():
    import boto3

    return boto3.client("s3", region_name=os.getenv("AWS_REGION") or None)


def _stream_s3_body(body):
    try:
        yield from body.iter_chunks(chunk_size=64 * 1024)
    finally:
        body.close()


def _deletion_allowed(record) -> bool:
    data = record.evidence_data if isinstance(record.evidence_data, dict) else {}
    storage = data.get("storage") if isinstance(data.get("storage"), dict) else {}
    policy = (
        storage.get("access_policy")
        if isinstance(storage.get("access_policy"), dict)
        else {}
    )
    try:
        allowed_at = datetime.fromisoformat(
            str(storage.get("deletion_allowed_at", "")).replace("Z", "+00:00")
        )
    except ValueError:
        return False
    return (
        allowed_at.tzinfo is not None
        and policy.get("allow_delete") is True
        and allowed_at <= datetime.now(timezone.utc)
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=EvidenceListResponse)
def list_evidence(
    request: Request,
    framework: Optional[str] = Query(
        None, description="Filter by framework: GDPR, HIPAA, SOC2"
    ),
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
    for record in records:
        _audit_access(record, request, "view", db)

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
    records = evidence_service.get_by_workflow(
        db, tenant_id=tenant_id, workflow_id=workflow_id
    )
    for record in records:
        _audit_access(record, request, "view", db)
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
    for record in records:
        _audit_access(record, request, "view", db)

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

    record = evidence_service.get_evidence(
        db, tenant_id=tenant_id, evidence_id=evidence_id
    )
    if not record:
        raise HTTPException(status_code=404, detail="Evidence record not found")

    _audit_access(record, request, "view", db)
    return _serialize_record(record, include_links=True)


@router.get("/{evidence_id}/download")
def download_evidence(
    evidence_id: str,
    request: Request,
    db: Session = Depends(get_tenant_db),
    _auth=require_scopes(["read"]),
):
    """Stream a file only after its tenant-bound evidence record authorizes it."""
    tenant_id = str(request.state.tenant_id)
    record = evidence_service.get_evidence(
        db, tenant_id=tenant_id, evidence_id=evidence_id
    )
    if not record:
        raise HTTPException(status_code=404, detail="Evidence record not found")
    if not verify_evidence_integrity(record):
        raise HTTPException(
            status_code=409, detail="Evidence record integrity check failed"
        )
    bucket, object_key, checksum, content_type = _download_metadata(record, tenant_id)
    response = None
    try:
        client = _s3_client()
        response = client.get_object(
            Bucket=bucket, Key=object_key, ChecksumMode="ENABLED"
        )
        actual = base64.b64decode(
            str(response.get("ChecksumSHA256") or ""), validate=True
        ).hex()
        if actual != checksum:
            raise ValueError("checksum mismatch")
        _audit_access(record, request, "download", db)
    except Exception as exc:
        if response is not None:
            response["Body"].close()
        if isinstance(exc, HTTPException):
            raise
        invalid = isinstance(exc, (ValueError, TypeError, binascii.Error))
        logger.warning(
            "Evidence download failed evidence_id=%s: %s",
            evidence_id,
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=409 if invalid else 503,
            detail=(
                "Evidence file integrity check failed"
                if invalid
                else "Evidence storage unavailable"
            ),
        ) from exc

    filename = quote(object_key.rsplit("/", 1)[-1], safe="")
    safe_type = (
        content_type
        if _MEDIA_TYPE.fullmatch(content_type)
        else "application/octet-stream"
    )
    return StreamingResponse(
        _stream_s3_body(response["Body"]),
        media_type=safe_type,
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{filename}",
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.delete("/{evidence_id}/file", status_code=204)
def delete_evidence_file(
    evidence_id: str,
    request: Request,
    db: Session = Depends(get_tenant_db),
    _role=require_roles(["owner", "admin"]),
    _auth=require_scopes(["write"]),
):
    """Delete an expired file while retaining its immutable evidence record."""
    tenant_id = str(request.state.tenant_id)
    record = evidence_service.get_evidence(
        db, tenant_id=tenant_id, evidence_id=evidence_id
    )
    if not record:
        raise HTTPException(status_code=404, detail="Evidence record not found")
    if not verify_evidence_integrity(record):
        raise HTTPException(
            status_code=409, detail="Evidence record integrity check failed"
        )
    if not _deletion_allowed(record):
        raise HTTPException(
            status_code=403, detail="Evidence retention policy forbids deletion"
        )
    bucket, object_key, checksum, _ = _download_metadata(record, tenant_id, "delete")
    try:
        client = _s3_client()
        head = client.head_object(Bucket=bucket, Key=object_key, ChecksumMode="ENABLED")
        actual = base64.b64decode(
            str(head.get("ChecksumSHA256") or ""), validate=True
        ).hex()
        if actual != checksum:
            raise ValueError("checksum mismatch")
        if not head.get("ETag"):
            raise ValueError("missing object identity")
        _audit_access(record, request, "delete", db)
        client.delete_object(Bucket=bucket, Key=object_key, IfMatch=head["ETag"])
    except HTTPException:
        raise
    except (ValueError, TypeError, binascii.Error) as exc:
        raise HTTPException(
            status_code=409, detail="Evidence file integrity check failed"
        ) from exc
    except Exception as exc:
        logger.warning(
            "Evidence storage unavailable evidence_id=%s: %s",
            record.id,
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=503, detail="Evidence storage unavailable"
        ) from exc
    return Response(status_code=204)

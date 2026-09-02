"""Create, retrieve, search, link, and paginate tenant evidence records."""

import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.models import EvidenceRecord, EvidenceLink
from app.core.evidence_integrity import (
    INTEGRITY_ALGORITHM,
    INTEGRITY_VERSION,
    compute_evidence_integrity_hash,
)
from app.services import event_backbone

logger = logging.getLogger("services.evidence")

_kafka_producer = None


def _init_kafka_producer():
    """Lazy-init a Kafka producer for audit events. Non-fatal if unavailable."""
    global _kafka_producer
    if _kafka_producer is not None:
        return
    try:
        _kafka_producer = event_backbone.make_kafka_producer()
        logger.info("Kafka producer initialized for evidence audit events")
    except Exception as exc:
        logger.warning(
            "Kafka producer unavailable — evidence audit events logged to stdout only: %s", exc
        )


def _emit_evidence_audit(evidence_id: str, tenant_id: str, framework: str) -> None:
    """Emit an EVIDENCE_CREATED Kafka audit event. Never raises."""
    event = event_backbone.audit_event(
        event_type="evidence",
        tenant_id=tenant_id,
        subject_id=evidence_id,
        identity_action=f"EVIDENCE_CREATED:{framework}",
        action="evidence:EVIDENCE_CREATED",
        reason=f"Evidence record created for framework {framework}",
        provider="evidence_service",
        frameworks=[framework],
        trace=[f"evidence_id={evidence_id}"],
    )

    _init_kafka_producer()
    if exc := event_backbone.publish_audit_event(_kafka_producer, tenant_id, event):
        logger.warning("Failed to emit EVIDENCE_CREATED audit event to Kafka: %s", exc)

    logger.info(
        "[EVIDENCE_CREATED] evidence_id=%s tenant=%s framework=%s",
        evidence_id, tenant_id, framework,
    )


def create_evidence(
    db: Session,
    *,
    tenant_id: str,
    workflow_id: Optional[str],
    framework: str,
    source_type: str,
    source_reference: Optional[str],
    evidence_type: str,
    evidence_data: dict,
    severity: str = "info",
    linked_workflow_id: Optional[str] = None,
) -> EvidenceRecord:
    """
    Persist a new evidence record and optionally link it to its workflow.

    Parameters
    ----------
    db               : Active SQLAlchemy Session (tenant context already set by middleware).
    tenant_id        : UUID string of the owning tenant.
    workflow_id      : String workflow ID from ComplianceWorkflow.workflow_id (may be None).
    framework        : Compliance framework: GDPR, HIPAA, SOC2.
    source_type      : Origin category: s3_document | gateway_event | audit_event |
                       approval_event | policy_evaluation.
    source_reference : Human-readable reference to the source artifact (S3 key, audit ID…).
    evidence_type    : Classification: pii_detected | policy_violation | approval_record |
                       audit_log | scan_result.
    evidence_data    : Full structured payload (Presidio entities, approval details, etc.).
    severity         : critical | high | medium | low | info  (default: info).
    linked_workflow_id : When provided, an EvidenceLink of type "workflow" is also created.
    """
    evidence_id = uuid.uuid4()
    created_at = datetime.now(tz=timezone.utc)
    record = EvidenceRecord(
        id=evidence_id,
        tenant_id=uuid.UUID(tenant_id),
        workflow_id=workflow_id,
        framework=framework,
        source_type=source_type,
        source_reference=source_reference,
        evidence_type=evidence_type,
        evidence_data=evidence_data,
        severity=severity,
        integrity_hash=compute_evidence_integrity_hash(
            evidence_id=evidence_id,
            tenant_id=tenant_id,
            workflow_id=workflow_id,
            framework=framework,
            source_type=source_type,
            source_reference=source_reference,
            evidence_type=evidence_type,
            evidence_data=evidence_data,
            severity=severity,
            created_at=created_at,
        ),
        integrity_algorithm=INTEGRITY_ALGORITHM,
        integrity_version=INTEGRITY_VERSION,
        created_at=created_at,
    )
    db.add(record)

    # Auto-link to workflow if provided
    if linked_workflow_id or workflow_id:
        link_id = linked_workflow_id or workflow_id
        link = EvidenceLink(
            id=uuid.uuid4(),
            tenant_id=uuid.UUID(tenant_id),
            evidence_id=evidence_id,
            linked_type="workflow",
            linked_id=str(link_id),
            created_at=datetime.now(tz=timezone.utc),
        )
        db.add(link)

    try:
        db.commit()
        db.refresh(record)
    except Exception as exc:
        db.rollback()
        logger.error("Failed to persist evidence record: %s", exc)
        raise

    # Emit Kafka audit (non-fatal)
    try:
        _emit_evidence_audit(str(evidence_id), tenant_id, framework)
    except Exception as exc:
        logger.warning("Evidence audit emission failed (non-fatal): %s", exc)

    logger.debug(
        "Created evidence %s type=%s severity=%s workflow=%s",
        evidence_id, evidence_type, severity, workflow_id,
    )
    return record


def get_evidence(
    db: Session,
    *,
    tenant_id: str,
    evidence_id: str,
) -> Optional[EvidenceRecord]:
    """
    Retrieve a single evidence record by ID, enforcing tenant isolation.
    Returns None if not found or tenant mismatch.
    """
    try:
        eid = uuid.UUID(evidence_id)
    except ValueError:
        return None

    return (
        db.query(EvidenceRecord)
        .filter(
            EvidenceRecord.id == eid,
            EvidenceRecord.tenant_id == uuid.UUID(tenant_id),
        )
        .first()
    )


def list_evidence(
    db: Session,
    *,
    tenant_id: str,
    framework: Optional[str] = None,
    evidence_type: Optional[str] = None,
    severity: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
) -> Tuple[List[EvidenceRecord], int]:
    """
    Paginated list of evidence records for a tenant with optional filters.

    Returns
    -------
    (records, total_count)
    """
    q = db.query(EvidenceRecord).filter(
        EvidenceRecord.tenant_id == uuid.UUID(tenant_id)
    )

    if framework:
        q = q.filter(EvidenceRecord.framework == framework.upper())
    if evidence_type:
        q = q.filter(EvidenceRecord.evidence_type == evidence_type)
    if severity:
        q = q.filter(EvidenceRecord.severity == severity)

    total = q.count()
    records = (
        q.order_by(EvidenceRecord.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return records, total


def get_by_workflow(
    db: Session,
    *,
    tenant_id: str,
    workflow_id: str,
) -> List[EvidenceRecord]:
    """
    All evidence records for a given workflow, newest first.
    Tenant-isolated.
    """
    return (
        db.query(EvidenceRecord)
        .filter(
            EvidenceRecord.tenant_id == uuid.UUID(tenant_id),
            EvidenceRecord.workflow_id == workflow_id,
        )
        .order_by(EvidenceRecord.created_at.desc())
        .all()
    )


def get_by_framework(
    db: Session,
    *,
    tenant_id: str,
    framework: str,
    page: int = 1,
    page_size: int = 20,
) -> Tuple[List[EvidenceRecord], int]:
    """
    Paginated evidence records filtered by framework.
    Tenant-isolated.
    """
    q = db.query(EvidenceRecord).filter(
        EvidenceRecord.tenant_id == uuid.UUID(tenant_id),
        EvidenceRecord.framework == framework.upper(),
    )
    total = q.count()
    records = (
        q.order_by(EvidenceRecord.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return records, total


def link_evidence(
    db: Session,
    *,
    tenant_id: str,
    evidence_id: str,
    linked_type: str,
    linked_id: str,
) -> EvidenceLink:
    """
    Create an explicit traceability link between an evidence record and any entity.

    linked_type: finding | workflow | approval | report
    linked_id  : String identifier of the linked entity
    """
    try:
        eid = uuid.UUID(evidence_id)
    except ValueError as exc:
        raise ValueError(f"Invalid evidence_id: {evidence_id}") from exc
    link = EvidenceLink(
        id=uuid.uuid4(),
        tenant_id=uuid.UUID(tenant_id),
        evidence_id=eid,
        linked_type=linked_type,
        linked_id=linked_id,
        created_at=datetime.now(tz=timezone.utc),
    )
    db.add(link)
    db.commit()
    db.refresh(link)
    return link


def get_links(
    db: Session,
    *,
    tenant_id: str,
    evidence_id: str,
) -> List[EvidenceLink]:
    """Return all traceability links for a given evidence record."""
    try:
        eid = uuid.UUID(evidence_id)
    except ValueError:
        return []

    return (
        db.query(EvidenceLink)
        .filter(
            EvidenceLink.tenant_id == uuid.UUID(tenant_id),
            EvidenceLink.evidence_id == eid,
        )
        .all()
    )

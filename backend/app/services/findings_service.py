"""Create, search, update, and summarize compliance findings."""

import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict, Any

from sqlalchemy import func, text
from sqlalchemy.orm import Session, joinedload

from app.db.models import Finding, FindingStatus, EvidenceRecord
from app.services import event_backbone

logger = logging.getLogger("services.findings")

_kafka_producer = None

TERMINAL_FINDING_STATUSES = frozenset(
    {FindingStatus.RESOLVED, FindingStatus.FALSE_POSITIVE, FindingStatus.ACCEPTED_RISK}
)


def _coerce_finding_status(status: str | FindingStatus) -> FindingStatus:
    if isinstance(status, FindingStatus):
        return status
    return FindingStatus(status.strip().upper())


def _init_kafka_producer():
    """Lazy-init a Kafka producer for audit events. Non-fatal if unavailable."""
    global _kafka_producer
    if _kafka_producer is not None:
        return
    try:
        _kafka_producer = event_backbone.make_kafka_producer()
        logger.info("Kafka producer initialized for findings audit events")
    except Exception as exc:
        logger.warning(
            "Kafka producer unavailable — findings audit events logged to stdout only: %s", exc
        )


def _emit_finding_audit(finding_id: str, tenant_id: str, framework: str, action: str) -> None:
    """Emit a FINDING_CREATED or FINDING_UPDATED Kafka audit event. Never raises."""
    event = event_backbone.audit_event(
        event_type="finding",
        tenant_id=tenant_id,
        subject_id=finding_id,
        identity_action=f"{action}:{framework}",
        action=f"finding:{action}",
        reason=f"Finding record {action.lower()} for framework {framework}",
        provider="findings_service",
        frameworks=[framework],
        trace=[f"finding_id={finding_id}"],
    )

    _init_kafka_producer()
    if exc := event_backbone.publish_audit_event(_kafka_producer, tenant_id, event):
        logger.warning("Failed to emit %s audit event to Kafka: %s", action, exc)

    logger.info(
        "[%s] finding_id=%s tenant=%s framework=%s",
        action, finding_id, tenant_id, framework,
    )


def create_finding(
    db: Session,
    *,
    tenant_id: str,
    workflow_id: Optional[str],
    evidence_id: Optional[str],
    framework: str,
    finding_type: str,
    source_reference: str,
    title: str,
    description: Optional[str],
    severity: str = "medium",
    status: str = "OPEN",
    risk_score: float = 0.0,
    remediation_summary: Optional[str] = None,
) -> Finding:
    """
    Create or update a finding, deduplicating by finding_key.
    finding_key = framework|finding_type|source_reference
    """
    canonical_status = _coerce_finding_status(status).value
    finding_key = f"{framework}|{finding_type}|{source_reference}"
    
    existing = (
        db.query(Finding)
        .filter(
            Finding.tenant_id == uuid.UUID(tenant_id),
            Finding.finding_key == finding_key
        )
        .first()
    )
    
    if existing:
        # Update existing finding
        existing.workflow_id = workflow_id
        if evidence_id:
            existing.evidence_id = uuid.UUID(evidence_id)
        existing.title = title
        existing.description = description
        existing.severity = severity
        existing.risk_score = risk_score
        existing.remediation_summary = remediation_summary
        existing.updated_at = datetime.now(tz=timezone.utc)
        
        # If the finding was resolved, reopen it since the issue reappeared
        if existing.status in ("RESOLVED", "FALSE_POSITIVE", "ACCEPTED_RISK") and canonical_status == "OPEN":
            existing.status = "OPEN"
            existing.resolved_at = None
        elif canonical_status != "OPEN":
            # If explicit status provided (not the default OPEN), respect it
            existing.status = canonical_status
            
        db.commit()
        db.refresh(existing)
        
        try:
            _emit_finding_audit(str(existing.id), tenant_id, framework, "FINDING_UPDATED")
        except Exception as exc:
            logger.warning("Finding audit emission failed (non-fatal): %s", exc)
            
        return existing

    # Create new finding
    finding_id = uuid.uuid4()
    record = Finding(
        id=finding_id,
        tenant_id=uuid.UUID(tenant_id),
        workflow_id=workflow_id,
        evidence_id=uuid.UUID(evidence_id) if evidence_id else None,
        framework=framework,
        finding_key=finding_key,
        title=title,
        description=description,
        severity=severity,
        status=canonical_status,
        finding_type=finding_type,
        risk_score=risk_score,
        remediation_summary=remediation_summary,
        created_at=datetime.now(tz=timezone.utc),
        updated_at=datetime.now(tz=timezone.utc),
    )
    db.add(record)

    try:
        db.commit()
        db.refresh(record)
    except Exception as exc:
        db.rollback()
        logger.error("Failed to persist finding record: %s", exc)
        raise

    # Emit Kafka audit (non-fatal)
    try:
        _emit_finding_audit(str(finding_id), tenant_id, framework, "FINDING_CREATED")
    except Exception as exc:
        logger.warning("Finding audit emission failed (non-fatal): %s", exc)

    logger.debug(
        "Created finding %s type=%s severity=%s workflow=%s",
        finding_id, finding_type, severity, workflow_id,
    )
    return record


def get_finding(
    db: Session,
    *,
    tenant_id: str,
    finding_id: str,
) -> Optional[Finding]:
    try:
        fid = uuid.UUID(finding_id)
    except ValueError:
        return None

    f = (
        db.query(Finding)
        .options(joinedload(Finding.evidence))
        .filter(
            Finding.id == fid,
            Finding.tenant_id == uuid.UUID(tenant_id),
        )
        .first()
    )
    if f:
        f.evidence_created_at = f.evidence.created_at if f.evidence else None
    return f


def list_findings(
    db: Session,
    *,
    tenant_id: str,
    framework: Optional[str] = None,
    finding_type: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
) -> Tuple[List[Finding], int]:
    q = db.query(Finding).filter(Finding.tenant_id == uuid.UUID(tenant_id))

    if framework:
        q = q.filter(Finding.framework == framework.upper())
    if finding_type:
        q = q.filter(Finding.finding_type == finding_type)
    if severity:
        q = q.filter(Finding.severity == severity.lower())
    if status:
        q = q.filter(Finding.status == status.upper())

    total = q.count()
    records = (
        q.options(joinedload(Finding.evidence))
        .order_by(Finding.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    for r in records:
        r.evidence_created_at = r.evidence.created_at if r.evidence else None
    return records, total


def update_status(
    db: Session,
    *,
    tenant_id: str,
    finding_id: str,
    status: str,
) -> Optional[Finding]:
    finding = get_finding(db, tenant_id=tenant_id, finding_id=finding_id)
    if not finding:
        return None

    canonical_status = _coerce_finding_status(status)
    finding.status = canonical_status.value
    finding.updated_at = datetime.now(tz=timezone.utc)
    
    if canonical_status in TERMINAL_FINDING_STATUSES:
        finding.resolved_at = datetime.now(tz=timezone.utc)
    else:
        finding.resolved_at = None

    db.commit()
    db.refresh(finding)
    
    try:
        _emit_finding_audit(str(finding.id), tenant_id, finding.framework, "FINDING_STATUS_UPDATED")
    except Exception:
        pass
        
    return finding


def assign_owner(
    db: Session,
    *,
    tenant_id: str,
    finding_id: str,
    owner_user_id: Optional[str],
) -> Optional[Finding]:
    finding = get_finding(db, tenant_id=tenant_id, finding_id=finding_id)
    if not finding:
        return None

    finding.owner_user_id = uuid.UUID(owner_user_id) if owner_user_id else None
    finding.updated_at = datetime.now(tz=timezone.utc)
    db.commit()
    db.refresh(finding)
    return finding


def resolve_finding(
    db: Session,
    *,
    tenant_id: str,
    finding_id: str,
    status: str | FindingStatus,
    remediation_summary: str,
) -> Optional[Finding]:
    canonical_status = _coerce_finding_status(status)
    if canonical_status not in TERMINAL_FINDING_STATUSES:
        raise ValueError(f"Finding status {canonical_status.value!r} is not terminal")
    finding = get_finding(db, tenant_id=tenant_id, finding_id=finding_id)
    if not finding:
        return None

    finding.status = canonical_status.value
    finding.remediation_summary = remediation_summary
    finding.resolved_at = datetime.now(tz=timezone.utc)
    finding.updated_at = datetime.now(tz=timezone.utc)
    db.commit()
    db.refresh(finding)
    
    try:
        action = {
            FindingStatus.RESOLVED: "FINDING_RESOLVED",
            FindingStatus.FALSE_POSITIVE: "FINDING_FALSE_POSITIVE",
            FindingStatus.ACCEPTED_RISK: "FINDING_ACCEPTED_RISK",
        }[canonical_status]
        _emit_finding_audit(str(finding.id), tenant_id, finding.framework, action)
    except Exception:
        pass
        
    return finding


def get_findings_by_workflow(
    db: Session,
    *,
    tenant_id: str,
    workflow_id: str,
) -> List[Finding]:
    return (
        db.query(Finding)
        .filter(
            Finding.tenant_id == uuid.UUID(tenant_id),
            Finding.workflow_id == workflow_id,
        )
        .order_by(Finding.created_at.desc())
        .all()
    )


def severity_breakdown(db: Session, tenant_id: str) -> Dict[str, int]:
    results = (
        db.query(Finding.severity, func.count(Finding.id))
        .filter(
            Finding.tenant_id == uuid.UUID(tenant_id),
            Finding.status.notin_(("RESOLVED", "FALSE_POSITIVE", "ACCEPTED_RISK"))
        )
        .group_by(Finding.severity)
        .all()
    )
    return {severity: count for severity, count in results}


def status_breakdown(db: Session, tenant_id: str) -> Dict[str, int]:
    results = (
        db.query(Finding.status, func.count(Finding.id))
        .filter(Finding.tenant_id == uuid.UUID(tenant_id))
        .group_by(Finding.status)
        .all()
    )
    return {status: count for status, count in results}


def framework_breakdown(db: Session, tenant_id: str) -> Dict[str, int]:
    results = (
        db.query(Finding.framework, func.count(Finding.id))
        .filter(Finding.tenant_id == uuid.UUID(tenant_id))
        .group_by(Finding.framework)
        .all()
    )
    return {framework: count for framework, count in results}


def get_dashboard_summary(db: Session, tenant_id: str) -> Dict[str, Any]:
    tid = uuid.UUID(tenant_id)
    
    open_count = db.query(Finding).filter(
        Finding.tenant_id == tid,
        Finding.status.notin_(("RESOLVED", "FALSE_POSITIVE", "ACCEPTED_RISK"))
    ).count()
    
    critical_count = db.query(Finding).filter(
        Finding.tenant_id == tid,
        Finding.status.notin_(("RESOLVED", "FALSE_POSITIVE", "ACCEPTED_RISK")),
        Finding.severity == "critical"
    ).count()
    
    resolved_count = db.query(Finding).filter(
        Finding.tenant_id == tid,
        Finding.status.in_(("RESOLVED", "FALSE_POSITIVE", "ACCEPTED_RISK"))
    ).count()
    
    avg_risk = db.query(func.avg(Finding.risk_score)).filter(
        Finding.tenant_id == tid,
        Finding.status.notin_(("RESOLVED", "FALSE_POSITIVE", "ACCEPTED_RISK"))
    ).scalar() or 0.0
    
    sev_counts = severity_breakdown(db, tenant_id)
    
    return {
        "open_findings": open_count,
        "critical_findings": critical_count,
        "resolved_findings": resolved_count,
        "average_risk_score": round(avg_risk, 2),
        "severity_distribution": sev_counts,
    }

def trend_summary(db: Session, tenant_id: str) -> List[Dict[str, Any]]:
    try:
        results = (
            db.query(
                func.date_trunc('day', Finding.created_at).label("day"),
                func.count(Finding.id).label("count")
            )
            .filter(Finding.tenant_id == uuid.UUID(tenant_id))
            .group_by(func.date_trunc('day', Finding.created_at))
            .order_by(func.date_trunc('day', Finding.created_at))
            .limit(30)
            .all()
        )
        return [{"date": row.day.strftime("%Y-%m-%d"), "count": row.count} for row in results if row.day]
    except Exception as exc:
        logger.warning("Could not calculate trend summary: %s", exc)
        return []

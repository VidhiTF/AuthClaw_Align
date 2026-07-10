"""Live compliance framework scoring from evidence, findings, and audit records."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.db.models import (
    APIKey,
    AuditLogMetadata,
    ComplianceScoreSnapshot,
    EvidenceRecord,
    Finding,
    GatewayConfig,
    PendingApproval,
    Policy,
    RedactionToken,
)
from app.services.notifications import create_notification

FRAMEWORKS = ("SOC2", "GDPR", "HIPAA")
RESOLVED_STATUSES = ("RESOLVED", "FALSE_POSITIVE", "ACCEPTED_RISK")


@dataclass(frozen=True)
class FrameworkMetrics:
    framework: str
    evidence_count: int
    audit_event_count: int
    framework_audit_event_count: int
    audit_hash_count: int
    redaction_count: int
    active_policy_count: int
    active_gateway_count: int
    active_api_key_count: int
    pending_approvals: int
    open_findings: int
    critical_findings: int
    high_findings: int
    resolved_findings: int
    pii_evidence_count: int
    approval_evidence_count: int
    remediation_audit_count: int
    policy_evidence_count: int


CONTROL_CATALOG: dict[str, list[dict[str, Any]]] = {
    "SOC2": [
        {
            "id": "CC6.1",
            "name": "Logical Access Controls",
            "description": "Access to gateway configuration, policies, and audit evidence is restricted and traceable.",
            "weight": 0.25,
            "signals": ("active_api_keys", "active_policies", "active_gateways", "audit_hashes"),
        },
        {
            "id": "CC6.3",
            "name": "System Monitoring",
            "description": "LLM traffic is monitored, retained, and available as tamper-evident audit evidence.",
            "weight": 0.25,
            "signals": ("audit_events", "hash_chain", "framework_evidence"),
        },
        {
            "id": "CC6.6",
            "name": "Transmission Protection",
            "description": "PII/PHI is redacted or tokenized before model-provider egress.",
            "weight": 0.25,
            "signals": ("redactions", "pii_evidence", "active_policies"),
        },
        {
            "id": "CC7.2",
            "name": "Issue Response and Remediation",
            "description": "Findings, approvals, and remediation attempts are tracked through closure.",
            "weight": 0.25,
            "signals": ("findings", "remediation_audit", "approvals"),
        },
    ],
    "GDPR": [
        {
            "id": "Article 25",
            "name": "Data Protection by Design and Default",
            "description": "Privacy controls are embedded in policy, routing, and redaction before processing.",
            "weight": 0.28,
            "signals": ("redactions", "active_policies", "pii_evidence"),
        },
        {
            "id": "Article 30",
            "name": "Records of Processing Activities",
            "description": "Processing activity is represented by retained audit and evidence records.",
            "weight": 0.24,
            "signals": ("audit_events", "framework_evidence", "hash_chain"),
        },
        {
            "id": "Article 32",
            "name": "Security of Processing",
            "description": "Processing security is backed by access controls, integrity evidence, and incident tracking.",
            "weight": 0.28,
            "signals": ("active_api_keys", "audit_hashes", "findings"),
        },
        {
            "id": "Article 35",
            "name": "Risk Assessment and DPIA Evidence",
            "description": "High-risk processing issues are surfaced as findings and remediation evidence.",
            "weight": 0.20,
            "signals": ("framework_evidence", "findings", "remediation_audit"),
        },
    ],
    "HIPAA": [
        {
            "id": "164.312(a)(1)",
            "name": "Access Control",
            "description": "Access to ePHI-related governance controls is scoped to authorized tenants and users.",
            "weight": 0.25,
            "signals": ("active_api_keys", "active_policies", "active_gateways"),
        },
        {
            "id": "164.312(b)",
            "name": "Audit Controls",
            "description": "System activity involving ePHI pathways is recorded with tamper-evident audit controls.",
            "weight": 0.25,
            "signals": ("audit_events", "hash_chain", "framework_evidence"),
        },
        {
            "id": "164.312(c)(1)",
            "name": "Integrity",
            "description": "Audit and remediation records protect against undetected alteration or destruction.",
            "weight": 0.25,
            "signals": ("audit_hashes", "remediation_audit", "findings"),
        },
        {
            "id": "164.312(e)(1)",
            "name": "Transmission Security",
            "description": "PHI-like content is redacted, tokenized, or blocked before external transmission.",
            "weight": 0.25,
            "signals": ("redactions", "pii_evidence", "active_policies"),
        },
    ],
}


def _tenant_uuid(tenant_id: str) -> uuid.UUID:
    return uuid.UUID(str(tenant_id))


def _safe_count(query) -> int:
    try:
        return int(query.count())
    except Exception:
        return 0


def _framework_audit_count(db: Session, tenant_id: uuid.UUID, framework: str) -> int:
    try:
        return int(
            db.query(AuditLogMetadata)
            .filter(
                AuditLogMetadata.tenant_id == tenant_id,
                AuditLogMetadata.frameworks_affected.any(framework),
            )
            .count()
        )
    except Exception:
        return 0


def collect_metrics(db: Session, tenant_id: str, framework: str) -> FrameworkMetrics:
    tid = _tenant_uuid(tenant_id)
    framework = framework.upper()
    open_filter = Finding.status.notin_(RESOLVED_STATUSES)
    evidence_q = db.query(EvidenceRecord).filter(EvidenceRecord.tenant_id == tid, EvidenceRecord.framework == framework)
    finding_q = db.query(Finding).filter(Finding.tenant_id == tid, Finding.framework == framework)

    return FrameworkMetrics(
        framework=framework,
        evidence_count=_safe_count(evidence_q),
        audit_event_count=_safe_count(db.query(AuditLogMetadata).filter(AuditLogMetadata.tenant_id == tid)),
        framework_audit_event_count=_framework_audit_count(db, tid, framework),
        audit_hash_count=_safe_count(
            db.query(AuditLogMetadata).filter(
                AuditLogMetadata.tenant_id == tid,
                AuditLogMetadata.integrity_hash.isnot(None),
                AuditLogMetadata.integrity_hash != "",
            )
        ),
        redaction_count=_safe_count(db.query(RedactionToken).filter(RedactionToken.tenant_id == tid)),
        active_policy_count=_safe_count(db.query(Policy).filter(Policy.tenant_id == tid, Policy.is_active == True)),
        active_gateway_count=_safe_count(db.query(GatewayConfig).filter(GatewayConfig.tenant_id == tid, GatewayConfig.is_active == True)),
        active_api_key_count=_safe_count(db.query(APIKey).filter(APIKey.tenant_id == tid, APIKey.is_active == True)),
        pending_approvals=_safe_count(db.query(PendingApproval).filter(PendingApproval.tenant_id == tid, PendingApproval.status == "PENDING")),
        open_findings=_safe_count(finding_q.filter(open_filter)),
        critical_findings=_safe_count(finding_q.filter(open_filter, Finding.severity == "critical")),
        high_findings=_safe_count(finding_q.filter(open_filter, Finding.severity == "high")),
        resolved_findings=_safe_count(finding_q.filter(Finding.status.in_(RESOLVED_STATUSES))),
        pii_evidence_count=_safe_count(evidence_q.filter(EvidenceRecord.evidence_type.in_(("pii_detected", "policy_violation")))),
        approval_evidence_count=_safe_count(evidence_q.filter(EvidenceRecord.evidence_type == "approval_record")),
        remediation_audit_count=_safe_count(
            db.query(AuditLogMetadata).filter(
                AuditLogMetadata.tenant_id == tid,
                AuditLogMetadata.action.ilike("%remediation%"),
            )
        ),
        policy_evidence_count=_safe_count(evidence_q.filter(EvidenceRecord.source_type == "policy_evaluation")),
    )


def _signal_score(signal: str, metrics: FrameworkMetrics) -> tuple[float, str | None, str | None]:
    if signal == "active_api_keys":
        return (100.0, f"{metrics.active_api_key_count} active API keys", None) if metrics.active_api_key_count else (40.0, None, "No active API key evidence")
    if signal == "active_policies":
        return (100.0, f"{metrics.active_policy_count} active policies", None) if metrics.active_policy_count else (35.0, None, "No active policy")
    if signal == "active_gateways":
        return (100.0, f"{metrics.active_gateway_count} active gateway routes", None) if metrics.active_gateway_count else (35.0, None, "No active gateway route")
    if signal == "audit_events":
        if metrics.audit_event_count >= 25:
            return 100.0, f"{metrics.audit_event_count} audit events", None
        if metrics.audit_event_count > 0:
            return 70.0, f"{metrics.audit_event_count} audit events", "Audit sample is still small"
        return 25.0, None, "No audit events"
    if signal == "framework_evidence":
        if metrics.evidence_count >= 5:
            return 100.0, f"{metrics.evidence_count} framework evidence records", None
        if metrics.evidence_count > 0:
            return 70.0, f"{metrics.evidence_count} framework evidence records", "More framework-specific evidence needed"
        return 30.0, None, "No framework-specific evidence"
    if signal == "hash_chain":
        if metrics.audit_hash_count >= max(1, metrics.audit_event_count):
            return 100.0, f"{metrics.audit_hash_count} hash-chained audit records", None
        if metrics.audit_hash_count > 0:
            return 75.0, f"{metrics.audit_hash_count} hash-chained audit records", "Some audit records lack integrity hashes"
        return 20.0, None, "No hash-chain evidence"
    if signal == "audit_hashes":
        return _signal_score("hash_chain", metrics)
    if signal == "redactions":
        if metrics.redaction_count >= 10:
            return 100.0, f"{metrics.redaction_count} redaction token mappings", None
        if metrics.redaction_count > 0:
            return 75.0, f"{metrics.redaction_count} redaction token mappings", "Redaction evidence sample is still small"
        if metrics.active_policy_count:
            return 60.0, "Policy redaction controls configured", "No redaction events observed yet"
        return 25.0, None, "No redaction evidence"
    if signal == "pii_evidence":
        if metrics.pii_evidence_count > 0:
            return 95.0, f"{metrics.pii_evidence_count} PII/PHI evidence records", None
        if metrics.redaction_count > 0:
            return 80.0, f"{metrics.redaction_count} redaction records", "No framework-tagged PII/PHI evidence"
        return 35.0, None, "No PII/PHI evidence"
    if signal == "approvals":
        if metrics.pending_approvals == 0:
            return 95.0, "No pending approvals", None
        return max(40.0, 90.0 - metrics.pending_approvals * 10), f"{metrics.pending_approvals} pending approvals", "Pending approvals need review"
    if signal == "remediation_audit":
        if metrics.remediation_audit_count > 0:
            return 95.0, f"{metrics.remediation_audit_count} remediation audit events", None
        if metrics.open_findings == 0 and metrics.resolved_findings > 0:
            return 90.0, f"{metrics.resolved_findings} resolved findings", None
        if metrics.open_findings == 0:
            return 75.0, "No open findings", "No remediation audit events yet"
        return 45.0, None, "Open findings lack remediation evidence"
    if signal == "findings":
        score = 100.0 - metrics.open_findings * 7 - metrics.high_findings * 8 - metrics.critical_findings * 15
        score = max(0.0, score)
        evidence = f"{metrics.resolved_findings} resolved findings" if metrics.resolved_findings else None
        gap = f"{metrics.open_findings} open findings" if metrics.open_findings else None
        return score, evidence, gap
    return 50.0, None, f"Unknown scoring signal {signal}"


def readiness_level(score: float) -> str:
    if score >= 90:
        return "audit_ready"
    if score >= 75:
        return "monitor"
    if score >= 60:
        return "needs_attention"
    return "insufficient_evidence"


def control_status(score: float) -> str:
    if score >= 85:
        return "compliant"
    if score >= 60:
        return "partial"
    return "non_compliant"


def _iso(value: Any) -> str:
    return value.isoformat() if value else ""


def _control_terms(control: dict[str, Any]) -> list[str]:
    terms = [str(control["id"]), str(control["name"])]
    terms.extend(part for part in str(control["id"]).replace("(", ".").replace(")", "").split(".") if len(part) > 2)
    return sorted({term.strip() for term in terms if term and term.strip()})


def _ilike_any(column: Any, terms: list[str]) -> Any:
    return or_(*[column.ilike(f"%{term}%") for term in terms])


def _control_traceability(db: Session, tenant_id: str, framework: str, control: dict[str, Any]) -> dict[str, Any]:
    tid = _tenant_uuid(tenant_id)
    terms = _control_terms(control)
    empty = {
        "evidence_total": 0,
        "finding_total": 0,
        "audit_event_total": 0,
        "evidence": [],
        "findings": [],
        "audit_events": [],
        "links": {
            "evidence_url": f"/evidence?framework={framework}",
            "findings_url": f"/findings?framework={framework}",
            "audit_url": "/audit",
        },
    }
    try:
        evidence_base = db.query(EvidenceRecord).filter(EvidenceRecord.tenant_id == tid, EvidenceRecord.framework == framework)
        evidence_q = evidence_base.filter(_ilike_any(EvidenceRecord.source_reference, terms))
        evidence_rows = evidence_q.order_by(EvidenceRecord.created_at.desc()).limit(5).all()
        evidence_scope = "control"
        if not evidence_rows:
            evidence_rows = evidence_base.order_by(EvidenceRecord.created_at.desc()).limit(3).all()
            evidence_scope = "framework"

        finding_base = db.query(Finding).filter(Finding.tenant_id == tid, Finding.framework == framework)
        finding_q = finding_base.filter(or_(
            _ilike_any(Finding.finding_key, terms),
            _ilike_any(Finding.title, terms),
            _ilike_any(Finding.description, terms),
            _ilike_any(Finding.remediation_summary, terms),
        ))
        finding_rows = finding_q.order_by(Finding.created_at.desc()).limit(5).all()
        finding_scope = "control"
        if not finding_rows:
            finding_rows = finding_base.order_by(Finding.created_at.desc()).limit(3).all()
            finding_scope = "framework"

        try:
            audit_base = db.query(AuditLogMetadata).filter(
                AuditLogMetadata.tenant_id == tid,
                AuditLogMetadata.frameworks_affected.any(framework),
            )
        except Exception:
            audit_base = db.query(AuditLogMetadata).filter(AuditLogMetadata.tenant_id == tid)
        audit_q = audit_base.filter(or_(
            _ilike_any(AuditLogMetadata.action, terms),
            _ilike_any(AuditLogMetadata.reason, terms),
            _ilike_any(AuditLogMetadata.execution_trace, terms),
        ))
        audit_rows = audit_q.order_by(AuditLogMetadata.created_at.desc()).limit(5).all()
        audit_scope = "control"
        if not audit_rows:
            audit_rows = audit_base.order_by(AuditLogMetadata.created_at.desc()).limit(3).all()
            audit_scope = "framework"

        return {
            **empty,
            "evidence_total": evidence_base.count(),
            "finding_total": finding_base.count(),
            "audit_event_total": audit_base.count(),
            "evidence": [
                {
                    "id": str(row.id),
                    "type": row.evidence_type,
                    "severity": row.severity,
                    "source_reference": row.source_reference or "",
                    "created_at": _iso(row.created_at),
                    "scope": evidence_scope,
                    "url": f"/evidence?evidence_id={row.id}&openDrawer=true",
                }
                for row in evidence_rows
            ],
            "findings": [
                {
                    "id": str(row.id),
                    "title": row.title,
                    "severity": row.severity,
                    "status": row.status,
                    "created_at": _iso(row.created_at),
                    "scope": finding_scope,
                    "url": f"/findings?finding_id={row.id}",
                }
                for row in finding_rows
            ],
            "audit_events": [
                {
                    "record_id": str(row.record_id),
                    "action": row.action,
                    "provider": row.provider or "",
                    "created_at": _iso(row.created_at),
                    "scope": audit_scope,
                    "url": "/audit",
                }
                for row in audit_rows
            ],
        }
    except Exception:
        return empty


def score_control(control: dict[str, Any], metrics: FrameworkMetrics) -> dict[str, Any]:
    scores: list[float] = []
    evidence: list[str] = []
    gaps: list[str] = []
    for signal in control["signals"]:
        score, evidence_item, gap = _signal_score(signal, metrics)
        scores.append(score)
        if evidence_item:
            evidence.append(evidence_item)
        if gap:
            gaps.append(gap)
    control_score = round(sum(scores) / max(1, len(scores)), 1)
    return {
        "id": control["id"],
        "name": control["name"],
        "description": control["description"],
        "weight": control["weight"],
        "score": control_score,
        "status": control_status(control_score),
        "evidence": sorted(set(evidence)),
        "gaps": sorted(set(gaps)),
    }


def score_framework(db: Session, tenant_id: str, framework: str) -> dict[str, Any]:
    framework = framework.upper()
    if framework not in CONTROL_CATALOG:
        raise ValueError(f"Unsupported framework: {framework}")
    metrics = collect_metrics(db, tenant_id, framework)
    controls = [score_control(control, metrics) for control in CONTROL_CATALOG[framework]]
    for control, catalog_control in zip(controls, CONTROL_CATALOG[framework]):
        control["traceability"] = _control_traceability(db, tenant_id, framework, catalog_control)
    overall = round(sum(control["score"] * control["weight"] for control in controls), 1)
    return {
        "framework": framework,
        "score": overall,
        "readiness_level": readiness_level(overall),
        "controls": controls,
        "metrics": {
            "evidence_count": metrics.evidence_count,
            "audit_event_count": metrics.audit_event_count,
            "framework_audit_event_count": metrics.framework_audit_event_count,
            "audit_hash_count": metrics.audit_hash_count,
            "redaction_count": metrics.redaction_count,
            "active_policy_count": metrics.active_policy_count,
            "active_gateway_count": metrics.active_gateway_count,
            "pending_approvals": metrics.pending_approvals,
            "open_findings": metrics.open_findings,
            "critical_findings": metrics.critical_findings,
            "high_findings": metrics.high_findings,
            "resolved_findings": metrics.resolved_findings,
        },
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
    }


def upsert_score_snapshot(db: Session, tenant_id: str, framework_score: dict[str, Any]) -> ComplianceScoreSnapshot:
    tid = _tenant_uuid(tenant_id)
    framework = framework_score["framework"]
    snapshot_date = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
    existing = (
        db.query(ComplianceScoreSnapshot)
        .filter(
            ComplianceScoreSnapshot.tenant_id == tid,
            ComplianceScoreSnapshot.framework == framework,
            ComplianceScoreSnapshot.snapshot_date == snapshot_date,
        )
        .first()
    )
    previous_score = existing.overall_score if existing else None
    if previous_score is None:
        previous = (
            db.query(ComplianceScoreSnapshot)
            .filter(
                ComplianceScoreSnapshot.tenant_id == tid,
                ComplianceScoreSnapshot.framework == framework,
                ComplianceScoreSnapshot.snapshot_date != snapshot_date,
            )
            .order_by(ComplianceScoreSnapshot.snapshot_date.desc())
            .first()
        )
        previous_score = previous.overall_score if previous else None
    metrics = framework_score["metrics"]
    if existing:
        snapshot = existing
    else:
        snapshot = ComplianceScoreSnapshot(
            tenant_id=tid,
            framework=framework,
            snapshot_date=snapshot_date,
        )
        db.add(snapshot)
    snapshot.overall_score = float(framework_score["score"])
    snapshot.readiness_level = framework_score["readiness_level"]
    snapshot.control_scores = {control["id"]: control for control in framework_score["controls"]}
    snapshot.evidence_count = int(metrics["evidence_count"])
    snapshot.audit_event_count = int(metrics["audit_event_count"])
    snapshot.open_findings = int(metrics["open_findings"])
    snapshot.critical_findings = int(metrics["critical_findings"])
    snapshot.generated_at = datetime.now(tz=timezone.utc)
    db.commit()
    db.refresh(snapshot)
    score_drop = (previous_score or 0) - snapshot.overall_score
    if previous_score is not None and score_drop >= 5:
        create_notification(
            db,
            tenant_id=tid,
            type="compliance_score_drop",
            severity="warning" if score_drop < 15 else "critical",
            title=f"{framework} score dropped",
            body=f"{framework} dropped from {previous_score:.1f}% to {snapshot.overall_score:.1f}%.",
            link="/frameworks",
        )
    return snapshot


def score_all_frameworks(db: Session, tenant_id: str, *, persist: bool = True) -> dict[str, Any]:
    frameworks = [score_framework(db, tenant_id, framework) for framework in FRAMEWORKS]
    if persist:
        for framework_score in frameworks:
            upsert_score_snapshot(db, tenant_id, framework_score)
    overall = round(sum(item["score"] for item in frameworks) / len(frameworks), 1)
    return {
        "overall_score": overall,
        "readiness_level": readiness_level(overall),
        "frameworks": frameworks,
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
    }


def score_history(db: Session, tenant_id: str, framework: str | None = None, days: int = 30) -> list[dict[str, Any]]:
    tid = _tenant_uuid(tenant_id)
    q = db.query(ComplianceScoreSnapshot).filter(ComplianceScoreSnapshot.tenant_id == tid)
    if framework:
        q = q.filter(ComplianceScoreSnapshot.framework == framework.upper())
    rows = (
        q.order_by(ComplianceScoreSnapshot.snapshot_date.desc(), ComplianceScoreSnapshot.framework.asc())
        .limit(max(1, min(days * len(FRAMEWORKS), 365)))
        .all()
    )
    return [
        {
            "framework": row.framework,
            "snapshot_date": row.snapshot_date,
            "overall_score": row.overall_score,
            "readiness_level": row.readiness_level,
            "evidence_count": row.evidence_count,
            "audit_event_count": row.audit_event_count,
            "open_findings": row.open_findings,
            "critical_findings": row.critical_findings,
            "generated_at": row.generated_at.isoformat() if row.generated_at else "",
        }
        for row in reversed(rows)
    ]

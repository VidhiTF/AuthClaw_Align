"""Tenant-bound, two-person reviews of immutable control evidence.

Only this adapter constructs an assessment. Uploaded metadata and mutable evidence
links are never assessments. Callers own the transaction; writes only flush.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.authorization import normalize_role
from app.core.compliance_policy import calculation_version
from app.core.evidence_integrity import (
    INTEGRITY_ALGORITHM, INTEGRITY_VERSION, compute_evidence_integrity_hash,
    verify_evidence_integrity,
)
from app.db.models import ApprovalAudit, EvidenceRecord, Finding, PendingApproval, User


# The reviewed source directions are in docs/compliance/GDPR_SOC2_CONTROL_MATRIX.md.
# These are engineering readiness requirements, not certification criteria. Release
# checks expire conservatively after 7/30 days; every material change needs a review.
CONTROL_REQUIREMENTS = {
    "SOC2": {
        "CC6.1": {"access_review": 90, "access_negative_tests": 30},
        "CC6.6": {"transport_enforcement": 30, "redaction_enforcement": 30},
        "CC7.1": {"release_security_scans": 7, "blocking_findings_disposition": 7},
        "CC7.2": {"monitoring_operation": 1, "alert_triage_review": 1},
        "CC7.3": {"finding_closure_retest": 7, "closure_owner_review": 7},
        "CC8.1": {"change_authorization": 7, "release_checks_and_rollback": 7},
        "A1.2": {"backup_operation": 1, "restore_failover_test": 90},
        "C1.1": {"tenant_isolation": 30, "encryption_and_key_review": 90},
    },
    "GDPR": {
        "Article 25": {"privacy_design_review": 90},
        "Article 30": {"processing_register_review": 90},
        "Article 32": {"processing_security_review": 30, "resilience_test": 90},
        "Article 35": {"organization_dpia_approval": 365},
    },
    "HIPAA": {
        "164.312(a)(1)": {"ephi_access_review": 90},
        "164.312(b)": {"ephi_monitoring_review": 1},
        "164.312(c)(1)": {"ephi_integrity_review": 30},
        "164.312(e)(1)": {"ephi_transmission_review": 30},
    },
}
PRODUCER = "governance_review.v1"
CALCULATION_VERSION = calculation_version()


def resolve_owners(role_ids: list[str], *, public: bool = False) -> list[str]:
    return settings.compliance_owners(role_ids, public=public)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


class AssessmentProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    framework: Literal["SOC2", "GDPR", "HIPAA"]
    control_id: str = Field(min_length=1, max_length=50)
    environment: Literal["local", "ci", "staging", "production"]
    evidence_ids: list[uuid.UUID] = Field(min_length=1, max_length=50)
    observed_at: datetime
    period_start: datetime
    period_end: datetime
    outcomes: dict[str, Literal["pass", "fail", "unknown"]]
    finding_dispositions: dict[uuid.UUID, Literal["RESOLVED", "FALSE_POSITIVE"]] = Field(default_factory=dict, max_length=100)
    review_note: str = Field(min_length=20, max_length=2000)

    @field_validator("observed_at", "period_start", "period_end")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("Assessment timestamps require an explicit timezone")
        return _utc(value)

    @model_validator(mode="after")
    def validate_contract(self):
        required = CONTROL_REQUIREMENTS[self.framework].get(self.control_id)
        if required is None or set(self.outcomes) != set(required):
            raise ValueError("Provide every requirement for an exact catalog control")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("Duplicate source evidence is not permitted")
        if not self.period_start <= self.period_end <= self.observed_at:
            raise ValueError("Covered period must end before the observation")
        if len(self.review_note.strip()) < 20 or any(ord(char) < 32 and char not in "\n\t" for char in self.review_note):
            raise ValueError("A readable review note is required")
        return self


def _hash(tenant_id, requester_id, payload: dict) -> str:
    data = {"tenant_id": str(tenant_id), "requester_id": str(requester_id), "payload": payload}
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _principal(db: Session, tenant_id: uuid.UUID, user_id: uuid.UUID) -> User:
    user = db.query(User).filter(User.id == user_id, User.tenant_id == tenant_id).populate_existing().with_for_update().first()
    if not user or not user.is_active or normalize_role(user.role) != "tenant_administrator":
        raise ValueError("An active tenant administrator is required")
    return user


def lock_review_principals(db: Session, tenant_id, requester_id, reviewer_id) -> User:
    tid, requester, reviewer = (uuid.UUID(str(value)) for value in (tenant_id, requester_id, reviewer_id))
    if requester == reviewer:
        raise ValueError("The requester cannot review their own assessment")
    # Lock both actors before consuming MFA so cross-over reviews use one order.
    users = db.query(User).filter(User.tenant_id == tid, User.id.in_((requester, reviewer))).order_by(
        User.id).populate_existing().with_for_update().all()
    if len(users) != 2 or any(
        not user.is_active or normalize_role(user.role) != (
            "approver" if user.id == reviewer else "tenant_administrator"
        )
        for user in users
    ):
        raise ValueError("An active tenant administrator requester and approver reviewer are required")
    return next(user for user in users if user.id == reviewer)


def _integrity(record) -> bool:
    return (record.integrity_algorithm == INTEGRITY_ALGORITHM
            and record.integrity_version == INTEGRITY_VERSION and verify_evidence_integrity(record))


def _scope(proposal: AssessmentProposal, now: datetime) -> None:
    if proposal.environment != settings.COMPLIANCE_ENVIRONMENT:
        raise ValueError("Assessment environment does not match the configured deployment")
    if proposal.framework != "SOC2":
        raise ValueError("No supported governance evidence producer for this framework")
    if proposal.observed_at > now:
        raise ValueError("Future observations are not permitted")


def _validate_sources(proposal: AssessmentProposal, rows: list, tenant_id: uuid.UUID) -> dict[str, str]:
    expected = {str(item) for item in proposal.evidence_ids}
    if {str(row.id) for row in rows} != expected:
        raise ValueError("Every source must exist in the authenticated tenant")
    for row in rows:
        data = row.evidence_data or {}
        if (str(row.tenant_id) != str(tenant_id) or row.framework != proposal.framework
                or data.get("environment") != proposal.environment
                or not proposal.period_start <= _utc(row.created_at) <= proposal.period_end
                or row.evidence_type == "control_assessment" or "control_assessment" in data
                or not _integrity(row)):
            raise ValueError("Source evidence has invalid integrity, time, or assessment scope")
    return {str(row.id): row.integrity_hash for row in rows}


def _sources(db: Session, tenant_id: uuid.UUID, proposal: AssessmentProposal) -> list:
    return db.query(EvidenceRecord).filter(EvidenceRecord.tenant_id == tenant_id,
                                           EvidenceRecord.id.in_(proposal.evidence_ids)).all()


def _finding_snapshot(row: Finding) -> dict:
    return {"status": row.status, "updated_at": _utc(row.updated_at).isoformat(),
            "resolved_at": _utc(row.resolved_at).isoformat() if row.resolved_at else None,
            "remediation_summary": row.remediation_summary}


def _finding_dispositions(db: Session, tenant_id: uuid.UUID, proposal: AssessmentProposal) -> dict:
    if not proposal.finding_dispositions:
        return {}
    rows = db.query(Finding).filter(Finding.tenant_id == tenant_id, Finding.framework == proposal.framework,
        Finding.id.in_(proposal.finding_dispositions)).with_for_update().all()
    if {row.id for row in rows} != set(proposal.finding_dispositions):
        raise ValueError("Reviewed findings must exist in the same tenant and framework")
    for row in rows:
        if (row.status != proposal.finding_dispositions[row.id] or not row.resolved_at
                or len((row.remediation_summary or "").strip()) < 20
                or _utc(row.updated_at) > proposal.observed_at or _utc(row.resolved_at) > proposal.observed_at):
            raise ValueError("Finding disposition requires a completed, explained remediation before observation")
    return {str(row.id): _finding_snapshot(row) for row in rows}


def propose_assessment(db: Session, tenant_id: str, requester_id: str, payload) -> PendingApproval:
    now, tid, uid = datetime.now(timezone.utc), uuid.UUID(str(tenant_id)), uuid.UUID(str(requester_id))
    proposal = payload if isinstance(payload, AssessmentProposal) else AssessmentProposal.model_validate(payload)
    _principal(db, tid, uid)
    _scope(proposal, now)
    sources = _validate_sources(proposal, _sources(db, tid, proposal), tid)
    bound = {"assessment": proposal.model_dump(mode="json"), "source_hashes": sources,
             "finding_dispositions": _finding_dispositions(db, tid, proposal),
             "calculation_version": CALCULATION_VERSION}
    approval_id = uuid.uuid4()
    approval = PendingApproval(id=approval_id, tenant_id=tid, requester_id=uid,
        action_id=str(approval_id), action_type="control_assessment", status="PENDING",
        action_description=f"Review {proposal.framework} {proposal.control_id} evidence",
        action_payload=bound, action_hash=_hash(tid, uid, bound),
        expires_at=now + timedelta(minutes=30), created_at=now, updated_at=now)
    db.add(approval)
    db.flush()
    db.add(ApprovalAudit(id=uuid.uuid4(), tenant_id=tid, approval_id=approval_id, actor_id=uid,
        action="ASSESSMENT_PROPOSED", action_hash=approval.action_hash, reason=proposal.review_note,
        details={"payload": bound, "requester_id": str(uid)}, mfa_verified=False, created_at=now))
    db.flush()
    return approval


def review_assessment(db: Session, tenant_id: str, approval_id: str, reviewer_id: str,
                      approve: bool, reason: str, mfa_timestamp: datetime | None) -> EvidenceRecord | None:
    now, tid, uid = datetime.now(timezone.utc), uuid.UUID(str(tenant_id)), uuid.UUID(str(reviewer_id))
    approval = db.query(PendingApproval).filter(PendingApproval.id == uuid.UUID(str(approval_id)),
        PendingApproval.tenant_id == tid, PendingApproval.action_type == "control_assessment").with_for_update().first()
    if not approval or approval.status != "PENDING" or _utc(approval.expires_at) <= now:
        raise ValueError("Assessment approval is unavailable, expired, or already resolved")
    reviewer = lock_review_principals(db, tid, approval.requester_id, uid)
    if not reviewer.mfa_enabled or mfa_timestamp is None or not now - timedelta(minutes=30) <= _utc(mfa_timestamp) <= now:
        raise ValueError("A fresh MFA verification is required")
    if not isinstance(reason, str) or not 20 <= len(reason.strip()) <= 2000:
        raise ValueError("A review decision requires a reason of 20 to 2000 characters")
    bound = approval.action_payload
    if _hash(tid, approval.requester_id, bound) != approval.action_hash or bound.get("calculation_version") != CALCULATION_VERSION:
        raise ValueError("Assessment proposal integrity or calculation version changed")
    proposal = AssessmentProposal.model_validate(bound["assessment"])
    _scope(proposal, now)
    # A proposal cannot be edited and re-hashed after its immutable creation audit.
    proposed = db.query(ApprovalAudit).filter(ApprovalAudit.tenant_id == tid,
        ApprovalAudit.approval_id == approval.id, ApprovalAudit.action == "ASSESSMENT_PROPOSED").all()
    if (len(proposed) != 1 or proposed[0].actor_id != approval.requester_id
            or proposed[0].action_hash != approval.action_hash
            or proposed[0].details != {"payload": bound, "requester_id": str(approval.requester_id)}):
        raise ValueError("Assessment proposal audit does not match")
    if approve and _validate_sources(proposal, _sources(db, tid, proposal), tid) != bound["source_hashes"]:
        raise ValueError("Assessment source references changed")
    if approve and _finding_dispositions(db, tid, proposal) != bound["finding_dispositions"]:
        raise ValueError("Finding dispositions changed after the proposal")
    audit_id, evidence_id = uuid.uuid4(), uuid.uuid4()
    approval.approver_id, approval.mfa_verified, approval.mfa_timestamp = uid, True, mfa_timestamp
    approval.approved_at, approval.resolution_reason = now, reason.strip()
    approval.status, approval.updated_at = ("CONSUMED" if approve else "REJECTED"), now
    if approve:
        approval.consumed_at, approval.consumed_by_id = now, uid
    db.add(ApprovalAudit(id=audit_id, tenant_id=tid, approval_id=approval.id, actor_id=uid,
        action="ASSESSMENT_APPROVED" if approve else "ASSESSMENT_REJECTED", action_hash=approval.action_hash,
        reason=reason.strip(), details={"payload": bound, "requester_id": str(approval.requester_id),
            **({"evidence_id": str(evidence_id)} if approve else {})},
        mfa_verified=True, mfa_timestamp=mfa_timestamp, created_at=now))
    record = None
    if approve:
        envelope = {"version": 1, "producer": PRODUCER, "approval_id": str(approval.id),
                    "audit_id": str(audit_id), "action_hash": approval.action_hash, **bound}
        values = dict(evidence_id=evidence_id, tenant_id=tid, workflow_id=None, framework=proposal.framework,
            source_type=PRODUCER, source_reference=str(approval.id), evidence_type="control_assessment",
            evidence_data={"control_assessment": envelope}, severity="info", created_at=now)
        integrity_hash = compute_evidence_integrity_hash(**values)
        values["id"] = values.pop("evidence_id")
        record = EvidenceRecord(**values, integrity_hash=integrity_hash,
            integrity_algorithm=INTEGRITY_ALGORITHM, integrity_version=INTEGRITY_VERSION)
        db.add(record)
    db.flush()
    return record


def _trusted_proposal(audit, records: dict, approvals: dict, sources: dict, findings: dict, tenant_id, as_of):
    try:
        bound, requester = audit.details["payload"], uuid.UUID(audit.details["requester_id"])
        uuid.UUID(audit.details["evidence_id"])
        proposal = AssessmentProposal.model_validate(bound["assessment"])
        expected_hash = _hash(tenant_id, requester, bound)
        if (str(audit.tenant_id) != str(tenant_id) or audit.action != "ASSESSMENT_APPROVED"
                or audit.action_hash != expected_hash or requester == audit.actor_id
                or not audit.mfa_verified or not audit.mfa_timestamp
                or not _utc(audit.created_at) - timedelta(minutes=30) <= _utc(audit.mfa_timestamp) <= _utc(audit.created_at)):
            return None, "untrusted_source"
        if bound.get("calculation_version") != CALCULATION_VERSION:
            return None, "unsupported_requirement"
        if proposal.environment != settings.COMPLIANCE_ENVIRONMENT or proposal.observed_at > as_of or _utc(audit.created_at) > as_of:
            return None, "wrong_scope"
    except (ValueError, KeyError, TypeError, AttributeError):
        return None, "untrusted_source"
    # An immutable, valid approval establishes observation order even if someone
    # removes or corrupts its evidence or mutable approval state later.
    try:
        approval = approvals[str(audit.approval_id)]
        if (approval.status != "CONSUMED" or str(approval.tenant_id) != str(tenant_id)
                or approval.action_type != "control_assessment" or approval.action_payload != bound
                or expected_hash != approval.action_hash or approval.requester_id != requester
                or audit.actor_id != approval.approver_id or approval.approver_id != approval.consumed_by_id
                or not _utc(approval.created_at) <= _utc(audit.created_at) < _utc(approval.expires_at)
                or not approval.consumed_at or _utc(approval.consumed_at) != _utc(audit.created_at)):
            return proposal, "untrusted_source"
    except (ValueError, KeyError, TypeError, AttributeError):
        return proposal, "untrusted_source"
    try:
        record = records[audit.details["evidence_id"]]
        envelope = {"version": 1, "producer": PRODUCER, "approval_id": str(approval.id),
                    "audit_id": str(audit.id), "action_hash": expected_hash, **bound}
        if (not _integrity(record) or str(record.tenant_id) != str(tenant_id)
                or record.framework != proposal.framework or record.source_type != PRODUCER
                or record.source_reference != str(approval.id) or _utc(record.created_at) != _utc(audit.created_at)
                or record.evidence_data != {"control_assessment": envelope}):
            return proposal, "invalid_integrity"
        actual = _validate_sources(proposal, [sources[str(key)] for key in proposal.evidence_ids], tenant_id)
        if actual != bound["source_hashes"]:
            return proposal, "invalid_integrity"
    except (ValueError, KeyError, TypeError, AttributeError):
        return proposal, "invalid_integrity"
    try:
        current = {str(key): _finding_snapshot(findings[str(key)]) for key in proposal.finding_dispositions}
        if current != bound["finding_dispositions"]:
            return proposal, "unverified_disposition"
    except (ValueError, KeyError, TypeError, AttributeError):
        return proposal, "unverified_disposition"
    return proposal, None


def assess_framework(db: Session, tenant_id: str, framework: str, as_of: datetime) -> dict[str, dict]:
    """Read fixed query sets; evaluate exact, verified requirements independently of traceability."""
    tid, as_of = uuid.UUID(str(tenant_id)), _utc(as_of)
    requirements = CONTROL_REQUIREMENTS[framework]
    records = {str(row.id): row for row in db.query(EvidenceRecord).filter(EvidenceRecord.tenant_id == tid,
        EvidenceRecord.framework == framework, EvidenceRecord.evidence_type == "control_assessment").all()}
    audits = db.query(ApprovalAudit).filter(ApprovalAudit.tenant_id == tid,
        ApprovalAudit.action == "ASSESSMENT_APPROVED",
        ApprovalAudit.details["payload"]["assessment"]["framework"].as_string() == framework).all()
    approval_ids = {row.approval_id for row in audits}
    source_ids = set()
    for audit in audits:
        try:
            source_ids.update(uuid.UUID(key) for key in audit.details["payload"]["source_hashes"])
        except (KeyError, TypeError, ValueError):
            pass
    approvals = {str(row.id): row for row in db.query(PendingApproval).filter(
        PendingApproval.tenant_id == tid, PendingApproval.id.in_(approval_ids)).all()} if approval_ids else {}
    sources = {str(row.id): row for row in db.query(EvidenceRecord).filter(
        EvidenceRecord.tenant_id == tid, EvidenceRecord.id.in_(source_ids)).all()} if source_ids else {}
    findings = {str(row.id): row for row in db.query(Finding).filter(
        Finding.tenant_id == tid, Finding.framework == framework).all()}
    terminal_findings = {key for key, row in findings.items() if row.status in {"RESOLVED", "FALSE_POSITIVE"}}
    decisions = {}
    for control_id, required in requirements.items():
        reasons, candidates = set(), []
        for audit in audits:
            assessment = ((audit.details or {}).get("payload") or {}).get("assessment") or {}
            if assessment.get("control_id") != control_id:
                continue
            proposal, reason = _trusted_proposal(audit, records, approvals, sources, findings, tid, as_of)
            if proposal is None:
                reasons.add(reason)
            else:
                candidates.append((proposal, audit.details["evidence_id"], reason))
        selected, qualified, expiries, reviewed_dispositions = [], 0, [], set()
        if framework != "SOC2":
            reasons.add("unsupported_requirement")
        if settings.COMPLIANCE_ENVIRONMENT == "unconfigured":
            reasons.add("wrong_scope")
        for requirement, days in required.items():
            applicable = [(proposal, eid, reason) for proposal, eid, reason in candidates if requirement in proposal.outcomes]
            if not applicable:
                reasons.add("missing_assessment")
                continue
            # Unknown/failure beat pass on ties. Only a trusted immutable review
            # establishes ordering; invalid evidence remains blocking at its place.
            proposal, eid, source_reason = max(applicable, key=lambda item: (item[0].observed_at,
                {"pass": 0, "unknown": 1, "fail": 2}[item[0].outcomes[requirement]], bool(item[2]), item[1]))
            selected.append(eid)
            expiry = min(proposal.observed_at, proposal.period_end) + timedelta(days=days)
            expiries.append(expiry)
            if source_reason:
                reasons.add(source_reason)
            elif expiry <= as_of:
                reasons.add("stale_assessment")
            elif proposal.outcomes[requirement] != "pass":
                reasons.add("failed_assessment")
            else:
                qualified += 1
                reviewed_dispositions.update(str(key) for key in proposal.finding_dispositions)
        # Invalid history is diagnostic only when a valid current decision exists;
        # it cannot overrule the independently verified effective observation.
        if qualified == len(required) and framework == "SOC2" and settings.COMPLIANCE_ENVIRONMENT != "unconfigured":
            reasons = set()
        if terminal_findings - reviewed_dispositions:
            reasons.add("unverified_disposition")
        decisions[control_id] = {
            "state": "qualified" if not reasons and qualified == len(required) else "blocked",
            "reason_codes": sorted(reasons), "required_count": len(required), "qualified_count": qualified,
            "as_of": as_of.isoformat(), "valid_until": min(expiries).isoformat() if expiries else None,
            "gaps": [f"{control_id}: {reason.replace('_', ' ')}" for reason in sorted(reasons)],
            "evidence_ids": sorted(set(selected)),
        }
    return decisions

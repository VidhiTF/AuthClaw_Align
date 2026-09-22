"""Real SQLAlchemy writer-to-reader checks; SQLite does not prove PostgreSQL RLS."""
from datetime import datetime, timedelta, timezone
import uuid

import pytest
from pydantic import ValidationError
from sqlalchemy import ARRAY, create_engine, event
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session

from app.core.config import Settings, settings
from app.core.evidence_integrity import compute_evidence_integrity_hash
from app.db.models import ApprovalAudit, EvidenceRecord, Finding, PendingApproval, User
from app.services import control_assessments as assessments


@compiles(ARRAY, "sqlite")
def sqlite_array(_type, _compiler, **_kw):
    return "JSON"


@pytest.fixture
def context(monkeypatch):
    monkeypatch.setattr(settings, "COMPLIANCE_ENVIRONMENT", "local")
    engine = create_engine("sqlite:///:memory:")
    for model in (User, EvidenceRecord, Finding, PendingApproval, ApprovalAudit):
        model.__table__.create(engine)
    with Session(engine) as db:
        tenant, other_tenant = uuid.uuid4(), uuid.uuid4()
        requester, reviewer, outsider = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        for user_id, tid in ((requester, tenant), (reviewer, tenant), (outsider, other_tenant)):
            db.add(User(id=user_id, tenant_id=tid, email=f"{user_id}@example.test", role="admin",
                        is_active=True, mfa_enabled=True))
        db.flush()
        yield db, tenant, requester, reviewer, outsider
    engine.dispose()


def source(db, tenant, *, environment="local", created_at=None):
    values = dict(evidence_id=uuid.uuid4(), tenant_id=tenant, workflow_id=None, framework="SOC2",
        source_type="audit_event", source_reference="immutable-monitoring-test", evidence_type="audit_log",
        evidence_data={"environment": environment, "monitoring_window": "reviewed operating record"},
        severity="info", created_at=created_at or datetime.now(timezone.utc) - timedelta(hours=1))
    digest = compute_evidence_integrity_hash(**values)
    values["id"] = values.pop("evidence_id")
    row = EvidenceRecord(**values, integrity_hash=digest, integrity_algorithm="sha256", integrity_version=1)
    db.add(row)
    db.flush()
    return row


def payload(record, **changes):
    now = datetime.now(timezone.utc)
    data = dict(framework="SOC2", control_id="CC7.2", environment="local", evidence_ids=[str(record.id)],
        observed_at=now - timedelta(minutes=1), period_start=now - timedelta(hours=2),
        period_end=now - timedelta(minutes=1),
        outcomes={"monitoring_operation": "pass", "alert_triage_review": "pass"},
        review_note="Inspected the scoped monitoring and triage operating records.")
    data.update(changes)
    return data


def approve(context, data):
    db, tenant, requester, reviewer, _ = context
    approval = assessments.propose_assessment(db, str(tenant), str(requester), data)
    record = assessments.review_assessment(db, str(tenant), str(approval.id), str(reviewer), True,
        "Independently verified the operating evidence and all requirement outcomes.", datetime.now(timezone.utc))
    db.commit()
    return approval, record


def decision(context, as_of=None):
    db, tenant, *_ = context
    return assessments.assess_framework(db, str(tenant), "SOC2", as_of or datetime.now(timezone.utc))["CC7.2"]


def test_real_writer_requires_independent_review_and_current_evidence(context):
    db, tenant, *_ = context
    evidence = source(db, tenant)
    assert decision(context)["state"] == "blocked"
    approval, record = approve(context, payload(evidence))
    assert approval.status == "CONSUMED"
    assert decision(context)["state"] == "qualified"
    assert decision(context)["qualified_count"] == 2
    assert decision(context)["evidence_ids"] == [str(record.id)]
    expired = decision(context, datetime.now(timezone.utc) + timedelta(days=1))
    assert expired["state"] == "blocked"
    assert expired["reason_codes"] == ["stale_assessment"]


@pytest.mark.parametrize("mutation", ["source_payload", "assessment_payload", "source_version", "approval_payload", "audit_payload"])
def test_tampering_removes_qualification(context, mutation):
    db, tenant, *_ = context
    evidence = source(db, tenant)
    approval, record = approve(context, payload(evidence))
    if mutation == "source_payload":
        evidence.evidence_data = {"environment": "local", "tampered": True}
    elif mutation == "assessment_payload":
        record.evidence_data = {"control_assessment": {**record.evidence_data["control_assessment"], "producer": "caller"}}
    elif mutation == "source_version":
        evidence.integrity_version = 999
    elif mutation == "approval_payload":
        approval.action_payload = {**approval.action_payload, "source_hashes": {}}
    else:
        db.query(ApprovalAudit).filter(ApprovalAudit.action == "ASSESSMENT_APPROVED").one().details = {}
    db.flush()
    assert decision(context)["state"] == "blocked"


def test_new_failure_supersedes_old_pass_and_duplicate_pass_cannot_override_tie(context):
    db, tenant, *_ = context
    evidence = source(db, tenant)
    original = payload(evidence)
    approve(context, original)
    observed = original["observed_at"] + timedelta(seconds=1)
    failed = payload(evidence, observed_at=observed,
        outcomes={"monitoring_operation": "fail", "alert_triage_review": "pass"})
    approve(context, failed)
    approve(context, payload(evidence, observed_at=observed))
    result = decision(context)
    assert result["state"] == "blocked"
    assert result["qualified_count"] == 1
    assert "failed_assessment" in result["reason_codes"]


def test_unknown_and_out_of_order_pass_do_not_erase_newer_failure(context):
    db, tenant, *_ = context
    evidence = source(db, tenant)
    current = payload(evidence)
    approve(context, {**current, "outcomes": {"monitoring_operation": "unknown", "alert_triage_review": "pass"}})
    approve(context, {**current, "observed_at": current["observed_at"] - timedelta(seconds=1),
                      "period_end": current["period_end"] - timedelta(seconds=1)})
    assert decision(context)["state"] == "blocked"
    assert "unknown_assessment" in decision(context)["reason_codes"]
    assert "failed_assessment" not in decision(context)["reason_codes"]
    assert decision(context)["evidence_timestamp"] == current["observed_at"].isoformat()


@pytest.mark.parametrize("case", ["self", "cross_tenant", "stale_mfa", "future_mfa", "inactive", "viewer", "disabled_mfa", "expired"])
def test_reviewer_authorization_is_checked_inside_service(context, case):
    db, tenant, requester, reviewer, outsider = context
    approval = assessments.propose_assessment(db, str(tenant), str(requester), payload(source(db, tenant)))
    actor = requester if case == "self" else outsider if case == "cross_tenant" else reviewer
    mfa = datetime.now(timezone.utc)
    if case == "stale_mfa":
        mfa -= timedelta(hours=1)
    if case == "future_mfa":
        mfa += timedelta(hours=1)
    if case in {"inactive", "viewer", "disabled_mfa"}:
        user = db.get(User, reviewer)
        if case == "inactive":
            user.is_active = False
        elif case == "viewer":
            user.role = "viewer"
        else:
            user.mfa_enabled = False
    if case == "expired":
        approval.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    with pytest.raises(ValueError):
        assessments.review_assessment(db, str(tenant), str(approval.id), str(actor), True,
            "Reviewed this proposal against the independent source evidence.", mfa)
    assert approval.status == "PENDING"
    assert decision(context)["state"] == "blocked"


def test_replay_and_rejection_never_write_another_assessment(context):
    db, tenant, requester, reviewer, _ = context
    approval, _ = approve(context, payload(source(db, tenant)))
    with pytest.raises(ValueError):
        assessments.review_assessment(db, str(tenant), str(approval.id), str(reviewer), True,
            "Reviewed again with the same independent evidence.", datetime.now(timezone.utc))
    pending = assessments.propose_assessment(db, str(tenant), str(requester), payload(source(db, tenant)))
    assert assessments.review_assessment(db, str(tenant), str(pending.id), str(reviewer), False,
        "Operating evidence does not substantiate the proposed conclusion.", datetime.now(timezone.utc)) is None
    assert pending.status == "REJECTED"
    assert db.query(EvidenceRecord).filter(EvidenceRecord.evidence_type == "control_assessment").count() == 1


@pytest.mark.parametrize("case", ["other_tenant", "wrong_environment", "future", "duplicate", "wrong_control", "nested"])
def test_unscoped_or_untrusted_sources_cannot_be_proposed(context, case):
    db, tenant, requester, *_ = context
    evidence = source(db, uuid.uuid4() if case == "other_tenant" else tenant,
                      environment="production" if case == "wrong_environment" else "local")
    data = payload(evidence)
    if case == "future":
        data["observed_at"] = datetime.now(timezone.utc) + timedelta(days=1)
    if case == "duplicate":
        data["evidence_ids"] *= 2
    if case == "wrong_control":
        data["control_id"] = "CC7.2.1"
    if case == "nested":
        evidence.evidence_type = "control_assessment"
    with pytest.raises(ValueError):
        assessments.propose_assessment(db, str(tenant), str(requester), data)


def test_modified_rehashed_proposal_cannot_bypass_creation_audit(context):
    db, tenant, requester, reviewer, _ = context
    approval = assessments.propose_assessment(db, str(tenant), str(requester), payload(source(db, tenant)))
    approval.action_payload = {**approval.action_payload, "source_hashes": {}}
    approval.action_hash = assessments._hash(tenant, requester, approval.action_payload)
    with pytest.raises(ValueError, match="proposal audit"):
        assessments.review_assessment(db, str(tenant), str(approval.id), str(reviewer), True,
            "Independently checked every assessment outcome against its evidence.", datetime.now(timezone.utc))


def test_tenant_read_and_deleted_sources_are_denied(context):
    db, tenant, *_ = context
    evidence = source(db, tenant)
    approve(context, payload(evidence))
    other = assessments.assess_framework(db, str(uuid.uuid4()), "SOC2", datetime.now(timezone.utc))
    assert all(item["state"] == "blocked" and not item["evidence_ids"] for item in other.values())
    db.query(EvidenceRecord).filter(EvidenceRecord.id == evidence.id).delete(synchronize_session=False)
    db.flush()
    assert decision(context)["state"] == "blocked"


def test_missing_environment_and_unmapped_frameworks_fail_closed(context, monkeypatch):
    db, tenant, *_ = context
    approve(context, payload(source(db, tenant)))
    monkeypatch.setattr(settings, "COMPLIANCE_ENVIRONMENT", "unconfigured")
    assert "wrong_scope" in decision(context)["reason_codes"]
    for framework in ("GDPR", "HIPAA"):
        decisions = assessments.assess_framework(db, str(tenant), framework, datetime.now(timezone.utc))
        assert all("unsupported_requirement" in row["reason_codes"] for row in decisions.values())


def test_configured_owners_have_separate_public_projection(monkeypatch):
    monkeypatch.setenv("AUTHCLAW_ENV", "local")
    config = Settings(_env_file=None, COMPLIANCE_OWNER_MAP_JSON='{"platform_security":["Security team"]}')
    assert config.compliance_owners(["platform_security"]) == ["Security team"]
    assert config.compliance_owners(["platform_security"], public=True) == ["Platform security"]
    assert config.compliance_owners(["governance"]) == ["Governance"]


@pytest.mark.parametrize("value", ['{"unknown":["Team"]}', '{"governance":[]}',
    '{"governance":"Team"}', '{"governance":["\\u0001bad"]}', 'secret-invalid-json'])
def test_invalid_owner_config_is_rejected_without_exposing_input(value):
    with pytest.raises(ValidationError) as error:
        Settings(_env_file=None, COMPLIANCE_OWNER_MAP_JSON=value)
    assert value not in str(error.value)


def test_local_evidence_scope_cannot_be_selected_on_production(monkeypatch):
    monkeypatch.setenv("AUTHCLAW_ENV", "production")
    with pytest.raises(ValidationError):
        Settings(_env_file=None, COMPLIANCE_ENVIRONMENT="local")
    assert Settings(_env_file=None, COMPLIANCE_ENVIRONMENT="production").COMPLIANCE_ENVIRONMENT == "production"


def test_valid_hash_and_asserted_producer_without_approval_never_qualify(context):
    db, tenant, *_ = context
    evidence = source(db, tenant)
    values = dict(evidence_id=uuid.uuid4(), tenant_id=tenant, workflow_id=None, framework="SOC2",
        source_type=assessments.PRODUCER, source_reference="asserted-review", evidence_type="control_assessment",
        evidence_data={"control_assessment": {"version": 1, "producer": assessments.PRODUCER,
            "calculation_version": assessments.CALCULATION_VERSION,
            "assessment": assessments.AssessmentProposal.model_validate(payload(evidence)).model_dump(mode="json"),
            "approval_id": str(uuid.uuid4()), "audit_id": str(uuid.uuid4()),
            "source_hashes": {str(evidence.id): evidence.integrity_hash}}},
        severity="info", created_at=datetime.now(timezone.utc))
    digest = compute_evidence_integrity_hash(**values)
    values["id"] = values.pop("evidence_id")
    db.add(EvidenceRecord(**values, integrity_hash=digest, integrity_algorithm="sha256", integrity_version=1))
    db.flush()
    result = decision(context)
    assert result["state"] == "blocked"
    assert "missing_assessment" in result["reason_codes"]


def test_framework_qualification_query_count_is_independent_of_control_detail(context):
    db, tenant, *_ = context
    evidence = source(db, tenant)
    for _ in range(3):
        approve(context, payload(evidence))
    statements = []
    def record_query(_connection, _cursor, statement, _parameters, _context, _many):
        if statement.lstrip().upper().startswith("SELECT"):
            statements.append(statement)
    event.listen(db.bind, "before_cursor_execute", record_query)
    try:
        result = assessments.assess_framework(db, str(tenant), "SOC2", datetime.now(timezone.utc))
    finally:
        event.remove(db.bind, "before_cursor_execute", record_query)
    assert len(result) == 8
    assert len(statements) == 5


def test_review_and_proposal_are_atomic_when_caller_rolls_back(context):
    db, tenant, requester, reviewer, _ = context
    evidence = source(db, tenant)
    db.commit()
    approval = assessments.propose_assessment(db, str(tenant), str(requester), payload(evidence))
    db.commit()
    record = assessments.review_assessment(db, str(tenant), str(approval.id), str(reviewer), True,
        "Independent review is valid but the enclosing operation will fail.", datetime.now(timezone.utc))
    record_id = record.id
    db.rollback()
    assert db.get(EvidenceRecord, record_id) is None
    assert db.get(PendingApproval, approval.id).status == "PENDING"
    assert db.query(ApprovalAudit).filter(ApprovalAudit.action == "ASSESSMENT_APPROVED").count() == 0


@pytest.mark.parametrize("mutation", ["deleted", "tampered", "assessment_deleted", "assessment_tampered", "approval_tampered"])
def test_losing_newer_failed_source_never_restores_older_pass(context, mutation):
    db, tenant, *_ = context
    old_source = source(db, tenant)
    initial = payload(old_source)
    approve(context, initial)
    newer_source = source(db, tenant)
    approval, record = approve(context, {**initial, "evidence_ids": [str(newer_source.id)],
        "observed_at": initial["observed_at"] + timedelta(seconds=1),
        "outcomes": {"monitoring_operation": "fail", "alert_triage_review": "fail"}})
    if mutation == "deleted":
        db.query(EvidenceRecord).filter(EvidenceRecord.id == newer_source.id).delete(synchronize_session=False)
    elif mutation == "tampered":
        newer_source.evidence_data = {"environment": "local", "tampered": True}
    elif mutation == "assessment_deleted":
        db.query(EvidenceRecord).filter(EvidenceRecord.id == record.id).delete(synchronize_session=False)
    elif mutation == "assessment_tampered":
        record.evidence_data = {"control_assessment": {}}
    else:
        approval.status = "PENDING"
    db.flush()
    result = decision(context)
    assert result["state"] == "blocked"
    assert result["qualified_count"] == 0
    assert ("untrusted_source" if mutation == "approval_tampered" else "invalid_integrity") in result["reason_codes"]


def finding(db, tenant, *, status="RESOLVED", summary="Remediation was independently retested against the scoped control."):
    when = datetime.now(timezone.utc) - timedelta(minutes=5)
    row = Finding(id=uuid.uuid4(), tenant_id=tenant, framework="SOC2", finding_key=str(uuid.uuid4()),
        title="Reviewed monitoring defect", severity="medium", finding_type="AUDIT_GAP",
        status=status, remediation_summary=summary, updated_at=when, resolved_at=when, created_at=when)
    db.add(row)
    db.flush()
    return row


@pytest.mark.parametrize("status", ["RESOLVED", "FALSE_POSITIVE"])
def test_terminal_finding_status_requires_explicit_review_and_changes_invalidate(context, status):
    db, tenant, *_ = context
    evidence = source(db, tenant)
    initial = payload(evidence)
    approve(context, initial)
    closed = finding(db, tenant, status=status)
    assert decision(context)["state"] == "blocked"
    assert "unverified_disposition" in decision(context)["reason_codes"]
    approve(context, {**initial, "observed_at": initial["observed_at"] + timedelta(seconds=1),
                      "finding_dispositions": {str(closed.id): status}})
    assert decision(context)["state"] == "qualified"
    closed.remediation_summary = "The remediation record was subsequently amended without new review."
    db.flush()
    assert decision(context)["state"] == "blocked"
    assert "unverified_disposition" in decision(context)["reason_codes"]


@pytest.mark.parametrize("case", ["cross_tenant", "missing_summary", "open", "wrong_framework"])
def test_unverifiable_finding_dispositions_cannot_be_proposed(context, case):
    db, tenant, requester, *_ = context
    closed = finding(db, uuid.uuid4() if case == "cross_tenant" else tenant,
        status="OPEN" if case == "open" else "RESOLVED", summary=None if case == "missing_summary" else "Retested all affected paths and independently validated the fix.")
    if case == "wrong_framework":
        closed.framework = "GDPR"
    db.flush()
    with pytest.raises(ValueError):
        assessments.propose_assessment(db, str(tenant), str(requester),
            payload(source(db, tenant), finding_dispositions={str(closed.id): "RESOLVED"}))


def test_finding_changed_after_proposal_cannot_be_approved(context):
    db, tenant, requester, reviewer, _ = context
    closed = finding(db, tenant)
    approval = assessments.propose_assessment(db, str(tenant), str(requester),
        payload(source(db, tenant), finding_dispositions={str(closed.id): "RESOLVED"}))
    closed.remediation_summary = "A different closure explanation requires an independent new proposal."
    db.flush()
    with pytest.raises(ValueError):
        assessments.review_assessment(db, str(tenant), str(approval.id), str(reviewer), True,
            "An independent reviewer cannot approve the altered closure record.", datetime.now(timezone.utc))

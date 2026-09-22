"""HTTP assessment contracts with real SQLite persistence, not PostgreSQL RLS.

Request identity is supplied by a test-only middleware; production role/scope
dependencies and tenant-filtered queries run unchanged. MFA verification is a
stub boundary here; its endpoint requirement and failure behavior are checked.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import ARRAY, create_engine, event, update
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.v1.endpoints import compliance_scores, trust_center as trust_endpoints
from app.core.auth import get_tenant_db
from app.core.config import settings
from app.core.evidence_integrity import verify_evidence_integrity
from app.db.models import ApprovalAudit, EvidenceRecord, Finding, PendingApproval, User
from app.services import control_assessments, evidence_service, trust_center
from starlette.requests import Request


@compiles(ARRAY, "sqlite")
def sqlite_array(_type, _compiler, **_kw):
    return "JSON"


@pytest.fixture
def api(monkeypatch):
    monkeypatch.setattr(settings, "COMPLIANCE_ENVIRONMENT", "local")
    monkeypatch.setattr(evidence_service, "_emit_evidence_audit", lambda *args: None)
    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    for model in (User, EvidenceRecord, Finding, PendingApproval, ApprovalAudit):
        model.__table__.create(engine)
    tenant, other, requester, reviewer, outsider = [uuid4() for _ in range(5)]
    with Session(engine) as db:
        for uid, tid in ((requester, tenant), (reviewer, tenant), (outsider, other)):
            db.add(User(id=uid, tenant_id=tid, email=f"{uid}@example.test", role="admin", is_active=True, mfa_enabled=True))
        db.commit()
        source = evidence_service.create_evidence(db, tenant_id=str(tenant), workflow_id=None,
            framework="SOC2", source_type="audit_event", source_reference="monitoring-operation",
            evidence_type="audit_log", evidence_data={"monitoring_window": "operating record"})
        source_id, created_at = source.id, source.created_at.replace(tzinfo=timezone.utc)
    identity = dict(tenant_id=tenant, user_id=requester, credential_kind="session", user_role="admin", scopes=["read", "write"])
    app = FastAPI()

    @app.middleware("http")
    async def bind_test_identity(request, call_next):
        for key, value in identity.items():
            setattr(request.state, key, value)
        return await call_next(request)

    def database():
        with Session(engine) as db:
            yield db

    app.dependency_overrides[get_tenant_db] = database
    app.dependency_overrides[compliance_scores.get_tenant_score_db] = database
    app.include_router(compliance_scores.router, prefix="/v1/compliance-scores")
    mfa = MagicMock(return_value=(True, datetime.now(timezone.utc)))
    monkeypatch.setitem(sys.modules, "app.api.v1.endpoints.workflows", SimpleNamespace(_verify_mfa_if_enabled=mfa))
    now = datetime.now(timezone.utc)
    proposal = dict(framework="SOC2", control_id="CC7.2", environment="local", evidence_ids=[str(source_id)],
        observed_at=now.isoformat(), period_start=(created_at - timedelta(minutes=1)).isoformat(), period_end=now.isoformat(),
        outcomes={"monitoring_operation": "pass", "alert_triage_review": "pass"},
        review_note="Independently inspect operating records and their control scope.")
    with TestClient(app, raise_server_exceptions=False) as client:
        yield SimpleNamespace(client=client, engine=engine, identity=identity, tenant=tenant, other=other,
            requester=requester, reviewer=reviewer, outsider=outsider, source_id=source_id, proposal=proposal, mfa=mfa)
    engine.dispose()


def propose(api):
    response = api.client.post("/v1/compliance-scores/assessments", json=api.proposal)
    assert response.status_code == 201, response.text
    return response.json()


@pytest.mark.parametrize("path", ["", "/SOC2"])
def test_compliance_reads_never_persist_and_posts_require_write(api, monkeypatch, path):
    calls = []
    api.client.app.dependency_overrides[compliance_scores.require_snapshot_schema] = lambda: None

    def calculate(*args, **kwargs):
        calls.append(kwargs.get("persist", False))
        raise HTTPException(418, "calculation boundary")

    monkeypatch.setattr(compliance_scores.compliance_scoring, "score_all_frameworks", calculate)
    monkeypatch.setattr(compliance_scores.compliance_scoring, "score_framework", calculate)
    api.identity["scopes"] = ["read"]
    url = "/v1/compliance-scores" + path
    for query in ("", "?persist_snapshot=true", "?persist_snapshot=false"):
        assert api.client.get(url + query).status_code == 418
        assert calls[-1] is False
    before = len(calls)
    assert api.client.post(url).status_code == 403
    assert len(calls) == before
    api.identity["scopes"] = ["read", "write"]
    assert api.client.post(url).status_code == 418
    if not path:
        assert calls[-1] is True


@pytest.mark.parametrize("nullable", [None, "NO", "YES"])
def test_snapshot_writes_require_expanded_schema(nullable):
    db = MagicMock()
    db.execute.return_value.scalar.return_value = nullable
    if nullable == "YES":
        compliance_scores.require_snapshot_schema(db)
    else:
        with pytest.raises(HTTPException) as failure:
            compliance_scores.require_snapshot_schema(db)
        assert failure.value.status_code == 503
    db.commit.assert_not_called()


def review_payload(proposal, **changes):
    return dict(approve=True, action_hash=proposal["action_hash"],
        reason="Independently reviewed the operating evidence and each outcome.", totp_code="123456", **changes)


@pytest.mark.parametrize("identity", [
    {"credential_kind": "api_key"}, {"user_role": "viewer"}, {"scopes": ["read"]}, {"user_id": None},
])
def test_proposal_requires_session_tenant_admin_with_write_scope(api, identity):
    api.identity.update(identity)
    response = api.client.post("/v1/compliance-scores/assessments", json=api.proposal)
    assert response.status_code == 403
    with Session(api.engine) as db:
        assert db.query(PendingApproval).count() == 0
    api.mfa.assert_not_called()


@pytest.mark.parametrize("mutation", ["inactive", "demoted", "different_tenant"])
def test_actor_database_state_overrides_asserted_request_role(api, mutation):
    with Session(api.engine) as db:
        user = db.get(User, api.requester)
        if mutation == "inactive":
            user.is_active = False
        elif mutation == "demoted":
            user.role = "viewer"
        else:
            api.identity["user_id"] = api.outsider
        db.commit()
    assert api.client.post("/v1/compliance-scores/assessments", json=api.proposal).status_code == 403


@pytest.mark.parametrize("revocation", [{"is_active": False}, {"role": "viewer"}])
def test_locked_principal_refreshes_cached_actor_after_database_revocation(api, revocation):
    with Session(api.engine) as db:
        cached_actor = db.get(User, api.requester)
        assert cached_actor.is_active and cached_actor.role == "admin"
        # Raw SQL models a changed database row while the ORM identity retains
        # the actor previously loaded by the endpoint authorization check.
        db.execute(update(User).where(User.id == api.requester).values(**revocation),
                   execution_options={"synchronize_session": False})
        assert cached_actor.is_active and cached_actor.role == "admin"
        with pytest.raises(ValueError, match="active tenant owner or administrator"):
            control_assessments._principal(db, api.tenant, api.requester)


def test_real_http_proposal_review_and_response_contract(api):
    pending = propose(api)
    assert pending["requester_id"] == str(api.requester)
    assert pending["status"] == "PENDING"
    assert pending["calculation_version"] == control_assessments.CALCULATION_VERSION
    assert pending["assessment"]["evidence_ids"] == [str(api.source_id)]
    assert "source_hashes" not in pending
    retrieved = api.client.get(f"/v1/compliance-scores/assessments/{pending['approval_id']}").json()
    # SQLite strips tzinfo; PostgreSQL timestamptz is covered by integration tests.
    assert datetime.fromisoformat(retrieved.pop("expires_at")).replace(tzinfo=timezone.utc) == datetime.fromisoformat(pending["expires_at"])
    assert retrieved == {key: value for key, value in pending.items() if key != "expires_at"}
    api.identity["user_id"] = api.reviewer
    response = api.client.post(f"/v1/compliance-scores/assessments/{pending['approval_id']}/review", json=review_payload(pending))
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["status"] == "CONSUMED"
    assert result["calculation_version"] == pending["calculation_version"]
    assert api.mfa.call_args.kwargs["required"] is True
    assert api.mfa.call_args.kwargs["operation"] == "control_assessment_review"
    with Session(api.engine) as db:
        record = db.query(EvidenceRecord).filter(EvidenceRecord.evidence_type == "control_assessment").one()
        assert str(record.id) == result["evidence_id"]
        assert record.tenant_id == api.tenant
        assert verify_evidence_integrity(record)
        decision = control_assessments.assess_framework(db, str(api.tenant), "SOC2", datetime.now(timezone.utc))["CC7.2"]
        assert decision["state"] == "qualified"
        assert decision["evidence_ids"] == [result["evidence_id"]]
    replay = api.client.post(f"/v1/compliance-scores/assessments/{pending['approval_id']}/review", json=review_payload(pending))
    assert replay.status_code == 400


def test_cross_tenant_read_and_review_are_not_found(api):
    pending = propose(api)
    api.identity.update(tenant_id=api.other, user_id=api.outsider)
    path = f"/v1/compliance-scores/assessments/{pending['approval_id']}"
    assert api.client.get(path).status_code == 404
    assert api.client.post(path + "/review", json=review_payload(pending)).status_code == 404
    api.mfa.assert_not_called()


def test_api_key_cannot_read_or_review_assessments(api):
    pending = propose(api)
    api.identity.update(credential_kind="api_key", user_id=api.reviewer)
    path = f"/v1/compliance-scores/assessments/{pending['approval_id']}"
    assert api.client.get(path).status_code == 403
    assert api.client.post(path + "/review", json=review_payload(pending)).status_code == 403
    api.mfa.assert_not_called()


def test_cross_tenant_source_is_rejected_before_proposal_commit(api):
    api.identity.update(tenant_id=api.other, user_id=api.outsider)
    response = api.client.post("/v1/compliance-scores/assessments", json=api.proposal)
    assert response.status_code == 400
    with Session(api.engine) as db:
        assert db.query(PendingApproval).count() == 0
        assert db.query(ApprovalAudit).count() == 0


def test_action_hash_mismatch_never_consumes_mfa_or_approval(api):
    pending = propose(api)
    api.identity["user_id"] = api.reviewer
    payload = review_payload(pending)
    payload["action_hash"] = "0" * 64
    response = api.client.post(f"/v1/compliance-scores/assessments/{pending['approval_id']}/review", json=payload)
    assert response.status_code == 409
    api.mfa.assert_not_called()
    with Session(api.engine) as db:
        assert db.query(PendingApproval).one().status == "PENDING"


def test_mfa_failure_and_self_review_cannot_consume_assessment(api):
    pending = propose(api)
    path = f"/v1/compliance-scores/assessments/{pending['approval_id']}/review"
    assert api.client.post(path, json=review_payload(pending)).status_code == 400
    api.identity["user_id"] = api.reviewer
    api.mfa.side_effect = HTTPException(status_code=401, detail="MFA challenge failed")
    assert api.client.post(path, json=review_payload(pending)).status_code == 401
    with Session(api.engine) as db:
        assert db.query(PendingApproval).one().status == "PENDING"
        assert db.query(EvidenceRecord).filter(EvidenceRecord.evidence_type == "control_assessment").count() == 0


def test_rejection_does_not_create_assessment_evidence(api):
    pending = propose(api)
    api.identity["user_id"] = api.reviewer
    payload = review_payload(pending)
    payload["approve"] = False
    response = api.client.post(f"/v1/compliance-scores/assessments/{pending['approval_id']}/review", json=payload)
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "REJECTED"
    assert response.json()["evidence_id"] is None


def test_review_service_failure_rolls_back_mutations(api, monkeypatch):
    pending = propose(api)
    api.identity["user_id"] = api.reviewer

    def fail_after_mutation(db, *_args):
        approval = db.query(PendingApproval).one()
        approval.status = "CONSUMED"
        db.flush()
        raise ValueError("Qualification failed after mutation")

    monkeypatch.setattr(control_assessments, "review_assessment", fail_after_mutation)
    response = api.client.post(f"/v1/compliance-scores/assessments/{pending['approval_id']}/review", json=review_payload(pending))
    assert response.status_code == 400
    with Session(api.engine) as db:
        assert db.query(PendingApproval).one().status == "PENDING"


def test_commit_failure_returns_no_success_and_rolls_back(api):
    def fail_commit(_db):
        raise RuntimeError("Persistence unavailable")

    event.listen(Session, "before_commit", fail_commit)
    try:
        response = api.client.post("/v1/compliance-scores/assessments", json=api.proposal)
    finally:
        event.remove(Session, "before_commit", fail_commit)
    assert response.status_code == 500
    with Session(api.engine) as db:
        assert db.query(PendingApproval).count() == 0
        assert db.query(ApprovalAudit).count() == 0


def test_evidence_writer_stamps_server_scope_and_hash_without_mutating_input(api):
    caller_data = {"environment": "production", "result": "activity"}
    with Session(api.engine) as db:
        record = evidence_service.create_evidence(db, tenant_id=str(api.tenant), workflow_id=None,
            framework="SOC2", source_type="audit_event", source_reference="server-producer",
            evidence_type="audit_log", evidence_data=caller_data)
        assert record.evidence_data["environment"] == "local"
        assert verify_evidence_integrity(record)
    assert caller_data["environment"] == "production"


@pytest.mark.parametrize("kind, data", [("control_assessment", {}), ("audit_log", {"control_assessment": {"outcome": "pass"}})])
def test_general_evidence_writer_rejects_assessment_injection(api, kind, data):
    with Session(api.engine) as db:
        before = db.query(EvidenceRecord).count()
        with pytest.raises(ValueError, match="independent governance review"):
            evidence_service.create_evidence(db, tenant_id=str(api.tenant), workflow_id=None,
                framework="SOC2", source_type="audit_event", source_reference="untrusted",
                evidence_type=kind, evidence_data=data)
        assert db.query(EvidenceRecord).count() == before


def test_public_projection_keeps_gaps_and_version_but_removes_private_provenance(monkeypatch):
    tid = uuid4()
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = SimpleNamespace(id=tid, name="Fixture", tier="enterprise")
    share = SimpleNamespace(id=uuid4(), tenant_id=tid, frameworks=["SOC2"], label="Review", auditor_email=None,
        permissions=["view_scores"], status="active", expires_at=None, created_at=None, last_accessed_at=None, access_count=0)
    monkeypatch.setattr(settings, "COMPLIANCE_OWNER_MAP_JSON", '{"platform_security":["Private fixture owner"]}')
    version = control_assessments.CALCULATION_VERSION
    private_control = dict(id="CC7.2", name="Security Event Monitoring", status="non_compliant", score=0,
        product_owners=["Private fixture owner"], operational_owners=["Private fixture owner"], gaps=["CC7.2: missing assessment"],
        traceability={"evidence": [{"id": "private-source"}]}, evidence_assessment={"state": "blocked",
        "reason_codes": ["missing_assessment"], "required_count": 2, "qualified_count": 0,
        "as_of": "2026-09-18T00:00:00+00:00", "valid_until": None, "evidence_ids": ["private-source"], "audit_id": "private-audit"})
    scores = dict(calculation_version=version, overall_score=50, readiness_level="insufficient_evidence", frameworks=[
        dict(framework="SOC2", score=0, readiness_level="insufficient_evidence", controls=[private_control]),
        dict(framework="GDPR", score=100, readiness_level="audit_ready", controls=[])],
        trust_summary=dict(counts={"verified": 1, "in_progress": 1, "planned": 0},
            verified=[{"framework": "GDPR", "id": "private-gdpr"}],
            in_progress=[{"framework": "SOC2", "id": "CC7.2"}], planned=[]))
    scorer = MagicMock(side_effect=lambda *_a, **_kw: deepcopy(scores))
    monkeypatch.setattr(trust_center.compliance_scoring, "score_all_frameworks", scorer)
    monkeypatch.setattr(trust_center, "signing_key_metadata", lambda: {"public_key": "test-key", "key_id": "test-id"})
    result = trust_center.build_public_package(db, share)["scores"]
    scorer.assert_called_once_with(db, str(tid), persist=False, include_traceability=False)
    assert result["calculation_version"] == version
    assert result["overall_score"] == 0
    assert result["readiness_level"] == "insufficient_evidence"
    assert [row["framework"] for row in result["frameworks"]] == ["SOC2"]
    assert result["trust_summary"]["verified"] == []
    control = result["frameworks"][0]["controls"][0]
    assert control["product_owners"] == ["Platform security"]
    assert control["gaps"] == ["CC7.2: missing assessment"]
    assert control["evidence_assessment"]["reason_codes"] == ["missing_assessment"]
    assert "traceability" not in control
    assert "private" not in str(result).lower()


@pytest.mark.parametrize("revoked_after_read", [False, True])
def test_public_access_revalidates_after_finishing_score_read(monkeypatch, revoked_after_read):
    db = object()
    original, refreshed = object(), object()
    state = {"read_finished": False, "lookups": 0}
    package = {"scores": {"calculation_version": "fixture", "readiness_level": "monitor"}}

    def lookup(actual_db, token):
        assert actual_db is db and token == "share-token"
        state["lookups"] += 1
        if state["read_finished"]:
            if revoked_after_read:
                raise HTTPException(status_code=404, detail="Share revoked")
            return refreshed
        return original

    def build(actual_db, share):
        assert actual_db is db and share is original
        assert not state["read_finished"]
        return package

    def finish(actual_db):
        assert actual_db is db
        state["read_finished"] = True

    def record(actual_db, share, **_kwargs):
        assert actual_db is db and share is refreshed
        assert state["read_finished"] and state["lookups"] == 2

    audit_access = MagicMock()
    recorder = MagicMock(side_effect=record)
    monkeypatch.setattr(trust_endpoints, "_public_share_or_404", lookup)
    monkeypatch.setattr(trust_endpoints, "_require_auditor_access", audit_access)
    monkeypatch.setattr(trust_center, "build_public_package", build)
    monkeypatch.setattr(trust_center.compliance_scoring, "finish_score_read", finish)
    monkeypatch.setattr(trust_center, "record_access", recorder)
    request = Request({"type": "http", "headers": [], "client": ("127.0.0.1", 12345)})
    if revoked_after_read:
        with pytest.raises(HTTPException) as error:
            trust_endpoints.get_public_trust_center("share-token", request, db)
        assert error.value.status_code == 404
        recorder.assert_not_called()
    else:
        assert trust_endpoints.get_public_trust_center("share-token", request, db) == package
        recorder.assert_called_once()
        assert audit_access.call_count == 2
    assert state["lookups"] == 2


@pytest.mark.parametrize("state,bucket,status,score", [
    ("qualified", "verified", "compliant", 100),
    ("blocked", "planned", "non_compliant", 0),
])
def test_trust_summary_preserves_public_qualification_metadata_without_provenance(state, bucket, status, score):
    safe = dict(state=state, reason_codes=[] if state == "qualified" else ["missing_assessment"],
        required_count=2, qualified_count=2 if state == "qualified" else 0,
        as_of="2026-09-18T00:00:00Z", valid_until="2026-09-19T00:00:00Z")
    control = dict(id="CC7.2", name="Monitoring", score=score, status=status,
        gaps=[] if state == "qualified" else ["CC7.2: missing assessment"],
        evidence_assessment={**safe, "evidence_ids": ["private-evidence"],
            "audit_id": "private-audit", "source_hashes": {"private-source": "private-hash"}})
    original = deepcopy(control)
    raw = trust_center.compliance_scoring._build_trust_summary([dict(framework="SOC2", controls=[control])])
    # The raw summary is used by the public package; private APIs additionally serialize it.
    serialized = compliance_scores.TrustSummaryResponse.model_validate(raw).model_dump()
    for summary in (raw, serialized):
        assert summary["calculation_version"] == control_assessments.CALCULATION_VERSION
        assert summary[bucket][0]["evidence_assessment"] == safe
        assert summary[bucket][0]["gaps"] == control["gaps"]
        assert "private" not in str(summary)
    assert control == original


def test_legacy_trust_summary_controls_remain_parseable():
    parsed = compliance_scores.TrustSummaryControlResponse.model_validate(dict(
        framework="SOC2", id="CC7.2", name="Monitoring", score=90, status="compliant"))
    assert parsed.evidence_assessment is None
    assert parsed.gaps == []

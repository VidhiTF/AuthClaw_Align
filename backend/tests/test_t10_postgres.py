"""T10 migration, authenticated PostgreSQL boundaries and concurrent persistence.

Requires all destructive-test URLs to explicitly target disposable `_test` DBs.
No SQLite fallback: missing PostgreSQL is a failed prerequisite, never a pass.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
from threading import Barrier, Event
from time import perf_counter
import tracemalloc
from types import SimpleNamespace
from uuid import uuid4
from unittest.mock import patch

import pytest
import pyotp
from fastapi import HTTPException
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from app.db.models import ApprovalAudit, ComplianceScoreSnapshot, ComplianceWorkflow, Notification, PendingApproval, TrustCenterAccessLog, TrustCenterShare, User
from app.db import dependencies, session as database_session
from app.core.auth import get_tenant_score_db, set_mfa_credentials
from app.core.startup_checks import validate_database_security
from app.services import abuse_controls, audit_store, compliance_scoring, control_assessments, event_backbone, evidence_service, trust_center
from app.api.v1.endpoints.trust_center import get_public_trust_center
from app.api.v1.endpoints import compliance_scores
from app.api.v1.endpoints import workflows as workflow_endpoints
from app.orchestrator.runner import (
    ComplianceWorkflowRunner,
    WorkflowResumeConflict,
    _create_approval_in_db,
)
from starlette.requests import Request
from tests.db_safety import destructive_test_urls
from tests.test_tenant_isolation import Identity, IsolationHarness


@pytest.fixture(scope="module")
def postgres():
    owner_url, app_url = destructive_test_urls()
    name = f"authclaw_t10_{uuid4().hex}_test"
    owner_database = make_url(owner_url).set(database=name)
    migration_database = make_url(os.environ["BACKEND_MIGRATION_DATABASE_URL"]).set(database=name)
    assert migration_database.username != owner_database.username, "Migrations require the restricted migrator role"
    admin = create_engine(owner_url, isolation_level="AUTOCOMMIT")
    owner = create_engine(owner_database)
    app = create_engine(make_url(app_url).set(database=name), pool_size=4, max_overflow=2)
    environment = {**os.environ, "POSTGRES_DB": name,
        "DATABASE_URL": owner_database.render_as_string(hide_password=False),
        "BOOTSTRAP_DATABASE_URL": owner_database.render_as_string(hide_password=False)}

    def command(*arguments, succeeds=True):
        command_environment = dict(environment)
        if arguments[:2] == ("-m", "alembic"):
            command_environment["DATABASE_URL"] = migration_database.render_as_string(hide_password=False)
        result = subprocess.run([sys.executable, *arguments], cwd=Path(__file__).parents[1],
            env=command_environment, capture_output=True, text=True, timeout=180, check=False)
        assert (result.returncode == 0) is succeeds, result.stderr
        return result

    legacy_tenant, legacy_snapshot = uuid4(), uuid4()
    legacy_user, legacy_user_two = uuid4(), uuid4()
    linkage_workflow = f"workflow-linkage-{uuid4()}"
    duplicate_pending, duplicate_approved, orphan_approval = uuid4(), uuid4(), uuid4()
    pending_audit, approved_audit = uuid4(), uuid4()
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    try:
        command("scripts/bootstrap_database_security.py", "prepare")
        command("-m", "alembic", "upgrade", "049")
        with owner.begin() as conn:
            conn.execute(text("INSERT INTO tenants (id,name) VALUES (:id,'T10 legacy migration')"), {"id": legacy_tenant})
            conn.execute(text("""INSERT INTO compliance_score_snapshots
                (id,tenant_id,framework,snapshot_date,overall_score,readiness_level,control_scores,
                 evidence_count,audit_event_count,open_findings,critical_findings,generated_at)
                VALUES (:id,:tenant,'SOC2',current_date::text,97.5,'audit_ready',
                '{"CC7.2":{"status":"compliant"}}'::jsonb,2,3,0,0,now())"""),
                {"id": legacy_snapshot, "tenant": legacy_tenant})
        command("-m", "alembic", "upgrade", "050")
        with owner.begin() as conn:
            conn.execute(text("""INSERT INTO users (id,tenant_id,email,role,platform_role,is_active,mfa_enabled,mfa_secret)
                VALUES (:id,:tenant,:email,'admin','NONE',true,true,'legacy-test-enrollment')"""), [
                {"id": legacy_user, "tenant": legacy_tenant, "email": "legacy-mfa@example.invalid"},
                {"id": legacy_user_two, "tenant": legacy_tenant, "email": "legacy-mfa-two@example.invalid"},
            ])
        command("-m", "alembic", "upgrade", "051")
        with app.connect() as connection:
            with pytest.raises(HTTPException) as failure:
                compliance_scores.require_snapshot_schema(connection)
            assert failure.value.status_code == 503
        command("-m", "alembic", "upgrade", "052")
        command("-m", "alembic", "upgrade", "053")
        with owner.begin() as conn:
            conn.execute(text("""
                INSERT INTO compliance_workflows
                    (id,tenant_id,workflow_id,framework,current_state,execution_status,
                     state_data,started_at,updated_at)
                VALUES (:id,:tenant,:workflow,'SOC2','AWAITING_APPROVAL','PAUSED',
                        '{}'::json,now(),now())
            """), {"id": uuid4(), "tenant": legacy_tenant, "workflow": linkage_workflow})
            for approval_id, status, requester, payload, action_hash, expires_at, resolution, created_at in (
                (duplicate_pending, "PENDING", legacy_user,
                 '{"plan":[{"action":"retain-pending"}]}', "1" * 64,
                 datetime(2026, 2, 1, tzinfo=timezone.utc), "pending historical reason",
                 datetime(2026, 1, 1, tzinfo=timezone.utc)),
                (duplicate_approved, "APPROVED", legacy_user_two,
                 '{"plan":[{"action":"retain-approved","destructive":true}]}', "2" * 64,
                 datetime(2026, 3, 1, tzinfo=timezone.utc), "approved historical reason",
                 datetime(2026, 1, 2, tzinfo=timezone.utc)),
            ):
                conn.execute(text("""
                    INSERT INTO pending_approvals
                        (id,tenant_id,action_id,action_type,action_description,action_payload,
                         action_hash,status,requester_id,mfa_verified,expires_at,resolution_reason,
                         created_at,updated_at)
                    VALUES (:id,:tenant,:action,'remediation','legacy duplicate',CAST(:payload AS jsonb),
                            :action_hash,:status,:requester,false,:expires,:resolution,:created,:created)
                """), {"id": approval_id, "tenant": legacy_tenant, "action": linkage_workflow,
                         "payload": payload, "action_hash": action_hash, "status": status,
                         "requester": requester, "expires": expires_at,
                         "resolution": resolution, "created": created_at})
            conn.execute(text("""
                INSERT INTO pending_approvals
                    (id,tenant_id,action_id,action_type,action_description,action_payload,
                     status,requester_id,mfa_verified,expires_at,created_at,updated_at)
                VALUES (:id,:tenant,'orphan-action','remediation','legacy orphan','{}'::json,
                        'PENDING',:user,false,now()+interval '1 hour',now(),now())
            """), {"id": orphan_approval, "tenant": legacy_tenant, "user": legacy_user})
            conn.execute(text("""
                INSERT INTO approval_audit
                    (id,tenant_id,approval_id,actor_id,action,action_hash,reason,details,
                     mfa_verified,created_at)
                VALUES (:pending_audit,:tenant,:pending,:pending_actor,'CREATED',:pending_hash,
                        'pending audit evidence','{"source":"pending"}'::jsonb,false,now()),
                       (:approved_audit,:tenant,:approved,:approved_actor,'APPROVED',:approved_hash,
                        'approved audit evidence','{"source":"approved"}'::jsonb,true,now())
            """), {"pending_audit": pending_audit, "approved_audit": approved_audit,
                     "tenant": legacy_tenant, "pending": duplicate_pending,
                     "approved": duplicate_approved, "pending_actor": legacy_user,
                     "approved_actor": legacy_user_two, "pending_hash": "1" * 64,
                     "approved_hash": "2" * 64})
            conn.execute(
                text("UPDATE compliance_workflows SET approval_id=:approval WHERE workflow_id=:workflow"),
                {"approval": duplicate_pending, "workflow": linkage_workflow},
            )
        command("-m", "alembic", "upgrade", "054")
        command("scripts/bootstrap_database_security.py", "finalize-backend")
        command("-m", "alembic", "upgrade", "head")
        command("scripts/bootstrap_database_security.py", "finalize-backend")
        with patch.dict(os.environ, AUTHCLAW_EXPECTED_DB_REVISION="054"), app.connect() as connection:
            validate_database_security(connection)
            compliance_scores.require_snapshot_schema(connection)
        harness = IsolationHarness(owner, app, sessionmaker(bind=app, expire_on_commit=False))
        harness.approval_linkage_054 = {
            "tenant_id": legacy_tenant,
            "workflow_id": linkage_workflow,
            "keeper_id": duplicate_approved,
            "duplicate_id": duplicate_pending,
            "orphan_id": orphan_approval,
            "requesters": {duplicate_pending: legacy_user, duplicate_approved: legacy_user_two},
            "payloads": {
                duplicate_pending: {"plan": [{"action": "retain-pending"}]},
                duplicate_approved: {"plan": [{"action": "retain-approved", "destructive": True}]},
            },
            "hashes": {duplicate_pending: "1" * 64, duplicate_approved: "2" * 64},
            "statuses": {duplicate_pending: "PENDING", duplicate_approved: "APPROVED"},
            "expiries": {
                duplicate_pending: datetime(2026, 2, 1, tzinfo=timezone.utc),
                duplicate_approved: datetime(2026, 3, 1, tzinfo=timezone.utc),
            },
            "resolutions": {
                duplicate_pending: "pending historical reason",
                duplicate_approved: "approved historical reason",
            },
            "audits": {pending_audit: duplicate_pending, approved_audit: duplicate_approved},
        }
        yield harness, command, legacy_snapshot
    finally:
        owner.dispose()
        app.dispose()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE "{name}"'))
        admin.dispose()


@pytest.fixture(autouse=True)
def evidence_scope(monkeypatch):
    monkeypatch.setattr(control_assessments.settings, "COMPLIANCE_ENVIRONMENT", "ci")
    monkeypatch.setattr(evidence_service, "_emit_evidence_audit", lambda *_: None)


def test_approval_linkage_upgrade_repairs_duplicates_orphans_and_reruns(postgres):
    harness, command, _ = postgres
    evidence = harness.approval_linkage_054

    def assert_reconciled():
        with harness.owner_engine.connect() as conn:
            workflow_approval = conn.execute(
                text("SELECT approval_id FROM compliance_workflows WHERE workflow_id=:workflow"),
                {"workflow": evidence["workflow_id"]},
            ).scalar_one()
            duplicate = conn.execute(
                text("SELECT action_id FROM pending_approvals WHERE id=:id"),
                {"id": evidence["duplicate_id"]},
            ).scalar_one()
            orphan_count = conn.execute(
                text("SELECT count(*) FROM pending_approvals WHERE id=:id"),
                {"id": evidence["orphan_id"]},
            ).scalar_one()
            approvals = conn.execute(text("""
                SELECT id,requester_id,action_payload,action_hash,status,expires_at,resolution_reason
                FROM pending_approvals WHERE id IN (:duplicate,:keeper)
            """), {"duplicate": evidence["duplicate_id"], "keeper": evidence["keeper_id"]}).mappings().all()
            audits = dict(conn.execute(
                text("SELECT id,approval_id FROM approval_audit WHERE id IN (:pending,:approved)"),
                {"pending": next(iter(evidence["audits"])),
                 "approved": next(reversed(evidence["audits"]))},
            ).all())
            canonical_count = conn.execute(text("""
                SELECT count(*) FROM pending_approvals
                WHERE tenant_id=:tenant AND action_type='remediation' AND action_id=:workflow
            """), {"tenant": evidence["tenant_id"], "workflow": evidence["workflow_id"]}).scalar_one()
        assert workflow_approval == evidence["keeper_id"]
        assert duplicate.endswith(f"#superseded:{evidence['duplicate_id']}")
        assert orphan_count == 1
        assert audits == evidence["audits"]
        for approval in approvals:
            approval_id = approval["id"]
            assert approval["requester_id"] == evidence["requesters"][approval_id]
            assert approval["action_payload"] == evidence["payloads"][approval_id]
            assert approval["action_hash"] == evidence["hashes"][approval_id]
            assert approval["status"] == evidence["statuses"][approval_id]
            assert approval["expires_at"] == evidence["expiries"][approval_id]
            assert evidence["resolutions"][approval_id] in approval["resolution_reason"]
        assert canonical_count == 1

    assert_reconciled()
    command("-m", "alembic", "downgrade", "053")
    command("-m", "alembic", "upgrade", "054")
    assert_reconciled()


def test_concurrent_approval_retry_reuses_single_upgraded_link(postgres):
    harness, _, _ = postgres
    identity = harness.create_identity("approval-retry")
    workflow_id = f"workflow-retry-{uuid4()}"
    with harness.owner_engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO compliance_workflows
                (id,tenant_id,workflow_id,framework,current_state,execution_status,
                 state_data,started_at,updated_at)
            VALUES (:id,:tenant,:workflow,'SOC2','AWAITING_APPROVAL','PAUSED',
                    '{}'::json,now(),now())
        """), {"id": uuid4(), "tenant": identity.tenant_id, "workflow": workflow_id})

    barrier = Barrier(2)

    def create_or_reuse():
        barrier.wait()
        with harness.session_for(identity) as db:
            return _create_approval_in_db(
                db,
                str(identity.tenant_id),
                workflow_id,
                [{"action": "redact", "destructive": False}],
                str(identity.user_id),
            )

    with ThreadPoolExecutor(max_workers=2) as pool:
        approval_ids = list(pool.map(lambda _: create_or_reuse(), range(2)))

    assert approval_ids[0] == approval_ids[1]
    with harness.owner_engine.connect() as conn:
        assert conn.execute(text("""
            SELECT count(*) FROM pending_approvals
            WHERE tenant_id=:tenant AND action_type='remediation' AND action_id=:workflow
        """), {"tenant": identity.tenant_id, "workflow": workflow_id}).scalar_one() == 1


def test_two_sessions_cannot_transfer_or_race_approved_workflow_resume(postgres):
    harness, _, _ = postgres
    requester = harness.create_identity("resume-requester")
    approver = reviewer(harness, requester)
    attacker = reviewer(harness, requester)
    workflow_id = str(uuid4())
    approval_id = uuid4()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    plan = [{"action": "redact", "destructive": False}]
    payload = workflow_endpoints.build_action_payload(workflow_id, plan)
    action_hash = workflow_endpoints.compute_action_hash(
        tenant_id=str(requester.tenant_id), action_payload=payload, expires_at=expires_at
    )
    state_data = {
        "workflow_id": workflow_id,
        "tenant_id": str(requester.tenant_id),
        "request_id": "resume-race",
        "requester_id": str(requester.user_id),
        "framework": "SOC2",
        "current_state": "AWAITING_APPROVAL",
        "remediation_plan": plan,
        "approval_id": str(approval_id),
        "approval_status": "APPROVED",
        "execution_status": "PAUSED",
    }
    with harness.session_for(requester) as db:
        db.add(PendingApproval(
            id=approval_id, tenant_id=requester.tenant_id, action_id=workflow_id,
            action_type="remediation", action_description="resume race",
            action_payload=payload, action_hash=action_hash, status="APPROVED",
            requester_id=requester.user_id, approver_id=approver.user_id,
            approved_at=datetime.now(timezone.utc), mfa_verified=True,
            mfa_timestamp=datetime.now(timezone.utc), expires_at=expires_at,
        ))
        db.add(ComplianceWorkflow(
            tenant_id=requester.tenant_id, workflow_id=workflow_id,
            framework="SOC2", current_state="AWAITING_APPROVAL",
            remediation_plan=plan, approval_id=approval_id,
            approval_status="APPROVED", execution_status="PAUSED",
            state_data=state_data,
        ))
        db.commit()

    with harness.session_for(attacker) as db:
        with pytest.raises(WorkflowResumeConflict, match="recorded approver"):
            ComplianceWorkflowRunner(db).resume(
                workflow_id, str(requester.tenant_id), str(attacker.user_id)
            )
    with harness.session_for(requester) as db:
        approval = db.get(PendingApproval, approval_id)
        workflow = db.query(ComplianceWorkflow).filter(
            ComplianceWorkflow.workflow_id == workflow_id
        ).one()
        assert approval.status == "APPROVED" and approval.consumed_at is None
        assert workflow.execution_status == "PAUSED"
        assert workflow.current_state == "AWAITING_APPROVAL"
        assert workflow.approval_status == "APPROVED"

    barrier = Barrier(2)

    def resume_as(identity):
        barrier.wait(timeout=15)
        with harness.session_for(identity) as db:
            runner = ComplianceWorkflowRunner(db)
            runner._drive_remediation_states = lambda state: state
            try:
                result = runner.resume(
                    workflow_id, str(requester.tenant_id), str(identity.user_id)
                )
                return "RESUMED", result
            except WorkflowResumeConflict:
                return "CONFLICT", None
            except ValueError as exc:
                assert "currently being processed" in str(exc)
                return "BUSY", None

    with ThreadPoolExecutor(max_workers=2) as pool:
        approver_future = pool.submit(resume_as, approver)
        attacker_future = pool.submit(resume_as, attacker)
        approver_result = approver_future.result(timeout=30)[0]
        attacker_result = attacker_future.result(timeout=30)[0]

    assert attacker_result in {"CONFLICT", "BUSY"}
    assert approver_result in {"RESUMED", "BUSY"}
    if approver_result == "BUSY":
        with harness.session_for(approver) as db:
            runner = ComplianceWorkflowRunner(db)
            runner._drive_remediation_states = lambda state: state
            runner.resume(workflow_id, str(requester.tenant_id), str(approver.user_id))

    with harness.session_for(requester) as db:
        approval = db.get(PendingApproval, approval_id)
        assert approval.status == "CONSUMED"
        assert approval.consumed_by_id == approver.user_id


def score(score_value, *, generated_at=None):
    return {"framework": "SOC2", "calculation_version": control_assessments.CALCULATION_VERSION,
        "score": score_value, "readiness_level": "monitor", "controls": [],
        "generated_at": (generated_at or datetime.now(timezone.utc)).isoformat(),
        "metrics": {"evidence_count": 0, "audit_event_count": 0, "open_findings": 0, "critical_findings": 0}}


def test_real_get_does_not_write_snapshot_or_notification(postgres):
    harness, _, _ = postgres
    tenant = harness.create_identity("ent019-read-only")
    request = SimpleNamespace(method="GET", state=SimpleNamespace(tenant_id=tenant.tenant_id))
    with harness.session_for(tenant) as db:
        db.connection(execution_options={"isolation_level": "REPEATABLE READ"})
        assert compliance_scores.get_compliance_scores(request, db=db)["overall_score"] is None
        assert compliance_scores.get_framework_score("SOC2", request, db=db)["score"] is None
        assert db.query(ComplianceScoreSnapshot).count() == db.query(Notification).count() == 0


def reviewer(harness, requester):
    identity = Identity(requester.tenant_id, uuid4(), uuid4().hex + uuid4().hex, f"reviewer-{uuid4().hex}@example.invalid")
    with harness.owner_engine.begin() as conn:
        conn.execute(text("UPDATE users SET mfa_enabled=true WHERE id=:id"), {"id": requester.user_id})
        conn.execute(text("""INSERT INTO users
            (id,tenant_id,email,role,platform_role,is_active,mfa_enabled,created_at,updated_at)
            VALUES (:id,:tenant,:email,'admin','NONE',true,true,now(),now())"""),
            {"id": identity.user_id, "tenant": identity.tenant_id, "email": identity.email})
        conn.execute(text("""SELECT authn.create_session(:hash,:tenant,:user,'t10-test',
            now()+interval '10 minutes','{}'::jsonb)"""),
            {"hash": identity.session_hash, "tenant": identity.tenant_id, "user": identity.user_id})
    return identity


def _approval_request(identity):
    request = SimpleNamespace(headers={}, query_params={}, state=SimpleNamespace())
    request.state.tenant_id = identity.tenant_id
    request.state.user_id = identity.user_id
    request.state.credential_kind = "session"
    request.state.credential_hash = identity.session_hash
    return request


def _assert_revocation_wins_post_lock_race(
    postgres, monkeypatch, *, remediation: bool
):
    harness, _, _ = postgres
    requester = harness.create_identity(
        "revocation-race-remediation" if remediation else "revocation-race-gateway"
    )
    approver = reviewer(harness, requester)
    approval_id = uuid4()
    workflow_id = f"workflow-{uuid4()}"
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    action_payload = (
        workflow_endpoints.build_action_payload(workflow_id, [])
        if remediation
        else {"request": "gateway egress"}
    )
    action_hash = workflow_endpoints.compute_action_hash(
        tenant_id=str(requester.tenant_id),
        action_payload=action_payload,
        expires_at=expires_at,
    )
    with harness.session_for(requester) as db:
        db.add(PendingApproval(
            id=approval_id,
            tenant_id=requester.tenant_id,
            action_id=workflow_id if remediation else f"gateway-{uuid4()}",
            action_type="remediation" if remediation else "gateway_policy_egress",
            action_description="Post-lock revocation regression",
            action_payload=action_payload,
            action_hash=action_hash,
            status="PENDING",
            requester_id=requester.user_id,
            expires_at=expires_at,
        ))
        if remediation:
            db.add(ComplianceWorkflow(
                tenant_id=requester.tenant_id,
                workflow_id=workflow_id,
                framework="SOC2",
                current_state="HUMAN_APPROVAL",
                remediation_plan=[],
                approval_id=approval_id,
                approval_status="PENDING",
                execution_status="PAUSED",
            ))
        db.commit()

    monkeypatch.setattr(
        workflow_endpoints,
        "_verify_mfa_if_enabled",
        lambda *_args, **_kwargs: (True, datetime.now(timezone.utc)),
    )
    if remediation:
        monkeypatch.setattr(
            workflow_endpoints.ComplianceWorkflowRunner,
            "get_status",
            lambda *_args, **_kwargs: {
                "execution_status": "PAUSED",
                "approval_id": str(approval_id),
            },
        )

    lock_requested = Event()

    def observe_user_lock(_conn, _cursor, statement, _parameters, _context, _many):
        normalized = " ".join(statement.upper().split())
        if "FROM USERS" in normalized and "FOR UPDATE" in normalized:
            lock_requested.set()

    event.listen(harness.app_engine, "before_cursor_execute", observe_user_lock)
    blocker = harness.owner_engine.connect()
    transaction = blocker.begin()
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        blocker.execute(
            text("SELECT id FROM users WHERE id=:id FOR UPDATE"),
            {"id": approver.user_id},
        )

        def approve():
            with harness.session_for(approver) as db:
                request = _approval_request(approver)
                body = workflow_endpoints.ApprovalRequest(totp_code="000000")
                if remediation:
                    return workflow_endpoints.approve_workflow(
                        workflow_id, request, body, db
                    )
                return workflow_endpoints.approve_gateway_approval(
                    str(approval_id), request, body, db
                )

        future = executor.submit(approve)
        assert lock_requested.wait(timeout=10), "approval never reached the locked user row"
        assert blocker.execute(
            text("SELECT authn.revoke_session(:credential_hash)"),
            {"credential_hash": approver.session_hash},
        ).scalar_one()
        transaction.commit()
        with pytest.raises(HTTPException) as rejected:
            future.result(timeout=15)
        assert rejected.value.status_code == 401
    finally:
        if transaction.is_active:
            transaction.rollback()
        blocker.close()
        executor.shutdown(wait=True, cancel_futures=True)
        event.remove(harness.app_engine, "before_cursor_execute", observe_user_lock)

    with harness.owner_engine.connect() as conn:
        assert conn.execute(
            text("SELECT status FROM pending_approvals WHERE id=:id"),
            {"id": approval_id},
        ).scalar_one() == "PENDING"
        assert conn.execute(
            text("SELECT count(*) FROM approval_audit WHERE approval_id=:id"),
            {"id": approval_id},
        ).scalar_one() == 0


def test_gateway_approval_cannot_commit_after_blocked_session_is_revoked(
    postgres, monkeypatch
):
    _assert_revocation_wins_post_lock_race(postgres, monkeypatch, remediation=False)


def test_remediation_approval_cannot_resume_after_blocked_session_is_revoked(
    postgres, monkeypatch
):
    _assert_revocation_wins_post_lock_race(postgres, monkeypatch, remediation=True)


def pending_assessment(harness, requester):
    with harness.session_for(requester) as db:
        source = evidence_service.create_evidence(db, tenant_id=str(requester.tenant_id), workflow_id=None,
            framework="SOC2", source_type="audit_event", source_reference="T10 scoped monitoring export",
            evidence_type="audit_log", evidence_data={"monitoring": "Observed alert triage operation"})
        now = datetime.now(timezone.utc)
        proposal = control_assessments.propose_assessment(db, str(requester.tenant_id), str(requester.user_id), {
            "framework": "SOC2", "control_id": "CC7.2", "environment": "ci", "evidence_ids": [str(source.id)],
            "observed_at": now, "period_start": now - timedelta(days=1), "period_end": now,
            "outcomes": {"monitoring_operation": "pass", "alert_triage_review": "pass"},
            "review_note": "Reviewed monitoring and triage operation against the scoped immutable export.",
        })
        db.commit()
        return proposal.id, source.id, proposal.action_hash


def reviewed_assessment(harness, requester, approver=None):
    approver = approver or reviewer(harness, requester)
    proposal_id, source_id, _ = pending_assessment(harness, requester)
    with harness.session_for(approver) as db:
        assessment = control_assessments.review_assessment(db, str(requester.tenant_id), str(proposal_id),
            str(approver.user_id), True, "Independent reviewer verified the source scope and successful outcomes.",
            datetime.now(timezone.utc))
        db.commit()
        assessment_id = assessment.id
    return proposal_id, source_id, assessment_id


def test_migration_preserves_legacy_rows_and_restricted_forced_rls(postgres):
    harness, _, legacy_id = postgres
    linkage = harness.approval_linkage_054
    with harness.owner_engine.connect() as conn:
        row = conn.execute(text("SELECT * FROM compliance_score_snapshots WHERE id=:id"), {"id": legacy_id}).mappings().one()
        assert row["overall_score"] == 97.5
        assert row["control_scores"] == {"CC7.2": {"status": "compliant"}}
        assert row["calculation_version"] == "legacy_unversioned"
        assert row["assessment_metadata"] == {}
        prior_user = conn.execute(text("""SELECT mfa_enabled,mfa_last_totp_step FROM users
            WHERE tenant_id=:tenant AND id=:user"""),
            {"tenant": row["tenant_id"],
             "user": linkage["requesters"][linkage["duplicate_id"]]}).one()
        assert prior_user.mfa_enabled is True and prior_user.mfa_last_totp_step is None
        assert conn.execute(text("""SELECT pg_get_userbyid(c.relowner)
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relname='compliance_score_snapshots'""")).scalar_one() == make_url(os.environ["BACKEND_MIGRATION_DATABASE_URL"]).username
        flags = conn.execute(text("""SELECT relname,relrowsecurity,relforcerowsecurity FROM pg_class
            WHERE relname IN ('compliance_score_snapshots','approval_audit','pending_approvals','evidence_records')""")).all()
        assert len(flags) == 4 and all(row.relrowsecurity and row.relforcerowsecurity for row in flags)
    with harness.app_engine.connect() as conn:
        role = conn.execute(text("SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user")).one()
        assert not role.rolsuper and not role.rolbypassrls
        assert conn.execute(text("SELECT count(*) FROM compliance_score_snapshots")).scalar_one() == 0


def seed_activity(harness, tenant):
    with harness.session_for(tenant) as db:
        for index in range(5):
            evidence_service.create_evidence(db, tenant_id=str(tenant.tenant_id), workflow_id=None,
                framework="SOC2", source_type="audit_event", source_reference=f"Operating record {index}",
                evidence_type="audit_log", evidence_data={"monitoring": "Reviewed operating trace"})
        for index in range(25):
            audit_store.append_audit_event(db, event_backbone.audit_event(event_type="test_monitoring",
                tenant_id=str(tenant.tenant_id), subject_id=str(index), identity_action="monitored",
                action="security.monitoring", reason="Recorded scoped monitoring operation", provider="test",
                actor_id=str(tenant.user_id), frameworks=["SOC2"]))
        db.commit()


@pytest.mark.parametrize("with_activity", [False, True])
def test_real_evidence_writer_and_review_qualify_with_repeatable_read(postgres, with_activity):
    harness, _, _ = postgres
    tenant = harness.create_identity("t10-producer")
    if with_activity:
        seed_activity(harness, tenant)
    with harness.session_for(tenant) as db:
        db.connection(execution_options={"isolation_level": "REPEATABLE READ"})
        db.info["compliance_read_transaction"] = True
        unreviewed = compliance_scores.get_framework_score("SOC2", SimpleNamespace(method="POST", state=SimpleNamespace(tenant_id=tenant.tenant_id)), db=db)
        assert unreviewed["score"] is None and unreviewed["readiness_level"] == "insufficient_evidence"
        assert all(row["score"] is None and row["status"] == "insufficient_evidence" for row in unreviewed["controls"])
        if with_activity:
            assert next(row for row in unreviewed["controls"] if row["id"] == "CC7.2")["activity_diagnostics"]["score"] == 100
        assert db.query(ComplianceScoreSnapshot).one().overall_score is None
    _, _, assessment_id = reviewed_assessment(harness, tenant)
    with harness.session_for(tenant) as db:
        db.connection(execution_options={"isolation_level": "REPEATABLE READ"})
        db.info["compliance_read_transaction"] = True
        result = compliance_scores.get_framework_score("SOC2", SimpleNamespace(method="POST", state=SimpleNamespace(tenant_id=tenant.tenant_id)), db=db)
        result = compliance_scores.FrameworkScoreResponse.model_validate(result).model_dump()
        control = next(row for row in result["controls"] if row["id"] == "CC7.2")
        assert control["evidence_assessment"]["state"] == "qualified", control["evidence_assessment"]
        assert control["status"] == "compliant"
        assert control["score"] == 100
        assert control["activity_diagnostics"]["authoritative"] is False
        assert (control["activity_diagnostics"]["score"] == 100) is with_activity
        assert str(assessment_id) in control["evidence_assessment"]["evidence_ids"]
        persisted = db.query(ComplianceScoreSnapshot).one()
        assert persisted.calculation_version == result["calculation_version"]
        assert persisted.overall_score is None
        assert persisted.control_scores["CC7.2"]["score"] == 100


def test_request_dependency_uses_single_connection_and_resets_write_isolation(postgres, monkeypatch):
    harness, _, _ = postgres
    tenant = harness.create_identity("t10-one-connection")
    pool = create_engine(harness.app_engine.url, pool_size=1, max_overflow=0, pool_timeout=2)
    monkeypatch.setenv("AUTHCLAW_RUNTIME_DB_ROLE", pool.url.username)
    event.listen(pool, "checkout", database_session.verify_runtime_database_identity)
    monkeypatch.setattr(dependencies, "SessionLocal", sessionmaker(bind=pool, expire_on_commit=False))
    request = SimpleNamespace(state=SimpleNamespace(tenant_id=tenant.tenant_id, user_id=tenant.user_id,
        credential_kind="session", credential_hash=tenant.session_hash))
    dependency = dependencies.get_score_db()
    db = next(dependency)
    authenticated = get_tenant_score_db(request, db)
    try:
        assert next(authenticated) is db
        assert db.connection().get_isolation_level() == "REPEATABLE READ"
        backend = db.execute(text("SELECT pg_backend_pid()")).scalar_one()
        result = compliance_scoring.score_framework(db, str(tenant.tenant_id), "SOC2", include_traceability=False)
        assert pool.pool.checkedout() == 1
        assert db.execute(text("SELECT pg_backend_pid()")).scalar_one() == backend
        compliance_scoring.upsert_score_snapshot(db, str(tenant.tenant_id), result)
        assert db.connection().get_isolation_level() == "READ COMMITTED"
        assert db.execute(text("SELECT authn.current_tenant_id()")).scalar_one() == tenant.tenant_id
        assert db.query(ComplianceScoreSnapshot).count() == 1
    finally:
        authenticated.close()
        dependency.close()
        pool.dispose()


@pytest.mark.parametrize("verb", ["UPDATE", "DELETE"])
def test_assessment_audits_are_immutable_even_to_owner(postgres, verb):
    harness, _, _ = postgres
    tenant = harness.create_identity(f"t10-audit-{verb.lower()}")
    proposal_id, _, _ = reviewed_assessment(harness, tenant)
    with pytest.raises(DBAPIError, match="immutable"):
        with harness.owner_engine.begin() as conn:
            sql = ("UPDATE approval_audit SET reason='altered' WHERE approval_id=:id" if verb == "UPDATE"
                   else "DELETE FROM approval_audit WHERE approval_id=:id")
            conn.execute(text(sql), {"id": proposal_id})
    with harness.session_for(tenant) as db:
        assert db.query(ApprovalAudit).filter(ApprovalAudit.approval_id == proposal_id).count() == 2


def test_cross_tenant_snapshot_and_review_reads_inserts_updates_history_denied(postgres):
    harness, _, _ = postgres
    alice, bob = harness.create_identity("t10-alice"), harness.create_identity("t10-bob")
    proposal_id, _, _ = reviewed_assessment(harness, bob)
    with harness.session_for(bob) as db:
        bob_snapshot = compliance_scoring.upsert_score_snapshot(db, str(bob.tenant_id), score(60)).id
    with harness.session_for(alice) as db:
        assert db.query(ComplianceScoreSnapshot).filter(ComplianceScoreSnapshot.id == bob_snapshot).first() is None
        assert db.query(PendingApproval).filter(PendingApproval.id == proposal_id).first() is None
        assert db.query(ApprovalAudit).filter(ApprovalAudit.approval_id == proposal_id).count() == 0
        assert compliance_scoring.score_history(db, str(bob.tenant_id)) == []
        assert db.execute(text("UPDATE compliance_score_snapshots SET overall_score=100 WHERE id=:id"), {"id": bob_snapshot}).rowcount == 0
    with pytest.raises(DBAPIError):
        with harness.session_for(alice) as db:
            compliance_scoring.upsert_score_snapshot(db, str(bob.tenant_id), score(100))
    with harness.session_for(alice) as db:
        own = compliance_scoring.upsert_score_snapshot(db, str(alice.tenant_id), score(40)).id
    with pytest.raises(DBAPIError):
        with harness.session_for(alice) as db:
            db.execute(text("UPDATE compliance_score_snapshots SET tenant_id=:tenant WHERE id=:id"),
                       {"tenant": bob.tenant_id, "id": own})
    with harness.session_for(bob) as db:
        assert db.get(ComplianceScoreSnapshot, bob_snapshot).overall_score == 60


def test_concurrent_same_day_snapshot_is_idempotent_and_emits_one_drop(postgres):
    harness, _, _ = postgres
    tenant = harness.create_identity("t10-concurrent")
    when = datetime.now(timezone.utc)
    with harness.session_for(tenant) as db:
        compliance_scoring.upsert_score_snapshot(db, str(tenant.tenant_id), score(90, generated_at=when-timedelta(seconds=1)))
    barrier = Barrier(2)
    def persist():
        with harness.session_for(tenant) as db:
            barrier.wait(timeout=15)
            return str(compliance_scoring.upsert_score_snapshot(db, str(tenant.tenant_id), score(70, generated_at=when)).id)
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(persist) for _ in range(2)]
        identifiers = [future.result(timeout=30) for future in futures]
    assert identifiers[0] == identifiers[1]
    with harness.session_for(tenant) as db:
        assert db.query(ComplianceScoreSnapshot).count() == 1
        assert db.query(Notification).filter(Notification.type == "compliance_score_drop").count() == 1


def test_versions_coexist_history_uses_dates_and_method_change_does_not_alert(postgres, monkeypatch):
    harness, _, _ = postgres
    tenant = harness.create_identity("t10-versions")
    when = datetime.now(timezone.utc)
    with harness.session_for(tenant) as db:
        compliance_scoring.upsert_score_snapshot(db, str(tenant.tenant_id), score(95, generated_at=when-timedelta(days=10)))
        compliance_scoring.upsert_score_snapshot(db, str(tenant.tenant_id), score(95, generated_at=when-timedelta(seconds=2)))
    monkeypatch.setattr(control_assessments, "CALCULATION_VERSION", "test-reviewed-policy-next")
    with harness.session_for(tenant) as db:
        compliance_scoring.upsert_score_snapshot(db, str(tenant.tenant_id), score(65, generated_at=when-timedelta(seconds=1)))
        assert db.query(Notification).count() == 0
        rows = compliance_scoring.score_history(db, str(tenant.tenant_id), "SOC2", days=1)
        assert len(rows) == 2 and len({row["calculation_version"] for row in rows}) == 2
        compliance_scoring.upsert_score_snapshot(db, str(tenant.tenant_id), score(50, generated_at=when))
        assert db.query(Notification).filter(Notification.type == "compliance_score_drop").count() == 1


def test_rollback_preserves_snapshot_and_notification_atomicity(postgres):
    harness, _, _ = postgres
    tenant = harness.create_identity("t10-rollback")
    when = datetime.now(timezone.utc)
    with harness.session_for(tenant) as db:
        compliance_scoring.upsert_score_snapshot(db, str(tenant.tenant_id), score(90, generated_at=when-timedelta(seconds=1)))
        compliance_scoring.upsert_score_snapshot(db, str(tenant.tenant_id), score(50, generated_at=when), commit=False)
        db.flush()
        db.rollback()
        assert db.query(ComplianceScoreSnapshot).one().overall_score == 90
        assert db.query(Notification).count() == 0


def test_unknown_transition_persists_null_and_one_atomic_alert(postgres):
    harness, _, _ = postgres
    tenant = harness.create_identity("ent019-unknown-snapshot")
    when = datetime.now(timezone.utc)
    with harness.session_for(tenant) as db:
        compliance_scoring.upsert_score_snapshot(db, str(tenant.tenant_id), score(90, generated_at=when))
        unknown = {**score(None, generated_at=when + timedelta(seconds=1)),
                   "readiness_level": "insufficient_evidence", "evidence_timestamp": None,
                   "inputs_as_of": when.isoformat(), "missing_control_treatment": compliance_scoring.MISSING_CONTROL_TREATMENT}
        compliance_scoring.upsert_score_snapshot(db, str(tenant.tenant_id), unknown)
        compliance_scoring.upsert_score_snapshot(db, str(tenant.tenant_id), unknown)
        assert db.query(ComplianceScoreSnapshot).one().overall_score is None
        assert db.query(Notification).filter(Notification.type == "compliance_score_unavailable").count() == 1
        history = compliance_scoring.score_history(db, str(tenant.tenant_id))[0]
        assert history["overall_score"] is None and history["evidence_timestamp"] is None
        assert history["inputs_as_of"] == when.isoformat()


def test_all_framework_snapshots_roll_back_on_real_postgres_failure(postgres, monkeypatch):
    harness, _, _ = postgres
    tenant = harness.create_identity("ent019-batch-rollback")
    with harness.session_for(tenant) as db:
        for framework in compliance_scoring.FRAMEWORKS:
            compliance_scoring.upsert_score_snapshot(db, str(tenant.tenant_id), {**score(90), "framework": framework})
    monkeypatch.setattr(compliance_scoring, "_calculate_framework", lambda db, tid, framework, **kwargs:
                        {**score(50, generated_at=kwargs["as_of"]), "framework": framework, "evidence_timestamp": None})

    def fail_second_framework(conn, cursor, statement, parameters, context, many):
        if statement.startswith("INSERT INTO compliance_score_snapshots") and parameters.get("framework") == "GDPR":
            conn.exec_driver_sql("SELECT 1 / 0")

    event.listen(harness.app_engine, "before_cursor_execute", fail_second_framework)
    try:
        with harness.session_for(tenant) as db:
            db.connection(execution_options={"isolation_level": "REPEATABLE READ"})
            db.info["compliance_read_transaction"] = True
            with pytest.raises(DBAPIError, match="division by zero"):
                compliance_scoring.score_all_frameworks(db, str(tenant.tenant_id), include_traceability=False)
            assert {row.overall_score for row in db.query(ComplianceScoreSnapshot).all()} == {90}
            assert db.query(Notification).count() == 0
    finally:
        event.remove(harness.app_engine, "before_cursor_execute", fail_second_framework)


def test_concurrent_first_framework_batches_are_one_revision(postgres, monkeypatch):
    harness, _, _ = postgres
    tenant = harness.create_identity("ent019-first-batch")
    barrier = Barrier(2)
    monkeypatch.setattr(compliance_scoring, "_calculate_framework", lambda db, tid, framework, **kwargs:
                        {**score(50, generated_at=kwargs["as_of"]), "framework": framework, "evidence_timestamp": None})

    def persist():
        with harness.session_for(tenant) as db:
            db.connection(execution_options={"isolation_level": "REPEATABLE READ"})
            db.info["compliance_read_transaction"] = True
            barrier.wait(timeout=15)
            return compliance_scoring.score_all_frameworks(db, str(tenant.tenant_id), include_traceability=False)["generated_at"]

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(persist) for _ in range(2)]
        latest = max(future.result(timeout=30) for future in futures)
    with harness.session_for(tenant) as db:
        rows = db.query(ComplianceScoreSnapshot).all()
        assert {row.framework for row in rows} == set(compliance_scoring.FRAMEWORKS)
        assert len(rows) == 3
        assert {row.generated_at.isoformat() for row in rows} == {latest}


def test_nullable_expansion_preserves_unknowns_and_old_numeric_writes_on_rollback(postgres):
    harness, command, _ = postgres
    tenant = harness.create_identity("ent019-null-rollback")
    with harness.session_for(tenant) as db:
        identifier = compliance_scoring.upsert_score_snapshot(db, str(tenant.tenant_id), score(None)).id
    command("-m", "alembic", "downgrade", "051")
    try:
        with harness.owner_engine.begin() as conn:
            assert conn.execute(text("SELECT overall_score FROM compliance_score_snapshots WHERE id=:id"), {"id": identifier}).scalar_one() is None
            assert conn.execute(text("SELECT is_nullable FROM information_schema.columns WHERE table_schema='public' AND table_name='compliance_score_snapshots' AND column_name='overall_score'")).scalar_one() == "YES"
            conn.execute(text("UPDATE compliance_score_snapshots SET overall_score=50 WHERE id=:id"), {"id": identifier})
    finally:
        command("-m", "alembic", "upgrade", "head")


def test_downgrade_refuses_retained_versioned_history_and_keeps_rls(postgres):
    harness, command, _ = postgres
    tenant = harness.create_identity("t10-downgrade")
    with harness.session_for(tenant) as db:
        compliance_scoring.upsert_score_snapshot(db, str(tenant.tenant_id), score(50))
    result = command("-m", "alembic", "downgrade", "049", succeeds=False)
    assert "downgrade refused" in result.stderr
    with harness.owner_engine.connect() as conn:
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == "054"
        assert conn.execute(text("SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE relname='compliance_score_snapshots'")).scalar_one()


def test_concurrent_public_score_views_rebind_and_log_each_access(postgres, monkeypatch):
    harness, _, _ = postgres
    tenant = harness.create_identity("t10-public")
    seed_activity(harness, tenant)
    monkeypatch.setenv("SESSION_SECRET_V1", "test-only-t10-auditor-session-secret-32-bytes")
    monkeypatch.setenv("AUTHCLAW_SESSION_KEY_VERSION", "v1")
    delivered = {}
    def deliver(_email, otp, _tenant, **_kwargs):
        delivered["otp"] = otp
        return SimpleNamespace(method="smtp")
    monkeypatch.setattr(trust_center, "send_otp_email", deliver)
    monkeypatch.setattr(trust_center, "signing_key_metadata", lambda: {"public_key": "test-public-key", "key_id": "test-key"})
    with harness.session_for(tenant) as db:
        share, token = trust_center.create_share(db, tenant_id=tenant.tenant_id, label="T10 concurrent views",
            auditor_email="reviewer@example.invalid", frameworks=["SOC2"], created_by=tenant.user_id)
        trust_center.issue_auditor_otp(db, share, "T10 test tenant")
        access = trust_center.verify_auditor_otp(db, share, token, delivered["otp"])["access_token"]
        share_id = share.id
    # Make both readers hold the same pre-write view to expose RR write conflicts.
    barrier = Barrier(2)
    build = trust_center.build_public_package
    def build_concurrently(db, share):
        result = build(db, share)
        barrier.wait(timeout=15)
        return result
    monkeypatch.setattr(trust_center, "build_public_package", build_concurrently)
    monkeypatch.setattr(dependencies, "SessionLocal", harness.testing_session_local)
    def view():
        dependency = dependencies.get_score_db()
        db = next(dependency)
        try:
            return get_public_trust_center(token, SimpleNamespace(
                headers={"x-trust-center-access": access}, client=SimpleNamespace(host="127.0.0.1")), db)
        finally:
            dependency.close()
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(view) for _ in range(2)]
        packages = [future.result(timeout=30) for future in futures]
    assert all(package["scores"]["calculation_version"] == control_assessments.CALCULATION_VERSION for package in packages)
    assert all([row["framework"] for row in package["scores"]["frameworks"]] == ["SOC2"] for package in packages)
    assert all(package["scores"]["overall_score"] is None
               and package["scores"]["readiness_level"] == "insufficient_evidence" for package in packages)
    with harness.session_for(tenant) as db:
        assert db.get(TrustCenterShare, share_id).access_count == 2
        assert db.query(TrustCenterAccessLog).filter(TrustCenterAccessLog.share_id == share_id,
            TrustCenterAccessLog.action == "view").count() == 2


@pytest.mark.skipif(os.getenv("T10_POSTGRES_MEASURE") != "1", reason="Opt-in synthetic measurement; no production SLO is asserted")
def test_synthetic_tenant_measurement(postgres):
    harness, _, _ = postgres
    tenant = harness.create_identity("t10-synthetic-volume")
    approver = reviewer(harness, tenant)
    with harness.session_for(tenant) as db:
        for index in range(500):
            evidence_service.create_evidence(db, tenant_id=str(tenant.tenant_id), workflow_id=None,
                framework="SOC2", source_type="audit_event", source_reference=f"Synthetic archived record {index}",
                evidence_type="audit_log", evidence_data={"sample": "Operating log sample. " * 200})
    for _ in range(100):
        reviewed_assessment(harness, tenant, approver)
    statements = []
    def track(_conn, _cursor, statement, _params, _context, _many):
        if statement.lstrip().upper().startswith("SELECT"):
            statements.append(statement)
    event.listen(harness.app_engine, "before_cursor_execute", track)
    try:
        with harness.session_for(tenant) as db:
            db.connection(execution_options={"isolation_level": "REPEATABLE READ"})
            statements.clear()
            start = perf_counter()
            metrics = compliance_scoring.collect_metrics(db, str(tenant.tenant_id), "SOC2")
            baseline_ms, baseline_queries = (perf_counter() - start) * 1000, len(statements)
            statements.clear()
            tracemalloc.start()
            start = perf_counter()
            qualified = control_assessments.assess_framework(db, str(tenant.tenant_id), "SOC2", datetime.now(timezone.utc))
            qualification_ms = (perf_counter() - start) * 1000
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            qualification_queries = len(statements)
            statements.clear()
            start = perf_counter()
            result = compliance_scoring.score_framework(db, str(tenant.tenant_id), "SOC2", include_traceability=False)
            full_ms, full_queries = (perf_counter() - start) * 1000, len(statements)
            assert metrics.evidence_count == 700 and qualified["CC7.2"]["state"] == "qualified"
            assert qualification_queries == 5
            print("T10_SYNTHETIC_MEASUREMENT=" + json.dumps({
                "postgresql": db.execute(text("SHOW server_version")).scalar_one(),
                "source_records": 600, "approved_assessments": 100, "review_audits": 200,
                "activity_metrics_baseline_ms": round(baseline_ms, 2), "activity_metrics_queries": baseline_queries,
                "qualification_ms_with_tracemalloc": round(qualification_ms, 2),
                "qualification_queries": qualification_queries, "qualification_python_peak_bytes": peak,
                "full_framework_ms": round(full_ms, 2), "full_framework_queries": full_queries,
                "full_framework_payload_bytes": len(json.dumps(result).encode()),
                "limit": "Synthetic loopback observation only; no production SLO or previous-version benchmark asserted",
            }, sort_keys=True))
    finally:
        if tracemalloc.is_tracing():
            tracemalloc.stop()
        event.remove(harness.app_engine, "before_cursor_execute", track)


@pytest.fixture
def real_mfa(postgres, monkeypatch):
    """Only rate-limit Redis storage is substituted; crypto, verifier and DB run."""
    from app.api.v1.endpoints import workflows
    harness, _, _ = postgres
    requester = harness.create_identity("t10-durable-mfa")
    approver = reviewer(harness, requester)
    secret = pyotp.random_base32()
    backup = "t10-one-use-backup-code"
    monkeypatch.setenv("AUTHCLAW_SECRET_PROVIDER", "env")
    monkeypatch.setenv("ENVELOPE_KEY_V1", "test-only-t10-envelope-key-material")
    monkeypatch.setenv("AUTHCLAW_SECRET_KEY_VERSION", "v1")
    monkeypatch.setenv("SESSION_SECRET_V1", "test-only-t10-mfa-session-key-material")
    monkeypatch.setenv("AUTHCLAW_SESSION_KEY_VERSION", "v1")
    class RedisRateLimitStorage:
        def eval(self, script, _number, *_arguments):
            if script == abuse_controls.MFA_CHECK_LUA:
                return -2
            if script == abuse_controls.MFA_RESET_LUA:
                return 0
            if script == abuse_controls.MFA_FAILURE_LUA:
                return [1, 0, 0]
            raise AssertionError("Unexpected Redis operation")
    monkeypatch.setattr(workflows, "_get_redis", lambda: RedisRateLimitStorage())
    # MFA security audit events use their normal writer against the disposable DB.
    monkeypatch.setattr(database_session, "SessionLocal", harness.testing_session_local)
    with harness.session_for(approver) as db:
        user = db.get(User, approver.user_id)
        set_mfa_credentials(user, secret, [backup])
        db.commit()
        assert user.mfa_secret != secret and user.mfa_last_totp_step is None
    def decide(pending, code, actor=approver):
        approval_id, _, action_hash = pending
        request = Request({"type": "http", "headers": [], "query_string": b"",
            "client": ("127.0.0.1", 12345)})
        request.state.tenant_id, request.state.user_id = actor.tenant_id, actor.user_id
        request.state.credential_kind = "session"
        body = compliance_scores.AssessmentReviewRequest(approve=True, action_hash=action_hash,
            reason="Independently verified each scoped operating record and its control outcome.", totp_code=code)
        with harness.session_for(actor) as db:
            return compliance_scores.review_control_assessment(approval_id, body, request, db)
    return SimpleNamespace(harness=harness, requester=requester, approver=approver, secret=secret,
        backup=backup, decide=decide, pending=lambda: pending_assessment(harness, requester))


def test_real_totp_cannot_be_reused_across_distinct_approvals_and_next_step_succeeds(real_mfa):
    state = real_mfa
    first, second = state.pending(), state.pending()
    code = pyotp.TOTP(state.secret).now()
    assert state.decide(first, code)["status"] == "CONSUMED"
    with state.harness.session_for(state.approver) as db:
        consumed_step = db.get(User, state.approver.user_id).mfa_last_totp_step
        assert isinstance(consumed_step, int)
    with pytest.raises(HTTPException) as rejected:
        state.decide(second, code)
    assert rejected.value.status_code == 400
    with state.harness.session_for(state.approver) as db:
        assert db.get(PendingApproval, second[0]).status == "PENDING"
        assert db.get(User, state.approver.user_id).mfa_last_totp_step == consumed_step
    next_code = pyotp.TOTP(state.secret).at((consumed_step + 1) * 30)
    assert state.decide(second, next_code)["status"] == "CONSUMED"
    with state.harness.session_for(state.approver) as db:
        assert db.get(User, state.approver.user_id).mfa_last_totp_step == consumed_step + 1


def test_concurrent_same_totp_step_allows_exactly_one_approval(real_mfa):
    state = real_mfa
    proposals = [state.pending(), state.pending()]
    code, barrier = pyotp.TOTP(state.secret).now(), Barrier(2)
    def decide(pending):
        barrier.wait(timeout=15)
        try:
            return state.decide(pending, code)["status"]
        except HTTPException as exc:
            assert exc.status_code == 400
            return "MFA_REJECTED"
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(decide, pending) for pending in proposals]
        outcomes = [future.result(timeout=30) for future in futures]
    assert sorted(outcomes) == ["CONSUMED", "MFA_REJECTED"]
    with state.harness.session_for(state.approver) as db:
        rows = db.query(PendingApproval).filter(PendingApproval.id.in_([item[0] for item in proposals])).all()
        assert sorted(row.status for row in rows) == ["CONSUMED", "PENDING"]
        assert db.query(ApprovalAudit).filter(ApprovalAudit.action == "ASSESSMENT_APPROVED").count() == 1


def test_real_backup_code_is_consumed_once_across_approvals(real_mfa):
    state = real_mfa
    first, second = state.pending(), state.pending()
    assert state.decide(first, state.backup)["status"] == "CONSUMED"
    with pytest.raises(HTTPException) as rejected:
        state.decide(second, state.backup)
    assert rejected.value.status_code == 400
    with state.harness.session_for(state.approver) as db:
        assert db.get(User, state.approver.user_id).mfa_backup_codes == []
        assert db.get(PendingApproval, second[0]).status == "PENDING"


def test_mfa_replay_state_is_tenant_scoped_and_reenrollment_preserves_consumption(real_mfa):
    state = real_mfa
    state.decide(state.pending(), pyotp.TOTP(state.secret).now())
    stranger = state.harness.create_identity("t10-mfa-other-tenant")
    with state.harness.session_for(stranger) as db:
        assert db.query(User.mfa_last_totp_step).filter(User.id == state.approver.user_id).first() is None
        assert db.execute(text("UPDATE users SET mfa_last_totp_step=NULL WHERE id=:id"),
            {"id": state.approver.user_id}).rowcount == 0
    with state.harness.session_for(state.approver) as db:
        user = db.get(User, state.approver.user_id)
        consumed = user.mfa_last_totp_step
        set_mfa_credentials(user, state.secret, [])
        db.commit()
        assert db.get(User, state.approver.user_id).mfa_last_totp_step == consumed


def test_cross_over_reviews_lock_principals_in_one_order_without_deadlock(real_mfa):
    state = real_mfa
    requester_secret = pyotp.random_base32()
    with state.harness.session_for(state.requester) as db:
        set_mfa_credentials(db.get(User, state.requester.user_id), requester_secret, [])
        db.commit()
    first = state.pending()
    second = pending_assessment(state.harness, state.approver)
    barrier = Barrier(2)
    def decide(pending, code, actor):
        barrier.wait(timeout=15)
        return state.decide(pending, code, actor)["status"]
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(decide, first, pyotp.TOTP(state.secret).now(), state.approver),
                   executor.submit(decide, second, pyotp.TOTP(requester_secret).now(), state.requester)]
        assert [future.result(timeout=30) for future in futures] == ["CONSUMED", "CONSUMED"]
    with state.harness.session_for(state.approver) as db:
        assert db.query(ApprovalAudit).filter(ApprovalAudit.action == "ASSESSMENT_APPROVED").count() == 2


def test_durable_mfa_state_prevents_schema_downgrade(real_mfa, postgres):
    state = real_mfa
    state.decide(state.pending(), pyotp.TOTP(state.secret).now())
    harness, command, _ = postgres
    result = command("-m", "alembic", "downgrade", "050", succeeds=False)
    assert "mfa" in result.stderr.lower() and "downgrade" in result.stderr.lower()
    with harness.owner_engine.connect() as conn:
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == "054"
        assert conn.execute(text("SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE relname='users'")).scalar_one()

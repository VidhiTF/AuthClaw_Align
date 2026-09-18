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
from threading import Barrier
from time import perf_counter
import tracemalloc
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from app.db.models import ApprovalAudit, ComplianceScoreSnapshot, Notification, PendingApproval, TrustCenterAccessLog, TrustCenterShare
from app.db import dependencies
from app.core.auth import get_tenant_score_db
from app.services import audit_store, compliance_scoring, control_assessments, event_backbone, evidence_service, trust_center
from app.api.v1.endpoints.trust_center import get_public_trust_center
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
        command("scripts/bootstrap_database_security.py", "finalize-backend")
        harness = IsolationHarness(owner, app, sessionmaker(bind=app, expire_on_commit=False))
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


def score(score_value, *, generated_at=None):
    return {"framework": "SOC2", "calculation_version": control_assessments.CALCULATION_VERSION,
        "score": score_value, "readiness_level": "monitor", "controls": [],
        "generated_at": (generated_at or datetime.now(timezone.utc)).isoformat(),
        "metrics": {"evidence_count": 0, "audit_event_count": 0, "open_findings": 0, "critical_findings": 0}}


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


def reviewed_assessment(harness, requester, approver=None):
    approver = approver or reviewer(harness, requester)
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
        proposal_id, source_id = proposal.id, source.id
    with harness.session_for(approver) as db:
        assessment = control_assessments.review_assessment(db, str(requester.tenant_id), str(proposal_id),
            str(approver.user_id), True, "Independent reviewer verified the source scope and successful outcomes.",
            datetime.now(timezone.utc))
        db.commit()
        assessment_id = assessment.id
    return proposal_id, source_id, assessment_id


def test_migration_preserves_legacy_rows_and_restricted_forced_rls(postgres):
    harness, _, legacy_id = postgres
    with harness.owner_engine.connect() as conn:
        row = conn.execute(text("SELECT * FROM compliance_score_snapshots WHERE id=:id"), {"id": legacy_id}).mappings().one()
        assert row["overall_score"] == 97.5
        assert row["control_scores"] == {"CC7.2": {"status": "compliant"}}
        assert row["calculation_version"] == "legacy_unversioned"
        assert row["assessment_metadata"] == {}
        assert conn.execute(text("SELECT pg_get_userbyid(relowner) FROM pg_class WHERE relname='compliance_score_snapshots'")).scalar_one() == make_url(os.environ["BACKEND_MIGRATION_DATABASE_URL"]).username
        flags = conn.execute(text("""SELECT relname,relrowsecurity,relforcerowsecurity FROM pg_class
            WHERE relname IN ('compliance_score_snapshots','approval_audit','pending_approvals','evidence_records')""")).all()
        assert len(flags) == 4 and all(row.relrowsecurity and row.relforcerowsecurity for row in flags)
    with harness.app_engine.connect() as conn:
        role = conn.execute(text("SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user")).one()
        assert not role.rolsuper and not role.rolbypassrls
        assert conn.execute(text("SELECT count(*) FROM compliance_score_snapshots")).scalar_one() == 0


def test_real_evidence_writer_and_review_qualify_with_repeatable_read(postgres):
    harness, _, _ = postgres
    tenant = harness.create_identity("t10-producer")
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
    with harness.session_for(tenant) as db:
        db.connection(execution_options={"isolation_level": "REPEATABLE READ"})
        unreviewed = compliance_scoring.score_framework(db, str(tenant.tenant_id), "SOC2", include_traceability=False)
        assert next(row for row in unreviewed["controls"] if row["id"] == "CC7.2")["status"] != "compliant"
    _, _, assessment_id = reviewed_assessment(harness, tenant)
    with harness.session_for(tenant) as db:
        db.connection(execution_options={"isolation_level": "REPEATABLE READ"})
        db.info["compliance_read_transaction"] = True
        result = compliance_scoring.score_framework(db, str(tenant.tenant_id), "SOC2", include_traceability=False)
        control = next(row for row in result["controls"] if row["id"] == "CC7.2")
        assert control["evidence_assessment"]["state"] == "qualified", control["evidence_assessment"]
        assert control["status"] == "compliant"
        assert str(assessment_id) in control["evidence_assessment"]["evidence_ids"]
        persisted = compliance_scoring.upsert_score_snapshot(db, str(tenant.tenant_id), result)
        assert persisted.calculation_version == result["calculation_version"]


def test_request_dependency_uses_single_connection_and_resets_write_isolation(postgres, monkeypatch):
    harness, _, _ = postgres
    tenant = harness.create_identity("t10-one-connection")
    pool = create_engine(harness.app_engine.url, pool_size=1, max_overflow=0, pool_timeout=2)
    monkeypatch.setattr(dependencies, "SessionLocal", sessionmaker(bind=pool, expire_on_commit=False))
    request = SimpleNamespace(state=SimpleNamespace(tenant_id=tenant.tenant_id,
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


def test_downgrade_refuses_retained_versioned_history_and_keeps_rls(postgres):
    harness, command, _ = postgres
    tenant = harness.create_identity("t10-downgrade")
    with harness.session_for(tenant) as db:
        compliance_scoring.upsert_score_snapshot(db, str(tenant.tenant_id), score(50))
    result = command("-m", "alembic", "downgrade", "049", succeeds=False)
    assert "downgrade refused" in result.stderr
    with harness.owner_engine.connect() as conn:
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == "050"
        assert conn.execute(text("SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE relname='compliance_score_snapshots'")).scalar_one()


def test_concurrent_public_score_views_rebind_and_log_each_access(postgres, monkeypatch):
    harness, _, _ = postgres
    tenant = harness.create_identity("t10-public")
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

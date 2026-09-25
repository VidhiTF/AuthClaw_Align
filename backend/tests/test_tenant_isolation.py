"""Integration tests for the signed Backend tenant boundary.

The application role cannot select a tenant by writing PostgreSQL GUCs. Test
identities are provisioned through the owner connection, then every application
transaction is authenticated with a real opaque session registered in authn.
"""

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.models import APIKey, AuditLogMetadata, EvidenceRecord, Policy, User
from app.db.session import database_auth_context
from app.api.v1.endpoints import evidence as evidence_endpoint
from app.services import evidence_service
from tests.db_safety import destructive_test_urls

_owner_engine = None
_app_engine = None
_testing_session_local = None


def _migration_head() -> str:
    config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    return ScriptDirectory.from_config(config).get_current_head()


@dataclass(frozen=True)
class Identity:
    tenant_id: UUID
    user_id: UUID
    session_hash: str
    email: str


class IsolationHarness:
    def __init__(self, owner_engine, app_engine, testing_session_local):
        self.owner_engine = owner_engine
        self.app_engine = app_engine
        self.testing_session_local = testing_session_local

    def create_identity(self, suffix: str) -> Identity:
        identity = Identity(
            tenant_id=uuid4(),
            user_id=uuid4(),
            session_hash=uuid4().hex + uuid4().hex,
            email=f"user-{suffix}-{uuid4().hex}@example.invalid",
        )
        with self.owner_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO public.tenants "
                    "(id, name, tier, status, created_at, updated_at) "
                    "VALUES (:id, :name, 'starter', 'active', now(), now())"
                ),
                {"id": identity.tenant_id, "name": f"tenant-{suffix}-{uuid4().hex}"},
            )
            conn.execute(
                text(
                    "INSERT INTO public.users "
                    "(id, tenant_id, email, role, platform_role, is_active, created_at, updated_at) "
                    "VALUES (:id, :tenant_id, :email, 'admin', 'NONE', true, now(), now())"
                ),
                {
                    "id": identity.user_id,
                    "tenant_id": identity.tenant_id,
                    "email": identity.email,
                },
            )
            conn.execute(
                text(
                    "SELECT authn.create_session("
                    ":session_hash, :tenant_id, :user_id, 'security-test', "
                    "now() + interval '10 minutes', '{}'::jsonb)"
                ),
                {
                    "session_hash": identity.session_hash,
                    "tenant_id": identity.tenant_id,
                    "user_id": identity.user_id,
                },
            )
        return identity

    @contextmanager
    def session_for(self, identity: Identity):
        with database_auth_context("session", identity.session_hash):
            db = self.testing_session_local()
            try:
                yield db
            finally:
                db.rollback()
                db.close()


def _engines():
    global _owner_engine, _app_engine, _testing_session_local
    if _owner_engine is None or _app_engine is None or _testing_session_local is None:
        owner_db_url, app_db_url = destructive_test_urls()
        _owner_engine = create_engine(owner_db_url, echo=False, poolclass=StaticPool)
        _app_engine = create_engine(app_db_url, echo=False, poolclass=StaticPool)
        _testing_session_local = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=_app_engine,
            expire_on_commit=False,
        )
    return _owner_engine, _app_engine, _testing_session_local


@pytest.fixture(scope="module", autouse=True)
def dispose_test_engines():
    yield
    if _owner_engine is not None:
        _owner_engine.dispose()
    if _app_engine is not None:
        _app_engine.dispose()


@pytest.fixture
def isolation() -> IsolationHarness:
    owner_engine, app_engine, testing_session_local = _engines()
    with owner_engine.begin() as conn:
        revision = conn.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one()
        expected_revision = _migration_head()
        if revision != expected_revision:
            pytest.fail(
                "tenant isolation tests require migration head "
                f"{expected_revision!r}, found {revision!r}"
            )
        conn.execute(text("TRUNCATE TABLE public.tenants CASCADE"))
    return IsolationHarness(owner_engine, app_engine, testing_session_local)


def test_missing_or_forged_context_reads_nothing(isolation: IsolationHarness):
    tenant_a = isolation.create_identity("a")
    tenant_b = isolation.create_identity("b")

    with isolation.app_engine.begin() as conn:
        assert conn.execute(text("SELECT count(*) FROM public.users")).scalar_one() == 0
        conn.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, true)"),
            {"tenant_id": str(tenant_b.tenant_id)},
        )
        assert conn.execute(text("SELECT count(*) FROM public.users")).scalar_one() == 0

    with isolation.session_for(tenant_a) as db:
        assert (
            db.query(User).filter(User.tenant_id == tenant_b.tenant_id).first() is None
        )


def test_ent026_rls_catalog_and_direct_role_denials(isolation: IsolationHarness):
    """Exercise migrated policies through signed sessions and the restricted DB role."""
    administrator = isolation.create_identity("ent026-administrator")
    tenant_id = administrator.tenant_id
    identities = {"tenant_administrator": administrator}
    with isolation.owner_engine.begin() as conn:
        for role in ("viewer", "developer", "operator", "auditor", "approver"):
            identity = Identity(tenant_id, uuid4(), uuid4().hex + uuid4().hex,
                f"ent026-{role}-{uuid4().hex}@example.invalid")
            conn.execute(text("""INSERT INTO public.users
                (id, tenant_id, email, role, platform_role, is_active, created_at, updated_at)
                VALUES (:id, :tenant, :email, :role, 'NONE', true, now(), now())"""),
                {"id": identity.user_id, "tenant": tenant_id, "email": identity.email, "role": role})
            conn.execute(text("""SELECT authn.create_session(
                :hash, :tenant, :user_id, 'ent026-rls-test',
                now() + interval '10 minutes', '{}'::jsonb)"""),
                {"hash": identity.session_hash, "tenant": tenant_id, "user_id": identity.user_id})
            identities[role] = identity
        approval_id, self_approval_id = uuid4(), uuid4()
        conn.execute(text("""INSERT INTO public.policies
            (id, tenant_id, name, policy_yaml, version, created_by, created_at, updated_at)
            VALUES (:id, :tenant, 'ent026-test', 'rules: []', 1, :user_id, now(), now())"""),
            {"id": uuid4(), "tenant": tenant_id, "user_id": administrator.user_id})
        conn.execute(text("""INSERT INTO public.gateway_configs (id, tenant_id, name, provider,
            endpoint, redaction_strategy, redaction_token_retention_days, created_at, updated_at)
            VALUES (:id, :tenant, 'ent026-test', 'openai', 'https://example.invalid',
                    'mask', 90, now(), now())"""),
            {"id": uuid4(), "tenant": tenant_id})
        conn.execute(text("""INSERT INTO public.provider_credentials (id, tenant_id, provider,
            display_name, encrypted_secret, created_by, created_at)
            VALUES (:id, :tenant, 'openai', 'ent026-test', 'encrypted-test-value', :user_id, now())"""),
            {"id": uuid4(), "tenant": tenant_id, "user_id": administrator.user_id})
        conn.execute(text("""INSERT INTO public.api_keys (id, tenant_id, key_hash, name, scopes,
            expires_at, created_by, created_at, updated_at)
            VALUES (:id, :tenant, :hash, 'ent026-test', ARRAY['read'],
                    now() + interval '1 day', :user_id, now(), now())"""),
            {"id": uuid4(), "tenant": tenant_id, "hash": uuid4().hex,
             "user_id": administrator.user_id})
        for row_id, requester_id in ((approval_id, administrator.user_id),
                                     (self_approval_id, identities["approver"].user_id)):
            conn.execute(text("""INSERT INTO public.pending_approvals
                (id, tenant_id, action_id, action_type, action_description, action_payload,
                 status, requester_id, expires_at, created_at, updated_at)
                VALUES (:id, :tenant, :action_id, 'remediation', 'ent026-test', '{}'::json,
                        'PENDING', :requester, now() + interval '30 minutes', now(), now())"""),
                {"id": row_id, "tenant": tenant_id, "action_id": str(row_id),
                 "requester": requester_id})
        conn.execute(text("""INSERT INTO public.data_subject_requests
            (id, tenant_id, subject_id, requester_id, request_type, status,
             identity_verified, scope, created_at, updated_at)
            VALUES (:id, :tenant, 'ent026-subject', :requester, 'ACCESS',
                    'PENDING', false, '{}'::json, now(), now())"""),
            {"id": uuid4(), "tenant": tenant_id, "requester": administrator.user_id})

        expected_policies = {
            "api_keys": {"tenant_isolation", "tenant_admin_api_keys_write", "tenant_access_review_api_keys_read"},
            "users": {"tenant_user_read", "tenant_user_insert", "tenant_user_update", "tenant_user_delete"},
            "policies": {"tenant_policy_read", "tenant_policy_write", "tenant_policy_update", "tenant_policy_delete"},
            "gateway_configs": {"tenant_gateway_read", "tenant_gateway_write", "tenant_gateway_update", "tenant_gateway_delete"},
            "provider_credentials": {"tenant_provider_read", "tenant_provider_write", "tenant_provider_update", "tenant_provider_delete"},
            "pending_approvals": {"tenant_approval_read", "tenant_approval_create", "tenant_approval_resolve", "tenant_approval_expire"},
            "data_subject_requests": {"data_subject_requests_read", "data_subject_requests_create", "data_subject_requests_update"},
            "audit_log_metadata": {"tenant_audit_read", "tenant_audit_append"},
        }
        rows = conn.execute(text("""SELECT p.tablename, p.policyname FROM pg_policies p
            WHERE p.schemaname = 'public' AND p.tablename = ANY(:tables)
              AND EXISTS (SELECT 1 FROM unnest(p.roles) AS policy_role(role_name)
                  WHERE CASE WHEN role_name = 'public' THEN true ELSE
                      pg_has_role(CAST(:app_role AS name), CAST(role_name AS name), 'member') END)"""),
            {"tables": list(expected_policies), "app_role": isolation.app_engine.url.username}).all()
        for table, names in expected_policies.items():
            assert {row.policyname for row in rows if row.tablename == table} == names
    read_tables = {
        "policies": {"tenant_administrator"},
        "gateway_configs": {"tenant_administrator"},
        "provider_credentials": {"tenant_administrator"},
        "api_keys": {"tenant_administrator", "auditor"},
        "pending_approvals": set(identities),
        "data_subject_requests": {"tenant_administrator", "auditor", "approver", "operator"},
    }
    for role, identity in identities.items():
        with isolation.session_for(identity) as db:
            assert db.execute(text("SELECT authn.current_role() ")).scalar_one() == role
            for table, allowed_roles in read_tables.items():
                count = db.execute(text(f"SELECT count(*) FROM public.{table} WHERE tenant_id = :tenant"),
                    {"tenant": tenant_id}).scalar_one()
                expected = (2 if table == "pending_approvals" else 1) if role in allowed_roles else 0
                assert count == expected, (role, table, count, expected)

    update_approval = text("""UPDATE public.pending_approvals
        SET status = 'APPROVED', approver_id = :actor, approved_at = now()
        WHERE id = :id RETURNING id""")
    for role in ("viewer", "developer", "operator", "auditor", "tenant_administrator"):
        with isolation.session_for(identities[role]) as db:
            assert db.execute(update_approval,
                {"actor": identities[role].user_id, "id": approval_id}).first() is None
    with isolation.session_for(identities["approver"]) as db:
        assert db.execute(update_approval,
            {"actor": identities["approver"].user_id, "id": self_approval_id}).first() is None
        assert db.execute(update_approval,
            {"actor": identities["approver"].user_id, "id": approval_id}).scalar_one() == approval_id
        db.commit()
    with isolation.owner_engine.connect() as conn:
        assert dict(tuple(row) for row in conn.execute(
            text("SELECT id, status FROM public.pending_approvals"))) == {
            approval_id: "APPROVED", self_approval_id: "PENDING"}


def test_writer_privileges_cannot_bypass_restricted_audit_verifier(
    isolation: IsolationHarness,
):
    tenant = isolation.create_identity("audit-verifier")
    record_id = uuid4()
    canonical_payload = '{"trusted":true}'
    integrity_hash = "a" * 64
    with isolation.session_for(tenant) as db:
        db.add(
            AuditLogMetadata(
                tenant_id=tenant.tenant_id,
                record_id=record_id,
                tenant_sequence=1,
                idempotency_key=f"audit-verifier-{record_id}",
                canonical_payload=canonical_payload,
                action="audit.verify",
                prior_hash="GENESIS",
                integrity_hash=integrity_hash,
            )
        )
        db.commit()

    with isolation.owner_engine.connect() as connection:
        assert (
            connection.execute(
                text(
                    "SELECT has_function_privilege('authclaw_audit_verifier', "
                    "'public.verify_audit_origin(uuid,uuid,text,text,text)', 'EXECUTE')"
                )
            ).scalar_one()
            is True
        )

    with pytest.raises(DBAPIError):
        with isolation.app_engine.begin() as connection:
            connection.execute(
                text("SELECT set_config('app.current_tenant_id', :tenant, true)"),
                {"tenant": str(tenant.tenant_id)},
            )
            assert (
                connection.execute(
                    text("SELECT count(*) FROM public.audit_log_metadata")
                ).scalar_one()
                == 0
            )
            connection.execute(
                text(
                    "SELECT public.verify_audit_origin("
                    ":tenant, :record, :payload, 'GENESIS', :integrity)"
                ),
                {
                    "tenant": tenant.tenant_id,
                    "record": record_id,
                    "payload": canonical_payload,
                    "integrity": integrity_hash,
                },
            )


def test_authenticated_sessions_only_read_their_own_tenant(isolation: IsolationHarness):
    tenant_a = isolation.create_identity("a")
    tenant_b = isolation.create_identity("b")

    with isolation.session_for(tenant_a) as db:
        users = db.query(User).all()
        assert [(user.tenant_id, user.email) for user in users] == [
            (tenant_a.tenant_id, tenant_a.email)
        ]

    with isolation.session_for(tenant_b) as db:
        users = db.query(User).all()
        assert [(user.tenant_id, user.email) for user in users] == [
            (tenant_b.tenant_id, tenant_b.email)
        ]


def test_authenticated_tenant_cannot_resolve_another_tenants_evidence(
    isolation: IsolationHarness,
):
    tenant_a = isolation.create_identity("evidence-a")
    tenant_b = isolation.create_identity("evidence-b")
    storage = {
        "storage": {
            "bucket": "evidence-test-bucket",
            "object_key": f"tenant-{tenant_a.tenant_id}/report.json",
            "sha256": "a" * 64,
            "retention_class": "seven_years",
            "access_policy": {"allow_download": True},
        }
    }

    with isolation.session_for(tenant_a) as db:
        record = evidence_service.create_evidence(
            db,
            tenant_id=str(tenant_a.tenant_id),
            workflow_id=None,
            framework="SOC2",
            source_type="s3_document",
            source_reference=storage["storage"]["object_key"],
            evidence_type="scan_result",
            evidence_data=storage,
        )
        record_id = str(record.id)

    with isolation.session_for(tenant_a) as db:
        resolved = evidence_service.get_evidence(
            db, tenant_id=str(tenant_a.tenant_id), evidence_id=record_id
        )
        assert resolved is not None
        request = SimpleNamespace(
            state=SimpleNamespace(
                tenant_id=tenant_a.tenant_id,
                user_id=tenant_a.user_id,
            ),
            headers={"x-request-id": "evidence-access-audit-test"},
        )
        db.info["authclaw_database_auth_context"] = (
            "session",
            tenant_a.session_hash,
        )
        evidence_endpoint._audit_access(resolved, request, "download", db)
        audit = (
            db.query(AuditLogMetadata)
            .filter(
                AuditLogMetadata.action == "evidence:download",
                AuditLogMetadata.record_id.isnot(None),
            )
            .one()
        )
        assert audit.actor_id == tenant_a.user_id
        assert "purpose=download" in audit.execution_trace

    with isolation.session_for(tenant_b) as db:
        assert (
            evidence_service.get_evidence(
                db, tenant_id=str(tenant_b.tenant_id), evidence_id=record_id
            )
            is None
        )
        # Prove RLS independently of the service's tenant filter.
        assert db.get(EvidenceRecord, UUID(record_id)) is None
        assert (
            evidence_service.get_evidence(
                db, tenant_id=str(tenant_a.tenant_id), evidence_id=record_id
            )
            is None
        )


def test_request_credential_rebinds_audit_after_commit_without_contextvar(isolation):
    tenant = isolation.create_identity("audit-rebind")
    with isolation.testing_session_local() as db:
        db.info["authclaw_database_auth_context"] = ("session", tenant.session_hash)
        record = SimpleNamespace(
            id=uuid4(), tenant_id=tenant.tenant_id, framework="SOC2"
        )
        request = SimpleNamespace(
            state=SimpleNamespace(user_id=tenant.user_id),
            headers={"x-request-id": "repeated"},
        )
        for operation in ("view", "download", "export", "delete", "download"):
            evidence_endpoint._audit_access(record, request, operation, db)
        rows = (
            db.query(AuditLogMetadata).order_by(AuditLogMetadata.tenant_sequence).all()
        )
        assert [row.action for row in rows] == [
            "evidence:view",
            "evidence:download",
            "evidence:export",
            "evidence:delete",
            "evidence:download",
        ]
        assert all(
            row.actor_id == tenant.user_id
            and row.tenant_id == tenant.tenant_id
            and f"purpose={row.action.split(':')[1]}" in row.execution_trace
            for row in rows
        )


def test_audit_context_migration_upgrades_existing_function(isolation, monkeypatch):
    config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    scripts = ScriptDirectory.from_config(config)
    migration = scripts.get_revision("049").module
    with isolation.owner_engine.begin() as conn:
        conn.execute(text(scripts.get_revision("028").module.APPEND_FUNCTION))
        monkeypatch.setattr(
            migration.op, "execute", lambda statement: conn.execute(text(statement))
        )
        migration.upgrade()
        definition = conn.execute(
            text(
                "SELECT pg_get_functiondef(oid) FROM pg_proc WHERE proname='append_audit_event_v2'"
            )
        ).scalar_one()
        assert "authn.current_tenant_id()" in definition
        assert "app.current_tenant_id" not in definition


def test_cross_tenant_user_insert_is_rejected(isolation: IsolationHarness):
    tenant_a = isolation.create_identity("a")
    tenant_b = isolation.create_identity("b")
    attempted_user_id = uuid4()

    with isolation.session_for(tenant_a) as db:
        db.add(
            User(
                id=attempted_user_id,
                tenant_id=tenant_b.tenant_id,
                email="wrong-tenant@example.invalid",
                role="viewer",
            )
        )
        with pytest.raises(DBAPIError):
            db.flush()

    with isolation.session_for(tenant_b) as db:
        assert db.get(User, attempted_user_id) is None


def test_api_keys_are_isolated_by_authenticated_session(isolation: IsolationHarness):
    tenant_a = isolation.create_identity("a")
    tenant_b = isolation.create_identity("b")

    for identity, name in ((tenant_a, "key-a"), (tenant_b, "key-b")):
        with isolation.session_for(identity) as db:
            db.add(
                APIKey(
                    id=uuid4(),
                    tenant_id=identity.tenant_id,
                    key_hash=f"hash-{uuid4().hex}",
                    name=name,
                    scopes=["read"],
                    expires_at=datetime.now(timezone.utc) + timedelta(days=1),
                    created_by=identity.user_id,
                )
            )
            db.commit()

    with isolation.session_for(tenant_a) as db:
        keys = db.query(APIKey).all()
        assert [(key.tenant_id, key.name) for key in keys] == [
            (tenant_a.tenant_id, "key-a")
        ]


def test_policies_are_isolated_by_authenticated_session(isolation: IsolationHarness):
    tenant_a = isolation.create_identity("a")
    tenant_b = isolation.create_identity("b")

    for identity, name in ((tenant_a, "policy-a"), (tenant_b, "policy-b")):
        with isolation.session_for(identity) as db:
            db.add(
                Policy(
                    id=uuid4(),
                    tenant_id=identity.tenant_id,
                    name=name,
                    policy_yaml="version: 1\nrules: []",
                    created_by=identity.user_id,
                )
            )
            db.commit()

    with isolation.session_for(tenant_b) as db:
        policies = db.query(Policy).all()
        assert [(policy.tenant_id, policy.name) for policy in policies] == [
            (tenant_b.tenant_id, "policy-b")
        ]


@pytest.mark.parametrize(
    ("table_name", "seed_sql", "insert_sql"),
    (
        (
            "compliance_workflows",
            "INSERT INTO public.compliance_workflows "
            "(id, tenant_id, workflow_id, framework) VALUES (:id, :tenant_id, CAST(:id AS text), 'HIPAA')",
            "INSERT INTO public.compliance_workflows "
            "(id, tenant_id, workflow_id, framework) VALUES (:attempt_id, :tenant_id, CAST(:attempt_id AS text), 'HIPAA')",
        ),
        (
            "aws_usage_limits",
            "INSERT INTO public.aws_usage_limits (id, tenant_id) VALUES (:id, :tenant_id)",
            "INSERT INTO public.aws_usage_limits (id, tenant_id) VALUES (:attempt_id, :tenant_id)",
        ),
        (
            "aws_s3_documents",
            "INSERT INTO public.aws_s3_documents "
            "(id, tenant_id, bucket_name, object_key, file_name) "
            "VALUES (:id, :tenant_id, 'isolation', 'seed.txt', 'seed.txt')",
            "INSERT INTO public.aws_s3_documents "
            "(id, tenant_id, bucket_name, object_key, file_name) "
            "VALUES (:attempt_id, :tenant_id, 'isolation', 'blocked.txt', 'blocked.txt')",
        ),
    ),
    ids=("compliance-workflows", "aws-usage-limits", "aws-s3-documents"),
)
def test_p0_resource_cross_tenant_crud_is_denied(
    isolation: IsolationHarness,
    table_name: str,
    seed_sql: str,
    insert_sql: str,
):
    tenant_a = isolation.create_identity("a")
    tenant_b = isolation.create_identity("b")
    record_id = uuid4()

    with isolation.owner_engine.begin() as conn:
        conn.execute(
            text(seed_sql),
            {"id": record_id, "tenant_id": tenant_b.tenant_id},
        )

    with isolation.session_for(tenant_a) as db:
        assert (
            db.execute(
                text(f"SELECT count(*) FROM public.{table_name} WHERE id = :id"),
                {"id": record_id},
            ).scalar_one()
            == 0
        )

        with pytest.raises(DBAPIError):
            db.execute(
                text(insert_sql),
                {"attempt_id": uuid4(), "tenant_id": tenant_b.tenant_id},
            )
        db.rollback()

    with isolation.session_for(tenant_a) as db:
        updated = db.execute(
            text(
                f"UPDATE public.{table_name} SET tenant_id = :tenant_id WHERE id = :id"
            ),
            {"tenant_id": tenant_a.tenant_id, "id": record_id},
        )
        deleted = db.execute(
            text(f"DELETE FROM public.{table_name} WHERE id = :id"),
            {"id": record_id},
        )
        assert (updated.rowcount, deleted.rowcount) == (0, 0)


def test_workflow_response_routes_respect_authenticated_postgres_boundary(isolation):
    from fastapi import HTTPException
    from starlette.requests import Request
    from app.api.v1.endpoints import workflows
    from app.db.models import ComplianceWorkflow
    from sqlalchemy.orm import Session

    tenant_a, tenant_b = isolation.create_identity("workflow-a"), isolation.create_identity("workflow-b")
    own_id, other_id = str(uuid4()), str(uuid4())
    with Session(isolation.owner_engine) as db:
        for identity, workflow_id in ((tenant_a, own_id), (tenant_b, other_id)):
            db.add(ComplianceWorkflow(id=uuid4(), tenant_id=identity.tenant_id, workflow_id=workflow_id,
                                     framework="HIPAA", current_state="COMPLETE", execution_status="COMPLETED",
                                     findings=[{"control": "private-document", "entity_count": 0}],
                                     remediation_plan=[], execution_result={}, state_data={"rollback_result": {}}))
        db.commit()
    request = Request({"type": "http", "headers": []})
    request.state.tenant_id, request.state.user_id = tenant_a.tenant_id, tenant_a.user_id
    with isolation.session_for(tenant_a) as db:
        assert db.execute(text("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user")).scalar_one() is False
        assert db.execute(text("SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid = 'compliance_workflows'::regclass")).scalar_one() is True
        assert [row.workflow_id for row in db.query(ComplianceWorkflow).all()] == [own_id]
        result = workflows.list_workflows(request, db)
        assert [row.workflow_id for row in result] == [own_id]
        assert result[0].model_dump()["findings"] == [{"control": "private-document", "entity_count": 0}]
    for operation in (workflows.get_workflow, workflows.resume_workflow, workflows.approve_workflow,
                      workflows.reject_workflow, workflows.remediate_workflow):
        with isolation.session_for(tenant_a) as db, pytest.raises(HTTPException) as exc:
            operation(workflow_id=other_id, request=request, db=db)
        assert exc.value.status_code == 404

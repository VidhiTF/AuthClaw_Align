"""Integration tests for the signed Backend tenant boundary.

The application role cannot select a tenant by writing PostgreSQL GUCs. Test
identities are provisioned through the owner connection, then every application
transaction is authenticated with a real opaque session registered in authn.
"""

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.models import APIKey, Policy, User
from app.db.session import database_auth_context
from tests.db_safety import destructive_test_urls


_owner_engine = None
_app_engine = None
_testing_session_local = None


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
        revision = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        if revision != "041":
            pytest.fail(f"tenant isolation tests require migration 041, found {revision!r}")
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
        assert db.query(User).filter(User.tenant_id == tenant_b.tenant_id).first() is None


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
        assert [(key.tenant_id, key.name) for key in keys] == [(tenant_a.tenant_id, "key-a")]


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
    ids=("aws-usage-limits", "aws-s3-documents"),
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
        assert db.execute(
            text(f"SELECT count(*) FROM public.{table_name} WHERE id = :id"),
            {"id": record_id},
        ).scalar_one() == 0

        with pytest.raises(DBAPIError):
            db.execute(
                text(insert_sql),
                {"attempt_id": uuid4(), "tenant_id": tenant_b.tenant_id},
            )
        db.rollback()

    with isolation.session_for(tenant_a) as db:
        updated = db.execute(
            text(f"UPDATE public.{table_name} SET tenant_id = :tenant_id WHERE id = :id"),
            {"tenant_id": tenant_a.tenant_id, "id": record_id},
        )
        deleted = db.execute(
            text(f"DELETE FROM public.{table_name} WHERE id = :id"),
            {"id": record_id},
        )
        assert (updated.rowcount, deleted.rowcount) == (0, 0)

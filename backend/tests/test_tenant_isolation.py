"""
Tests for Cross-Tenant Isolation
Verifies that RLS policies enforce strict multi-tenant data separation
"""
import pytest
import os
from datetime import datetime, timedelta, timezone
from sqlalchemy import text, create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import DBAPIError
from sqlalchemy.pool import StaticPool
from uuid import uuid4

from app.db.models import (
    APIKey,
    ApprovalAudit,
    AWSS3Document,
    AWSUsageLimits,
    PendingApproval,
    Policy,
    Tenant,
    User,
)
from tests.db_safety import destructive_test_urls

_owner_engine = None
_app_engine = None
_TestingSessionLocal = None


def _engines():
    global _owner_engine, _app_engine, _TestingSessionLocal
    if _owner_engine is None or _app_engine is None or _TestingSessionLocal is None:
        owner_db_url, db_url = destructive_test_urls()
        _owner_engine = create_engine(owner_db_url, echo=False, poolclass=StaticPool)
        _app_engine = create_engine(db_url, echo=False, poolclass=StaticPool)
        _TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_app_engine, expire_on_commit=False)
    return _owner_engine, _app_engine, _TestingSessionLocal


@pytest.fixture(scope="module", autouse=True)
def dispose_test_engines():
    yield
    if _owner_engine is not None:
        _owner_engine.dispose()
    if _app_engine is not None:
        _app_engine.dispose()


@pytest.fixture
def test_db():
    """Create a test database session with clean tables"""
    owner_engine, _, TestingSessionLocal = _engines()
    
    # Schema setup needs owner rights; assertions below run through the restricted app role.
    from app.db.base import Base
    Base.metadata.create_all(bind=owner_engine)
    
    # Truncate tables before test runs
    with owner_engine.connect() as conn:
        conn.execute(text("TRUNCATE TABLE audit_log_metadata, pending_approvals, redaction_tokens, gateway_configs, policies, api_keys, users, tenants CASCADE;"))
        conn.commit()
        
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.rollback()
        db.close()


def create_tenant(db: Session, name: str) -> Tenant:
    """Helper to create a tenant with correct context to allow RETURNING clause in RLS"""
    tenant_id = uuid4()
    db.execute(text(f"SET app.current_tenant_id = '{tenant_id}'"))
    tenant = Tenant(id=tenant_id, name=name, tier="starter")
    db.add(tenant)
    db.commit()
    return tenant


def test_tenant_isolation_read(test_db: Session):
    """
    Test: User from Tenant A cannot read data from Tenant B
    This verifies RLS policy is working
    """
    # Create two test tenants
    tenant_a = create_tenant(test_db, "tenant-a")
    tenant_b = create_tenant(test_db, "tenant-b")
    
    tenant_a_id = tenant_a.id
    tenant_b_id = tenant_b.id

    # Set context to Tenant A and create a user
    test_db.execute(text(f"SET app.current_tenant_id = '{tenant_a_id}'"))
    user_a = User(
        id=uuid4(),
        tenant_id=tenant_a_id,
        email="user-a@tenant-a.com",
        role="admin"
    )
    test_db.add(user_a)
    test_db.commit()
    
    # Set context to Tenant B and create a user
    test_db.execute(text(f"SET app.current_tenant_id = '{tenant_b_id}'"))
    user_b = User(
        id=uuid4(),
        tenant_id=tenant_b_id,
        email="user-b@tenant-b.com",
        role="admin"
    )
    test_db.add(user_b)
    test_db.commit()
    
    # Set context to Tenant A
    test_db.execute(text(f"SET app.current_tenant_id = '{tenant_a_id}'"))
    test_db.expire_all()
    
    # Query users: should only see Tenant A's users
    users_in_context = test_db.query(User).all()
    
    # Verify only Tenant A users are returned
    assert len(users_in_context) == 1
    assert users_in_context[0].tenant_id == tenant_a_id
    assert users_in_context[0].email == "user-a@tenant-a.com"
    
    # Verify cannot access Tenant B users
    tenant_b_user_ids = [u.id for u in users_in_context if u.tenant_id == tenant_b_id]
    assert len(tenant_b_user_ids) == 0


def test_tenant_isolation_insert_with_wrong_tenant(test_db: Session):
    """
    Test: Cannot insert data with mismatched tenant_id when RLS is enforced
    """
    tenant_a = create_tenant(test_db, "tenant-a")
    tenant_b = create_tenant(test_db, "tenant-b")
    
    # Set context to Tenant A
    test_db.execute(text(f"SET app.current_tenant_id = '{tenant_a.id}'"))
    
    # Try to create a user that belongs to Tenant B
    # (This should fail with RLS policy)
    user_wrong_tenant = User(
        id=uuid4(),
        tenant_id=tenant_b.id,  # <-- Wrong tenant!
        email="wrong-tenant@example.com",
        role="viewer"
    )
    
    test_db.add(user_wrong_tenant)
    
    # Depending on RLS configuration, this may raise an error or silently fail
    # In production with strict RLS, this should raise InsufficientPrivilegeError
    # For this test, we document the expected behavior
    try:
        test_db.commit()
        # If no error, verify the user wasn't actually created in the wrong tenant
        # by switching context to Tenant B
        test_db.execute(text(f"SET app.current_tenant_id = '{tenant_b.id}'"))
        users_in_b = test_db.query(User).all()
        # Should not contain the user we tried to create
        assert user_wrong_tenant.id not in [u.id for u in users_in_b]
    except DBAPIError as e:
        # Expected: RLS prevents the insert
        assert "privilege" in str(e).lower() or "insufficient" in str(e).lower()
        test_db.rollback()


def test_tenant_isolation_api_keys(test_db: Session):
    """
    Test: API keys are isolated between tenants
    """
    tenant_a = create_tenant(test_db, "tenant-a")
    tenant_b = create_tenant(test_db, "tenant-b")
    
    # Set context to Tenant A and create user & key
    test_db.execute(text(f"SET app.current_tenant_id = '{tenant_a.id}'"))
    user_a = User(id=uuid4(), tenant_id=tenant_a.id, email="user-a@tenant-a.com", role="admin")
    test_db.add(user_a)
    test_db.flush()
    key_a = APIKey(
        id=uuid4(),
        tenant_id=tenant_a.id,
        key_hash="hash-a-123",
        name="key-a",
        created_by=user_a.id
    )
    test_db.add(key_a)
    test_db.commit()
    
    # Set context to Tenant B and create user & key
    test_db.execute(text(f"SET app.current_tenant_id = '{tenant_b.id}'"))
    user_b = User(id=uuid4(), tenant_id=tenant_b.id, email="user-b@tenant-b.com", role="admin")
    test_db.add(user_b)
    test_db.flush()
    key_b = APIKey(
        id=uuid4(),
        tenant_id=tenant_b.id,
        key_hash="hash-b-456",
        name="key-b",
        created_by=user_b.id
    )
    test_db.add(key_b)
    test_db.commit()
    
    # Set context to Tenant A and query
    test_db.execute(text(f"SET app.current_tenant_id = '{tenant_a.id}'"))
    test_db.expire_all()
    keys_in_a = test_db.query(APIKey).all()
    
    # Should only see Tenant A's keys
    assert len(keys_in_a) == 1
    assert keys_in_a[0].tenant_id == tenant_a.id
    assert keys_in_a[0].name == "key-a"


def test_cross_tenant_query_isolation(test_db: Session):
    """
    Test: Verify that querying without setting context returns no results
    (or returns only appropriate data)
    """
    tenant_a = create_tenant(test_db, "tenant-a")
    
    test_db.execute(text(f"SET app.current_tenant_id = '{tenant_a.id}'"))
    user_a = User(
        id=uuid4(),
        tenant_id=tenant_a.id,
        email="user-a@tenant-a.com",
        role="admin"
    )
    test_db.add(user_a)
    test_db.commit()
    
    # Query without setting context
    # With RLS enabled, this should either:
    # 1. Return no results (strict RLS)
    # 2. Raise an error (if context is required)
    # 3. Return public data only
    
    # For this implementation, we expect the context to be set by middleware
    # So querying without it should return empty or raise error
    test_db.execute(text("RESET app.current_tenant_id"))
    test_db.expire_all()
    users = test_db.query(User).all()
    
    # RLS should prevent access
    assert len(users) == 0


def test_tenant_isolation_policies(test_db: Session):
    """
    Test: Policies are isolated between tenants
    """
    tenant_a = create_tenant(test_db, "tenant-a")
    tenant_b = create_tenant(test_db, "tenant-b")
    
    # Set context to Tenant A and create user & policy
    test_db.execute(text(f"SET app.current_tenant_id = '{tenant_a.id}'"))
    user_a = User(id=uuid4(), tenant_id=tenant_a.id, email="user-a@tenant-a.com", role="admin")
    test_db.add(user_a)
    test_db.flush()
    policy_a = Policy(
        id=uuid4(),
        tenant_id=tenant_a.id,
        name="policy-a",
        policy_yaml="version: 1\nrules: []",
        created_by=user_a.id
    )
    test_db.add(policy_a)
    test_db.commit()
    
    # Set context to Tenant B and create user & policy
    test_db.execute(text(f"SET app.current_tenant_id = '{tenant_b.id}'"))
    user_b = User(id=uuid4(), tenant_id=tenant_b.id, email="user-b@tenant-b.com", role="admin")
    test_db.add(user_b)
    test_db.flush()
    policy_b = Policy(
        id=uuid4(),
        tenant_id=tenant_b.id,
        name="policy-b",
        policy_yaml="version: 1\nrules: []",
        created_by=user_b.id
    )
    test_db.add(policy_b)
    test_db.commit()
    
    # Set context to Tenant B and query
    test_db.execute(text(f"SET app.current_tenant_id = '{tenant_b.id}'"))
    test_db.expire_all()
    policies_in_b = test_db.query(Policy).all()
    
    # Should only see Tenant B's policies
    assert len(policies_in_b) == 1
    assert policies_in_b[0].tenant_id == tenant_b.id
    assert policies_in_b[0].name == "policy-b"


@pytest.mark.parametrize(
    "model",
    (ApprovalAudit, AWSUsageLimits, AWSS3Document),
    ids=("approval-audit", "aws-usage-limits", "aws-s3-documents"),
)
def test_p0_resource_cross_tenant_crud_is_denied(test_db: Session, model):
    tenant_a = create_tenant(test_db, "tenant-a")
    tenant_b = create_tenant(test_db, "tenant-b")
    tenant_c = create_tenant(test_db, "tenant-c")
    tenant_a_id = tenant_a.id

    if model is ApprovalAudit:
        approvals = []
        users = []
        for tenant, suffix in ((tenant_b, "b"), (tenant_c, "c")):
            test_db.execute(text(f"SET app.current_tenant_id = '{tenant.id}'"))
            user = User(
                id=uuid4(), tenant_id=tenant.id, email=f"user-{suffix}@example.com", role="admin"
            )
            test_db.add(user)
            test_db.flush()
            approval = PendingApproval(
                id=uuid4(),
                tenant_id=tenant.id,
                action_id=f"action-{suffix}",
                action_type="remediation",
                action_description="Tenant isolation test",
                action_payload={},
                requester_id=user.id,
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
            )
            test_db.add(approval)
            test_db.commit()
            users.append(user)
            approvals.append(approval)
        records = [
            ApprovalAudit(
                id=uuid4(),
                tenant_id=tenant.id,
                approval_id=approval.id,
                actor_id=user.id,
                action="APPROVED",
            )
            for tenant, approval, user in zip((tenant_b, tenant_c), approvals, users)
        ]
    elif model is AWSUsageLimits:
        records = [AWSUsageLimits(id=uuid4(), tenant_id=tenant.id) for tenant in (tenant_b, tenant_c)]
    else:
        records = [
            AWSS3Document(
                id=uuid4(),
                tenant_id=tenant.id,
                bucket_name="tenant-isolation",
                object_key=f"{suffix}/document.txt",
                file_name="document.txt",
            )
            for tenant, suffix in ((tenant_b, "b"), (tenant_c, "c"))
        ]

    tenant_b_record, wrong_tenant_record = records
    test_db.execute(text(f"SET app.current_tenant_id = '{tenant_b.id}'"))
    test_db.add(tenant_b_record)
    test_db.commit()
    tenant_b_record_id = tenant_b_record.id

    test_db.execute(text(f"SET app.current_tenant_id = '{tenant_a_id}'"))
    test_db.expire_all()
    read_denied = test_db.query(model).filter(model.id == tenant_b_record_id).first() is None

    test_db.add(wrong_tenant_record)
    try:
        test_db.flush()
        create_denied = False
    except DBAPIError:
        create_denied = True
    test_db.rollback()

    test_db.execute(text(f"SET app.current_tenant_id = '{tenant_a_id}'"))
    updated = test_db.execute(
        text(f"UPDATE {model.__tablename__} SET tenant_id = :tenant_id WHERE id = :id"),
        {"tenant_id": tenant_a_id, "id": tenant_b_record_id},
    )

    deleted = test_db.execute(
        text(f"DELETE FROM {model.__tablename__} WHERE id = :id"),
        {"id": tenant_b_record_id},
    )
    assert (read_denied, create_denied, updated.rowcount, deleted.rowcount) == (True, True, 0, 0)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

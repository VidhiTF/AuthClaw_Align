import pytest
from fastapi.testclient import TestClient
from fastapi import status
from sqlalchemy import text, create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker, Session
import uuid
from uuid import uuid4, UUID
import os
import base64
import pyotp
from datetime import datetime, timedelta, timezone
from main import app

# Force fallback to PostgreSQL audit logs by unsetting CLICKHOUSE_HOST for endpoints test suite
os.environ.pop("CLICKHOUSE_HOST", None)

from app.db.dependencies import get_db
from app.db.models import AccessRequest, AccessRequestHistory, DataSubjectRequest, Notification, Tenant, User, APIKey, Policy, GatewayConfig, RedactionToken, AuditLogMetadata
from app.core.auth import hash_key
from app.services import access_requests as access_request_service
from app.services.privacy_lifecycle import purge_expired_access_requests
from app.services import data_subject_requests as data_subject_request_service
from app.services import event_backbone
from tests.db_safety import destructive_test_urls

owner_db_url, db_url = destructive_test_urls()
owner_engine = create_engine(owner_db_url, echo=False, poolclass=StaticPool)
engine = create_engine(db_url, echo=False, poolclass=StaticPool)
OwnerTestingSessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=owner_engine, expire_on_commit=False
)
AppTestingSessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=engine, expire_on_commit=False
)


@pytest.fixture(scope="module")
def db_session() -> Session:
    """Create a clean database session and apply tables/RLS contexts"""
    from app.db.base import Base
    Base.metadata.create_all(bind=owner_engine)

    app_role = owner_engine.dialect.identifier_preparer.quote(
        os.getenv("POSTGRES_APP_USER", "authclaw_app")
    )
    # Truncate tables before run
    with owner_engine.connect() as conn:
        conn.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON access_requests TO {app_role}"))
        conn.execute(text(f"GRANT SELECT, INSERT ON access_request_history TO {app_role}"))
        conn.execute(text(f"GRANT SELECT, INSERT ON onboarding_email_otps TO {app_role}"))
        conn.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON data_subject_requests TO {app_role}"))
        conn.execute(text("TRUNCATE TABLE data_subject_requests, access_request_history, access_requests, audit_log_metadata, pending_approvals, redaction_tokens, gateway_configs, policies, api_keys, users, tenants CASCADE;"))
        conn.commit()
        
    # Seed and inspect fixtures through the owner connection. Runtime requests below
    # still use the restricted application role and its signed RLS context.
    db = OwnerTestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        owner_engine.dispose()
        engine.dispose()


@pytest.fixture(scope="module")
def client(db_session: Session) -> TestClient:
    """FastAPI TestClient with overridden get_db dependency to enforce RLS"""
    def override_get_db():
        db = AppTestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def test_public_health(client: TestClient):
    """Test public health check doesn't require auth"""
    response = client.get("/health")
    assert response.status_code == status.HTTP_200_OK
    health = response.json()
    assert health["status"] == "healthy"
    assert health["service"] == "authclaw-backend"
    assert set(health) == {"status", "service"}

    metrics_response = client.get("/metrics")
    assert metrics_response.status_code == status.HTTP_401_UNAUTHORIZED

    # Verify OpenAPI documentation loads successfully
    openapi_resp = client.get("/openapi.json")
    assert openapi_resp.status_code == status.HTTP_200_OK
    assert "paths" in openapi_resp.json()

    docs_resp = client.get("/docs")
    assert docs_resp.status_code == status.HTTP_200_OK


def test_authentication_gates(client: TestClient):
    """Test secure routes block unauthenticated/mismatched requests"""
    preflight = client.options(
        "/v1/audit-logs",
        headers={
            "Origin": "http://localhost:3001",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization",
        },
    )
    assert preflight.status_code == status.HTTP_200_OK
    assert preflight.headers["access-control-allow-origin"] == "http://localhost:3001"

    # 1. Missing Authorization header
    response = client.get("/v1/audit-logs")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Missing Authorization Header" in response.json()["detail"]

    # 2. Invalid format
    response = client.get("/v1/audit-logs", headers={"Authorization": "InvalidFormatKey"})
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Expected: Bearer <key>" in response.json()["detail"]

    # 3. Invalid API key value
    response = client.get("/v1/audit-logs", headers={"Authorization": "Bearer badkey"})
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Invalid or expired credential" in response.json()["detail"]


def test_data_subject_request_lifecycle_authorization_and_isolation(
    client: TestClient,
    db_session: Session,
    monkeypatch,
):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    signing_key = Ed25519PrivateKey.generate()
    monkeypatch.delenv("AUDIT_EXPORT_SIGNING_PRIVATE_KEY_PEM", raising=False)
    monkeypatch.setenv("AUDIT_EXPORT_SIGNING_PRIVATE_KEY", base64.b64encode(
        signing_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    ).decode("ascii"))
    metrics_before = event_backbone.metrics_snapshot()
    tenant_a_id, tenant_b_id = uuid4(), uuid4()
    owner_a_id, viewer_a_id, owner_b_id = uuid4(), uuid4(), uuid4()
    owner_a_key, viewer_a_key, owner_b_key = "dsr-owner-a", "dsr-viewer-a", "dsr-owner-b"

    for tenant_id, name, users in (
        (tenant_a_id, "DSR Tenant A", [(owner_a_id, "owner-a@dsr.test", "owner"), (viewer_a_id, "viewer-a@dsr.test", "viewer")]),
        (tenant_b_id, "DSR Tenant B", [(owner_b_id, "owner-b@dsr.test", "owner")]),
    ):
        db_session.execute(text(f"SET app.current_tenant_id = '{tenant_id}'"))
        db_session.add(Tenant(id=tenant_id, name=name, tier="enterprise", status="active"))
        db_session.flush()
        for user_id, email, role in users:
            db_session.add(User(id=user_id, tenant_id=tenant_id, email=email, role=role, is_active=True))
        db_session.commit()

    for tenant_id, user_id, key, scopes in (
        (tenant_a_id, owner_a_id, owner_a_key, ["admin", "read", "write"]),
        (tenant_a_id, viewer_a_id, viewer_a_key, ["read"]),
        (tenant_b_id, owner_b_id, owner_b_key, ["admin", "read", "write"]),
    ):
        db_session.execute(text(f"SET app.current_tenant_id = '{tenant_id}'"))
        db_session.add(APIKey(id=uuid4(), tenant_id=tenant_id, key_hash=hash_key(key), name="Subject API key", scopes=scopes, is_active=True, created_by=user_id))
        db_session.commit()
    db_session.execute(text("SET app.current_tenant_id = ''"))

    audit_events = []
    published_tenants = []
    producer = object()
    monkeypatch.setattr(
        data_subject_request_service,
        "append_audit_event",
        lambda _db, event: audit_events.append(event) or {},
    )
    monkeypatch.setattr(data_subject_request_service, "_kafka_producer", None)
    monkeypatch.setattr(
        data_subject_request_service.event_backbone,
        "make_kafka_producer",
        lambda: producer,
    )
    monkeypatch.setattr(
        data_subject_request_service.event_backbone,
        "publish_pending_audit_events",
        lambda actual, tenant_id: published_tenants.append((actual, tenant_id)),
    )
    payload = {
        "subject_id": "customer-123",
        "request_type": "ACCESS",
        "scope": {"systems": ["console"]},
    }
    owner_a_headers = {"Authorization": f"Bearer {owner_a_key}"}

    denied = client.post(
        "/v1/data-subject-requests",
        json=payload,
        headers={"Authorization": f"Bearer {viewer_a_key}"},
    )
    assert denied.status_code == status.HTTP_403_FORBIDDEN

    created = client.post("/v1/data-subject-requests", json=payload, headers=owner_a_headers)
    assert created.status_code == status.HTTP_201_CREATED
    request_id = created.json()["id"]
    assert created.json()["status"] == "PENDING"

    unsupported_scope = client.post(
        "/v1/data-subject-requests",
        json={**payload, "scope": {"unsupported": ["console"]}},
        headers=owner_a_headers,
    )
    assert unsupported_scope.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    isolated = client.get(
        f"/v1/data-subject-requests/{request_id}",
        headers={"Authorization": f"Bearer {owner_b_key}"},
    )
    assert isolated.status_code == status.HTTP_404_NOT_FOUND

    verified = client.post(
        f"/v1/data-subject-requests/{request_id}/verify",
        json={"identity_verified": True},
        headers=owner_a_headers,
    )
    assert verified.status_code == status.HTTP_200_OK
    assert verified.json()["status"] == "VERIFIED"

    publication_count = len(published_tenants)
    approved = client.post(
        f"/v1/data-subject-requests/{request_id}/approve",
        json={"decision_reason": "Identity and scope confirmed"},
        headers=owner_a_headers,
    )
    assert approved.status_code == status.HTTP_200_OK
    assert approved.json()["status"] == "COMPLETED"
    assert approved.json()["completed_at"]
    assert published_tenants[publication_count:] == [(producer, str(tenant_a_id))]

    invalid_state = client.post(
        f"/v1/data-subject-requests/{request_id}/export",
        headers=owner_a_headers,
    )
    assert invalid_state.status_code == status.HTTP_409_CONFLICT

    second = client.post(
        "/v1/data-subject-requests",
        json={**payload, "subject_id": "customer-456", "request_type": "DELETION"},
        headers=owner_a_headers,
    )
    second_id = second.json()["id"]
    client.post(
        f"/v1/data-subject-requests/{second_id}/verify",
        json={"identity_verified": True},
        headers=owner_a_headers,
    )
    rejected = client.post(
        f"/v1/data-subject-requests/{second_id}/reject",
        json={"decision_reason": "Identity confirmed; request rejected"},
        headers=owner_a_headers,
    )
    assert rejected.status_code == status.HTTP_200_OK
    assert rejected.json()["status"] == "REJECTED"

    def approved_request(subject_id: str, request_type: str, scope=None) -> str:
        response = client.post(
            "/v1/data-subject-requests",
            json={**payload, "subject_id": subject_id, "request_type": request_type, "scope": scope or payload["scope"]},
            headers=owner_a_headers,
        )
        export_request_id = response.json()["id"]
        assert client.post(
            f"/v1/data-subject-requests/{export_request_id}/verify",
            json={"identity_verified": True},
            headers=owner_a_headers,
        ).status_code == status.HTTP_200_OK
        assert client.post(
            f"/v1/data-subject-requests/{export_request_id}/approve",
            json={"decision_reason": "Approved subject access export"},
            headers=owner_a_headers,
        ).status_code == status.HTTP_200_OK
        return export_request_id

    export_request_id = approved_request(str(owner_a_id), "EXPORT", {"datasets": ["user"]})
    unauthorized = client.post(
        f"/v1/data-subject-requests/{export_request_id}/export",
        headers={"Authorization": f"Bearer {viewer_a_key}"},
    )
    assert unauthorized.status_code == status.HTTP_403_FORBIDDEN
    cross_tenant = client.post(
        f"/v1/data-subject-requests/{export_request_id}/export",
        headers={"Authorization": f"Bearer {owner_b_key}"},
    )
    assert cross_tenant.status_code == status.HTTP_404_NOT_FOUND

    exported = client.post(
        f"/v1/data-subject-requests/{export_request_id}/export",
        headers=owner_a_headers,
    )
    assert exported.status_code == status.HTTP_200_OK
    artifact = exported.json()
    assert artifact["manifest"]["format_version"] == "authclaw.data-subject.export.v1"
    assert artifact["manifest"]["record_counts"] == {
        "users": 1,
        "api_keys": 0,
        "audit_metadata": 0,
    }
    assert artifact["request_id"] == export_request_id
    assert artifact["tenant_id"] == str(tenant_a_id)
    assert artifact["subject"] == {"id": str(owner_a_id)}
    assert artifact["data"]["user"]["email"] == "owner-a@dsr.test"
    assert artifact["data"]["api_keys"] == []
    assert "key_hash" not in str(artifact)
    assert owner_a_key not in str(artifact)
    assert artifact["digest"]["algorithm"] == "SHA-256"
    assert artifact["signature"]["algorithm"] == "Ed25519"

    completed = client.post(
        f"/v1/data-subject-requests/{export_request_id}/export",
        headers=owner_a_headers,
    )
    assert completed.status_code == status.HTTP_409_CONFLICT

    empty_request_id = approved_request("external-subject-with-no-records", "EXPORT")
    empty_export = client.post(
        f"/v1/data-subject-requests/{empty_request_id}/export",
        headers=owner_a_headers,
    )
    assert empty_export.status_code == status.HTTP_200_OK
    assert empty_export.json()["manifest"]["record_counts"] == {
        "users": 0,
        "api_keys": 0,
        "audit_metadata": 0,
    }

    db_session.execute(text(f"SET app.current_tenant_id = '{tenant_a_id}'"))
    db_session.add(
        Notification(
            tenant_id=tenant_a_id,
            user_id=viewer_a_id,
            type="privacy-test",
            severity="info",
            title="Synthetic notification",
            body="Synthetic content",
        )
    )
    db_session.commit()
    deletion_request_id = approved_request(str(viewer_a_id), "DELETION", {"datasets": ["notifications"]})
    unauthorized_delete = client.post(
        f"/v1/data-subject-requests/{deletion_request_id}/delete",
        headers={"Authorization": f"Bearer {viewer_a_key}"},
    )
    assert unauthorized_delete.status_code == status.HTTP_403_FORBIDDEN
    cross_tenant_delete = client.post(
        f"/v1/data-subject-requests/{deletion_request_id}/delete",
        headers={"Authorization": f"Bearer {owner_b_key}"},
    )
    assert cross_tenant_delete.status_code == status.HTTP_404_NOT_FOUND

    publication_count = len(published_tenants)
    deleted = client.post(
        f"/v1/data-subject-requests/{deletion_request_id}/delete",
        headers=owner_a_headers,
    )
    assert deleted.status_code == status.HTTP_200_OK
    deletion_result = deleted.json()
    assert deletion_result["deleted_items"] == {
        "api_keys": 0,
        "notifications": 1,
        "onboarding_status": 0,
    }
    assert deletion_result["retained_items"] == {"user_identity": 1}
    assert deletion_result["exception_reasons"] == [
        "user_identity:account_and_tenant_lifecycle"
    ]
    assert deletion_result["completed_at"]
    assert "viewer-a@dsr.test" not in str(deletion_result)
    assert published_tenants[publication_count:] == [(producer, str(tenant_a_id))]

    repeated = client.post(
        f"/v1/data-subject-requests/{deletion_request_id}/delete",
        headers=owner_a_headers,
    )
    assert repeated.status_code == status.HTTP_200_OK
    assert repeated.json()["deleted_items"] == {}

    db_session.execute(text(f"SET app.current_tenant_id = '{tenant_a_id}'"))
    assert db_session.query(User).filter(User.id == viewer_a_id).one().is_active
    assert db_session.query(APIKey).filter(APIKey.created_by == viewer_a_id).count() == 1
    assert db_session.query(Notification).filter(Notification.user_id == viewer_a_id).count() == 0
    assert [event["action"] for event in audit_events] == [
        "request_created",
        "identity_verified",
        "request_approved",
        "request_completed",
        "request_created",
        "identity_verified",
        "request_rejected",
        "request_created",
        "identity_verified",
        "request_approved",
        "export_started",
        "export_completed",
        "request_created",
        "identity_verified",
        "request_approved",
        "export_started",
        "export_completed",
        "request_created",
        "identity_verified",
        "request_approved",
        "deletion_started",
        "deletion_exception_applied",
        "deletion_completed",
    ]
    export_audit = [
        event for event in audit_events if event["action"].startswith("export_")
    ]
    assert all(f"subject_id={owner_a_id}" in event["execution_trace"] for event in export_audit[:2])
    assert "owner-a@dsr.test" not in str(export_audit)
    assert owner_a_key not in str(export_audit)

    deletion_audit = [
        event for event in audit_events if event["action"].startswith("deletion_")
    ]
    assert [event["action"] for event in deletion_audit] == [
        "deletion_started",
        "deletion_exception_applied",
        "deletion_completed",
    ]
    assert "viewer-a@dsr.test" not in str(deletion_audit)

    rollback_request_id = approved_request("rollback-subject", "DELETION")
    monkeypatch.setattr(
        data_subject_request_service.DataSubjectRequestService,
        "_delete_subject_data",
        staticmethod(lambda _db, _record: (_ for _ in ()).throw(RuntimeError("failure"))),
    )
    publication_count = len(published_tenants)
    with pytest.raises(RuntimeError, match="failure"):
        client.post(
            f"/v1/data-subject-requests/{rollback_request_id}/delete",
            headers=owner_a_headers,
        )
    assert len(published_tenants) == publication_count
    db_session.expire_all()
    db_session.execute(text(f"SET app.current_tenant_id = '{tenant_a_id}'"))
    rollback_record = db_session.query(DataSubjectRequest).filter(
        DataSubjectRequest.id == rollback_request_id
    ).one()
    assert rollback_record.status == "APPROVED"
    assert rollback_record.completed_at is None

    metrics_after = event_backbone.metrics_snapshot()
    assert metrics_after["gdpr_requests_created_total"] - metrics_before.get(
        "gdpr_requests_created_total", 0
    ) == 6
    assert metrics_after["gdpr_requests_verified_total"] - metrics_before.get(
        "gdpr_requests_verified_total", 0
    ) == 6
    assert metrics_after["gdpr_requests_approved_total"] - metrics_before.get(
        "gdpr_requests_approved_total", 0
    ) == 5
    assert metrics_after["gdpr_exports_completed_total"] - metrics_before.get(
        "gdpr_exports_completed_total", 0
    ) == 2
    assert metrics_after["gdpr_deletions_completed_total"] - metrics_before.get(
        "gdpr_deletions_completed_total", 0
    ) == 1
    assert metrics_after["gdpr_request_failures_total"] > metrics_before.get(
        "gdpr_request_failures_total", 0
    )

    db_session.execute(text(f"SET app.current_tenant_id = '{tenant_a_id}'"))
    records = db_session.query(DataSubjectRequest).filter(DataSubjectRequest.tenant_id == tenant_a_id).all()
    assert len(records) == 6
    assert sum(record.status == "COMPLETED" for record in records) == 4


def test_public_access_request_persists_server_owned_fields(
    client: TestClient,
    db_session: Session,
    monkeypatch,
):
    monkeypatch.setattr(
        access_request_service.settings,
        "PRIVACY_NOTICE_VERSION",
        "approved-test-version",
    )
    payload = {
        "name": "Ada Lovelace",
        "business_email": "ada@example.com",
        "company": "Analytical Engines",
        "role": "CTO",
        "use_case": "Govern AI traffic.",
        "requested_access": "EARLY_ACCESS",
        "consent": True,
        "source_page": "/security",
    }

    response = client.post("/api/public/v1/access-requests", json=payload)

    assert response.status_code == status.HTTP_202_ACCEPTED
    reference = response.json()["reference"]
    record = db_session.query(AccessRequest).filter(AccessRequest.reference == reference).one()
    assert record.notice_version == "approved-test-version"
    assert record.source_page == "/security"
    assert record.status == "PENDING"
    history = (
        db_session.query(AccessRequestHistory)
        .filter(
            AccessRequestHistory.access_request_id == record.id,
            AccessRequestHistory.event_type == "CREATED",
        )
        .one()
    )
    assert history.event_type == "CREATED"
    assert history.new_status == "PENDING"

    duplicate = AccessRequest(
        reference=reference,
        name=record.name,
        business_email=record.business_email,
        company=record.company,
        role=record.role,
        use_case=record.use_case,
        requested_access=record.requested_access,
        consent_timestamp=record.consent_timestamp,
        notice_version=record.notice_version,
        source_page=record.source_page,
        status=record.status,
    )
    db_session.add(duplicate)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()
    assert db_session.query(AccessRequest).filter(AccessRequest.reference == reference).count() == 1


def test_access_request_retention_policy(db_session: Session):
    now = datetime.now(timezone.utc)

    def record(reference: str, status_value: str, age_days: int, email: str):
        created = now - timedelta(days=age_days)
        return AccessRequest(
            reference=reference,
            name="Synthetic User",
            business_email=email,
            company="Synthetic Company",
            role="Tester",
            use_case="Synthetic lifecycle test",
            requested_access="EARLY_ACCESS",
            consent_timestamp=created,
            notice_version="test",
            source_page="/early-access",
            status=status_value,
            created_at=created,
            updated_at=created,
        )

    expired = [
        record("AR-RETENTION-PENDING", "PENDING", 91, "pending@example.test"),
        record("AR-RETENTION-REJECTED", "REJECTED", 31, "rejected@example.test"),
        record("AR-RETENTION-INVITED", "INVITED", 31, "invited@example.test"),
    ]
    retained = [
        record("AR-RETENTION-APPROVED", "APPROVED", 120, "approved@example.test"),
        record("AR-RETENTION-RECENT", "PENDING", 10, "recent@example.test"),
        record("AR-RETENTION-STARTED", "INVITED", 31, "started@example.test"),
    ]
    db_session.add_all(expired + retained)
    db_session.commit()
    with owner_engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO onboarding_email_otps (
                    id, email, tenant_name, otp_hash, status, expires_at, created_at
                )
                VALUES (
                    :id, 'started@example.test', 'Synthetic', 'synthetic',
                    'pending', :expires_at, :created_at
                )
                """
            ),
            {
                "id": uuid4(),
                "expires_at": now + timedelta(minutes=15),
                "created_at": now - timedelta(days=1),
            },
        )

    assert purge_expired_access_requests(db_session, now=now) == 3

    remaining = {
        row.reference
        for row in db_session.query(AccessRequest)
        .filter(AccessRequest.reference.like("AR-RETENTION-%"))
        .all()
    }
    assert remaining == {
        "AR-RETENTION-APPROVED",
        "AR-RETENTION-RECENT",
        "AR-RETENTION-STARTED",
    }
    deleted_ids = {row.id for row in expired}
    histories = (
        db_session.query(AccessRequestHistory)
        .filter(AccessRequestHistory.access_request_id.in_(deleted_ids))
        .all()
    )
    assert len(histories) == 3
    assert all(history.event_type == "DELETED" for history in histories)


def test_platform_session_issuer_isolation(client, db_session, monkeypatch):
    from app.api.v1.endpoints import auth
    from app.core.passwords import hash_password
    from scripts.bootstrap_database_security import configured_roles, secure_authentication_boundary
    from sqlalchemy.exc import DBAPIError

    monkeypatch.setenv("PLATFORM_AUTH_PASSWORD", "test-only-issuer-password")
    monkeypatch.setenv("PLATFORM_AUTH_USER", "authclaw_platform_auth_test")
    with owner_engine.begin() as conn:
        secure_authentication_boundary(conn, configured_roles()[1])
        secure_authentication_boundary(conn, configured_roles()[1])
    issuer_engine = create_engine(owner_engine.url.set(
        username="authclaw_platform_auth_test", password="test-only-issuer-password"
    ))
    monkeypatch.setattr(auth, "PlatformSessionLocal", sessionmaker(bind=issuer_engine))
    admin_id = uuid4()
    email = f"{admin_id}@platform.test"
    password = "Platform-Test-Only-Password-42!"
    with owner_engine.begin() as conn:
        conn.execute(text("INSERT INTO authn.platform_admins (id, email, password_hash) VALUES (:id, :email, :hash)"),
                     {"id": admin_id, "email": email, "hash": hash_password(password)})
    try:
        for sql in (
            "SELECT authn.create_platform_session(:hash, :id, 'password', now() + interval '1 hour', '{}'::jsonb)",
            "SELECT authn.set_platform_context(:id, :id)",
            "SET ROLE authclaw_platform_auth_test",
            "INSERT INTO authn.platform_sessions DEFAULT VALUES",
        ):
            with engine.begin() as conn, pytest.raises(DBAPIError) as denied:
                conn.execute(text(sql), {"hash": "0" * 64, "id": admin_id})
            assert denied.value.orig.sqlstate == "42501"
        with issuer_engine.begin() as conn, pytest.raises(DBAPIError):
            conn.execute(text("SELECT * FROM authn.platform_admins"))
        rejected = client.post("/v1/auth/login", json={"email": email, "password": "wrong"})
        assert rejected.status_code == 401
        logged_in = client.post("/v1/auth/login", json={"email": email, "password": password})
        assert logged_in.status_code == 200, logged_in.text
        headers = {"Authorization": f"Bearer {logged_in.json()['session_token']}"}
        profile = client.get("/v1/auth/me", headers=headers)
        assert profile.status_code == 200
        assert profile.json()["tenant_id"] is None
        assert client.post("/v1/tenants", json={"name": "Issuer test tenant", "tier": "starter"}, headers=headers).status_code == 201
        from types import SimpleNamespace
        monkeypatch.setattr(access_request_service, "send_otp_email", lambda *_a, **_kw: SimpleNamespace(method="local_outbox"))
        invitee = f"invite-{uuid4().hex}@example.com"
        submitted = client.post("/api/public/v1/access-requests", json={
            "name": "Invite test", "business_email": invitee, "company": f"Invite-{uuid4().hex}",
            "role": "Owner", "use_case": "Test onboarding", "requested_access": "EARLY_ACCESS",
            "consent": True, "source_page": "/early-access",
        })
        assert submitted.status_code == 202
        reference = submitted.json()["reference"]
        approved = client.patch(f"/api/public/v1/access-requests/{reference}/status", params={"new_status": "APPROVED"}, headers=headers)
        assert approved.status_code == 204, approved.text
        history = client.get("/api/public/v1/access-requests", params={"status_filter": "APPROVED", "limit": 1}, headers=headers).json()
        record = next(row for row in history if row["reference"] == reference)
        invite = next(row["metadata"] for row in record["history"] if "invite_id" in row["metadata"])
        assert invite["invite_id"] in invite["invite_link"]
        verification = {
            "signup_id": invite["invite_id"], "otp": invite["dev_otp"], "password": password,
            "terms_accepted": True, "terms_version": "2026-07-20",
            "privacy_notice_acknowledged": True, "privacy_notice_version": "2026-07-20",
        }
        joined = client.post("/v1/onboarding/verify", json=verification)
        assert joined.status_code == 200, joined.text
        assert client.post("/v1/onboarding/verify", json=verification).status_code == 400
        tenant_login = client.post("/v1/auth/login", json={"email": invitee, "password": password})
        assert tenant_login.status_code == 200
        tenant_headers = {"Authorization": f"Bearer {tenant_login.json()['session_token']}"}
        assert client.get("/api/public/v1/access-requests", headers=tenant_headers).status_code == 403
        assert client.get("/v1/gateways", headers=tenant_headers).status_code == 200
        monkeypatch.setattr(auth, "PlatformSessionLocal", None)
        assert client.post("/v1/auth/login", json={"email": email, "password": password}).status_code == 503
    finally:
        with owner_engine.begin() as conn:
            conn.execute(text("DELETE FROM authn.platform_admins WHERE id = :id"), {"id": admin_id})
        issuer_engine.dispose()


def test_tenant_creation_and_isolation(client: TestClient, db_session: Session):
    """Test full CRUD endpoints, YAML validations, and tenant RLS isolation"""
    
    # -------------------------------------------------------------------------
    # 1. Setup Tenant A and Tenant B
    # -------------------------------------------------------------------------
    tenant_a_id = uuid4()
    tenant_b_id = uuid4()
    
    # Seed tenants with SET session context to bypass RLS inserts
    db_session.execute(text(f"SET app.current_tenant_id = '{tenant_a_id}'"))
    tenant_a = Tenant(id=tenant_a_id, name="Test Tenant A", tier="enterprise", status="active")
    db_session.add(tenant_a)
    db_session.commit()

    db_session.execute(text(f"SET app.current_tenant_id = '{tenant_b_id}'"))
    tenant_b = Tenant(id=tenant_b_id, name="Test Tenant B", tier="starter", status="active")
    db_session.add(tenant_b)
    db_session.commit()

    # A legacy tenant admin must not gain platform access through API-key scopes.
    admin_user_id = uuid4()
    db_session.execute(text(f"SET app.current_tenant_id = '{tenant_a_id}'"))
    admin_user = User(
        id=admin_user_id,
        tenant_id=tenant_a_id,
        email="admin@tenantA.com",
        role="owner",
        platform_role="ADMIN",
        is_active=True,
    )
    db_session.add(admin_user)
    db_session.commit()

    admin_key = "system_admin_key_value"
    admin_hash = hash_key(admin_key)
    admin_api_key = APIKey(
        id=uuid4(),
        tenant_id=tenant_a_id,
        key_hash=admin_hash,
        name="Admin Key",
        scopes=["admin", "read", "write", "platform.admin"],
        is_active=True,
        created_by=admin_user_id
    )
    db_session.add(admin_api_key)
    db_session.commit()

    # Seed User & API Key for Tenant B (write/read scope)
    user_b_id = uuid4()
    db_session.execute(text(f"SET app.current_tenant_id = '{tenant_b_id}'"))
    user_b = User(id=user_b_id, tenant_id=tenant_b_id, email="user@tenantB.com", role="operator", is_active=True)
    db_session.add(user_b)
    db_session.commit()

    key_b = "tenant_b_operator_key"
    hash_b = hash_key(key_b)
    api_key_b = APIKey(
        id=uuid4(),
        tenant_id=tenant_b_id,
        key_hash=hash_b,
        name="Operator Key B",
        scopes=["read", "write"],
        is_active=True,
        created_by=user_b_id
    )
    db_session.add(api_key_b)
    db_session.commit()

    # Clear RLS session setting
    db_session.execute(text("SET app.current_tenant_id = ''"))

    # -------------------------------------------------------------------------
    # 2. Test POST /tenants (Admin-only scope check)
    # -------------------------------------------------------------------------
    headers_admin = {"Authorization": f"Bearer {admin_key}"}
    headers_b = {"Authorization": f"Bearer {key_b}"}

    # Request as Tenant B operator (insufficient scope) -> 403 Forbidden
    response = client.post("/v1/tenants", json={"name": "Tenant C", "tier": "starter"}, headers=headers_b)
    assert response.status_code == status.HTTP_403_FORBIDDEN

    # Even a tenant owner with legacy ADMIN/platform.admin claims is denied.
    response = client.post("/v1/tenants", json={"name": "Tenant C", "tier": "pro"}, headers=headers_admin)
    assert response.status_code == status.HTTP_403_FORBIDDEN

    platform_admin_id = uuid4()
    platform_token = f"acl_session_{uuid4().hex}"
    with owner_engine.begin() as connection:
        connection.execute(
            text("""
                INSERT INTO authn.platform_admins (id, email, password_hash)
                VALUES (:id, :email, 'unusable-test-password')
            """),
            {"id": platform_admin_id, "email": f"{platform_admin_id}@platform.test"},
        )
        connection.execute(
            text("""
                INSERT INTO authn.platform_sessions (
                    id, token_hash, platform_admin_id, authentication_method, expires_at
                ) VALUES (:id, :token_hash, :admin_id, 'password', :expires_at)
            """),
            {
                "id": uuid4(),
                "token_hash": hash_key(platform_token),
                "admin_id": platform_admin_id,
                "expires_at": datetime.now(timezone.utc) + timedelta(minutes=15),
            },
        )
    try:
        response = client.post(
            "/v1/tenants",
            json={"name": "Tenant C", "tier": "pro"},
            headers={"Authorization": f"Bearer {platform_token}"},
        )
    finally:
        with owner_engine.begin() as connection:
            connection.execute(
                text("DELETE FROM authn.platform_admins WHERE id = :id"),
                {"id": platform_admin_id},
            )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["name"] == "Tenant C"
    assert response.json()["tier"] == "pro"

    # -------------------------------------------------------------------------
    # 3. Test POST /gateways (Isolated CRUD check)
    # -------------------------------------------------------------------------
    # Register gateway config for Tenant A
    gw_payload = {
        "name": "OpenAI Route",
        "provider": "openai",
        "endpoint": "https://api.openai.com/v1",
        "model_whitelist": ["gpt-4"],
        "redaction_strategy": "mask"
    }
    response = client.post("/v1/gateways", json=gw_payload, headers=headers_admin)
    assert response.status_code == status.HTTP_201_CREATED
    gw_id = response.json()["id"]

    # -------------------------------------------------------------------------
    # 4. Cross-Tenant GET Isolation Check
    # -------------------------------------------------------------------------
    # Tenant B tries to retrieve Tenant A's config -> 404 Not Found (enforced by RLS)
    response = client.get(f"/v1/gateways/{gw_id}/config", headers=headers_b)
    assert response.status_code == status.HTTP_404_NOT_FOUND

    # Tenant A retrieves its own config -> 200 OK
    response = client.get(f"/v1/gateways/{gw_id}/config", headers=headers_admin)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["name"] == "OpenAI Route"

    # -------------------------------------------------------------------------
    # 5. Test POST /policies & YAML/Regex validation
    # -------------------------------------------------------------------------
    # A. Malformed YAML check
    bad_yaml_payload = {
        "name": "Invalid YAML Policy",
        "policy_yaml": "model_rules:\n  blacklist: - bad format"
    }
    response = client.post("/v1/policies", json=bad_yaml_payload, headers=headers_admin)
    assert response.status_code == status.HTTP_400_BAD_REQUEST

    # B. Invalid regex compilation check
    bad_regex_payload = {
        "name": "Invalid Regex Policy",
        "policy_yaml": "regex_rules:\n  - pattern: '['\n    reason: 'brackets error'"
    }
    response = client.post("/v1/policies", json=bad_regex_payload, headers=headers_admin)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    detail = response.json()["detail"]
    assert detail["message"] == "Policy validation failed"
    assert any(
        error["path"] == "regex_rules[0].pattern"
        and "invalid regex pattern" in error["message"].lower()
        for error in detail["errors"]
    )

    # C. Valid policy creation
    valid_policy_payload = {
        "name": "Standard Policy",
        "policy_yaml": "model_rules:\n  blacklist:\n    - gpt-3.5-turbo\nregex_rules:\n  - pattern: '(?i)confidential'\n    reason: 'Confidentiality block'\n"
    }
    response = client.post("/v1/policies", json=valid_policy_payload, headers=headers_admin)
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["version"] == 1
    assert response.json()["is_active"] is True

    # -------------------------------------------------------------------------
    # 6. Test GET /redaction/{id}/tokenization-map with dynamic decryption
    # -------------------------------------------------------------------------
    # Current runtime token maps contain authenticated AES-GCM envelopes.
    # Historical CBC upgrade/rejection is exercised by the retirement suites.
    from app.core.crypto import encrypt_secret
    import hashlib

    encrypted_base64 = encrypt_secret("John Doe")

    token_hash = hashlib.sha256("[REDACTED_PERSON_abc]".encode("utf-8")).hexdigest()
    
    # Save token in DB under Tenant A
    db_session.execute(text(f"SET app.current_tenant_id = '{tenant_a_id}'"))
    token_record = RedactionToken(
        id=uuid4(),
        tenant_id=tenant_a_id,
        original_value=encrypted_base64,
        original_value_blind_index="a" * 64,
        token_hash=token_hash,
        token_value="[REDACTED_PERSON_abc]",
        strategy="mask"
    )
    db_session.add(token_record)
    db_session.commit()
    db_session.execute(text("SET app.current_tenant_id = ''"))

    # A. Tenant B requests Tenant A's map -> 403 Forbidden (URL tenant mismatch check)
    response = client.get(f"/v1/redaction/{tenant_a_id}/tokenization-map", headers=headers_b)
    assert response.status_code == status.HTTP_403_FORBIDDEN

    # B. Tenant A requests its own map -> returns decrypted plaintext "John Doe"
    response = client.get(f"/v1/redaction/{tenant_a_id}/tokenization-map", headers=headers_admin)
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()) == 1
    assert response.json()[0]["original_value"] == "John Doe"
    assert response.json()[0]["token_value"] == "[REDACTED_PERSON_abc]"

    # -------------------------------------------------------------------------
    # 7. Test GET /audit-logs
    # -------------------------------------------------------------------------
    # Seed audit log metadata record for Tenant A
    db_session.execute(text(f"SET app.current_tenant_id = '{tenant_a_id}'"))
    audit_record = AuditLogMetadata(
        id=uuid4(),
        tenant_id=tenant_a_id,
        record_id=uuid4(),
        tenant_sequence=1,
        idempotency_key="test:audit-endpoint",
        chain_version=2,
        canonical_payload="{}",
        actor_id=admin_user_id,
        action="policy_block",
        frameworks_affected=["GDPR", "SOC2"]
    )
    db_session.add(audit_record)
    db_session.commit()
    db_session.execute(text("SET app.current_tenant_id = ''"))

    # Retrieve audit logs as Tenant B (isolated - returns empty list)
    response = client.get("/v1/audit-logs", headers=headers_b)
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["records"]) == 0

    # Retrieve audit logs as Tenant A (returns Tenant A's logs)
    response = client.get("/v1/audit-logs", headers=headers_admin)
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["records"]) == 1
    assert response.json()["records"][0]["action"] == "policy_block"
    assert "GDPR" in response.json()["records"][0]["frameworks_affected"]


def test_workflow_approval_integration(client: TestClient, db_session: Session):
    """Test full workflow approval integration: create, approve, resume, verify completed state."""
    # 1. Setup Tenant C and Admin/User
    tenant_id = uuid4()
    user_id = uuid4()
    api_key_raw = "system_admin_key_tenant_c"
    api_key_hash = hash_key(api_key_raw)

    # Seed database
    db_session.execute(text(f"SET app.current_tenant_id = '{tenant_id}'"))
    tenant = Tenant(id=tenant_id, name="Test Tenant C", tier="enterprise", status="active")
    db_session.add(tenant)
    db_session.commit()

    db_session.execute(text(f"SET app.current_tenant_id = '{tenant_id}'"))
    user = User(id=user_id, tenant_id=tenant_id, email="admin@tenantC.com", role="admin", is_active=True)
    db_session.add(user)
    approver_id = uuid4()
    db_session.add(User(
        id=approver_id, tenant_id=tenant_id, email="approver@tenantC.com",
        role="admin", is_active=True,
    ))
    db_session.commit()

    api_key = APIKey(
        id=uuid4(),
        tenant_id=tenant_id,
        key_hash=api_key_hash,
        name="Admin Key C",
        scopes=["admin", "read", "write"],
        is_active=True,
        created_by=user_id
    )
    db_session.add(api_key)
    approver_api_key_raw = "separate_approver_key_tenant_c"
    db_session.add(APIKey(
        id=uuid4(), tenant_id=tenant_id, key_hash=hash_key(approver_api_key_raw),
        name="Separate Approver Key C", scopes=["admin", "read", "write"],
        is_active=True, created_by=approver_id,
    ))
    db_session.commit()
    db_session.execute(text("SET app.current_tenant_id = ''"))

    headers = {"Authorization": f"Bearer {api_key_raw}"}
    approver_headers = {"Authorization": f"Bearer {approver_api_key_raw}"}

    # 2. Create compliance workflow (scan executes to completion)
    from unittest.mock import patch, MagicMock
    
    with patch("app.orchestrator.connectors.DocumentScanner.list_documents") as mock_list, \
         patch("app.orchestrator.connectors.DocumentScanner.fetch_and_extract_text") as mock_fetch, \
         patch("requests.post") as mock_post:
         
        mock_list.return_value = [{"object_key": "test-doc.txt", "file_name": "test-doc.txt", "size": 1024}]
        mock_fetch.return_value = "My email is john@example.com"
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"entity_type": "EMAIL_ADDRESS"}]
        mock_post.return_value = mock_resp

        response = client.post(
            "/v1/workflows",
            headers=headers,
            json={"framework": "HIPAA"}
        )
        assert response.status_code == status.HTTP_201_CREATED
        wf_data = response.json()
        workflow_id = wf_data["workflow_id"]
    
    assert wf_data["current_state"] == "COMPLETE"
    assert wf_data["execution_status"] == "COMPLETED"

    # Trigger remediation (creates the pending approval)
    response_remediate = client.post(
        f"/v1/workflows/{workflow_id}/remediate",
        headers=headers
    )
    if response_remediate.status_code != status.HTTP_200_OK:
        print(f"REMEDIATION ERROR: {response_remediate.json()}")
    assert response_remediate.status_code == status.HTTP_200_OK
    wf_remediate_data = response_remediate.json()
    approval_id = wf_remediate_data["approval_id"]

    assert wf_remediate_data["current_state"] == "AWAITING_APPROVAL"
    assert wf_remediate_data["execution_status"] == "PAUSED"
    assert wf_remediate_data["approval_status"] == "PENDING"
    assert approval_id is not None

    # Verify database state for PendingApproval and ComplianceWorkflow
    db_session.execute(text(f"SET app.current_tenant_id = '{tenant_id}'"))
    from app.db.models import PendingApproval, ComplianceWorkflow
    db_wf = db_session.query(ComplianceWorkflow).filter(
        ComplianceWorkflow.workflow_id == workflow_id
    ).first()
    assert db_wf.approval_id == uuid.UUID(approval_id)
    assert db_wf.approval_status == "PENDING"

    db_app = db_session.query(PendingApproval).filter(
        PendingApproval.id == uuid.UUID(approval_id)
    ).first()
    assert db_app.status == "PENDING"
    assert db_app.approved_at is None
    assert db_app.approver_id is None
    db_session.execute(text("SET app.current_tenant_id = ''"))

    legacy_setup = client.post("/v1/workflows/mfa/setup", headers=approver_headers)
    assert legacy_setup.status_code == status.HTTP_410_GONE
    session_token = "acl_session_" + uuid4().hex
    db_session.execute(text("""SELECT authn.create_session(
        :hash, :tenant, :user, 'mfa-test', now()+interval '10 minutes', '{}'::jsonb)"""),
        {"hash": hash_key(session_token), "tenant": tenant_id, "user": approver_id})
    db_session.commit()
    mfa_headers = {"Authorization": f"Bearer {session_token}"}
    mfa_setup = client.post("/v1/users/me/mfa/setup", headers=mfa_headers)
    assert mfa_setup.status_code == status.HTTP_200_OK
    backup_code = mfa_setup.json()["backup_codes"][0]
    mfa_confirm = client.post(
        "/v1/users/me/mfa/confirm",
        headers=mfa_headers,
        json={"code": pyotp.TOTP(mfa_setup.json()["mfa_secret"]).now()},
    )
    assert mfa_confirm.status_code == status.HTTP_200_OK

    # 3. Approve workflow
    with patch("app.orchestrator.connectors.DocumentScanner.execute_remediation") as mock_execute:
        mock_execute.return_value = {
            "connector": "aws_s3",
            "control": "test-doc.txt",
            "target": {"uri": "s3://authclaw-documents/test-doc.txt"},
            "status": "success",
            "details": "Simulated local remediation proof",
            "mutation_id": "local-proof",
            "rollback_ref": {"bucket": "authclaw-documents", "backup_key": "local", "target_key": "test-doc.txt"},
        }
        response_approve = client.post(
            f"/v1/workflows/{workflow_id}/approve",
            headers=approver_headers,
            json={"totp_code": backup_code},
        )
    assert response_approve.status_code == status.HTTP_200_OK
    wf_approved_data = response_approve.json()

    # Expected outcomes
    assert wf_approved_data["current_state"] == "COMPLETE"
    assert wf_approved_data["execution_status"] == "COMPLETED"
    assert wf_approved_data["approval_status"] == "APPROVED"

    # Verify db states
    db_session.rollback()
    db_session.execute(text(f"SET app.current_tenant_id = '{tenant_id}'"))
    db_wf_final = db_session.query(ComplianceWorkflow).filter(
        ComplianceWorkflow.workflow_id == workflow_id
    ).first()
    assert db_wf_final.current_state == "COMPLETE"
    assert db_wf_final.execution_status == "COMPLETED"
    assert db_wf_final.approval_status == "APPROVED"

    db_app_final = db_session.query(PendingApproval).filter(
        PendingApproval.id == uuid.UUID(approval_id)
    ).first()
    assert db_app_final.status == "CONSUMED"
    assert db_app_final.approved_at is not None
    assert db_app_final.approver_id == approver_id
    assert db_app_final.consumed_at is not None
    assert db_app_final.consumed_by_id == approver_id
    db_session.execute(text("SET app.current_tenant_id = ''"))

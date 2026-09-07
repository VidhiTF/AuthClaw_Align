"""PostgreSQL regression suite for the notification endpoints.

Focus: ``POST /v1/notifications/read-all`` must return a reliable response,
persist every visible unread notification as read, and leave notifications
that belong to other users or other tenants untouched. The regression guards
against calling the ``list_notifications`` endpoint function directly as a
helper, which binds FastAPI ``Query`` defaults as SQLAlchemy ``limit`` values
and fails the request after the read state has already been committed.
"""

import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from main import app

# Force fallback to PostgreSQL audit logs by unsetting CLICKHOUSE_HOST for this suite
os.environ.pop("CLICKHOUSE_HOST", None)

from app.core.auth import hash_key
from app.db.dependencies import get_db
from app.db.models import APIKey, Finding, FindingStatus, Notification, Tenant, User
from app.services import findings_service
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

OWNER_A_KEY = "notif-owner-a"
VIEWER_A_KEY = "notif-viewer-a"
OWNER_B_KEY = "notif-owner-b"

# Owner A owns more unread personal notifications than the read-all response
# page size, so the bounded response proves the limit is a real integer.
OWNER_A_UNREAD_COUNT = 55
READ_ALL_PAGE_SIZE = 50


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
        conn.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON notifications TO {app_role}"))
        conn.execute(
            text(
                "TRUNCATE TABLE notifications, data_subject_requests, access_request_history, "
                "access_requests, audit_log_metadata, pending_approvals, redaction_tokens, "
                "gateway_configs, policies, api_keys, users, tenants CASCADE;"
            )
        )
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


@pytest.fixture(scope="module")
def seeded(db_session: Session) -> dict:
    """Two tenants, three principals, and a deterministic notification mix."""
    tenant_a_id, tenant_b_id = uuid4(), uuid4()
    owner_a_id, viewer_a_id, owner_b_id = uuid4(), uuid4(), uuid4()

    for tenant_id, name, users in (
        (
            tenant_a_id,
            "Notification Tenant A",
            [
                (owner_a_id, "owner-a@notifications.test", "owner"),
                (viewer_a_id, "viewer-a@notifications.test", "viewer"),
            ],
        ),
        (tenant_b_id, "Notification Tenant B", [(owner_b_id, "owner-b@notifications.test", "owner")]),
    ):
        db_session.execute(text(f"SET app.current_tenant_id = '{tenant_id}'"))
        db_session.add(Tenant(id=tenant_id, name=name, tier="enterprise", status="active"))
        db_session.flush()
        for user_id, email, role in users:
            db_session.add(User(id=user_id, tenant_id=tenant_id, email=email, role=role, is_active=True))
        db_session.commit()

    for tenant_id, user_id, key, scopes in (
        (tenant_a_id, owner_a_id, OWNER_A_KEY, ["admin", "read", "write"]),
        (tenant_a_id, viewer_a_id, VIEWER_A_KEY, ["read"]),
        (tenant_b_id, owner_b_id, OWNER_B_KEY, ["admin", "read", "write"]),
    ):
        db_session.execute(text(f"SET app.current_tenant_id = '{tenant_id}'"))
        db_session.add(
            APIKey(
                id=uuid4(),
                tenant_id=tenant_id,
                key_hash=hash_key(key),
                name="Notification API key",
                scopes=scopes,
                is_active=True,
                created_by=user_id,
            )
        )
        db_session.commit()
    db_session.execute(text("SET app.current_tenant_id = ''"))

    db_session.execute(text(f"SET app.current_tenant_id = '{tenant_a_id}'"))
    for index in range(OWNER_A_UNREAD_COUNT):
        db_session.add(
            Notification(
                id=uuid4(),
                tenant_id=tenant_a_id,
                user_id=owner_a_id,
                type="policy_violation_block",
                severity="warning",
                title=f"Owner A unread {index}",
                body="regression seed",
                link="/audit",
            )
        )
    for title in ("Unread broadcast one", "Unread broadcast two"):
        db_session.add(
            Notification(
                id=uuid4(),
                tenant_id=tenant_a_id,
                user_id=None,
                type="gateway_api_key_issue",
                severity="warning",
                title=title,
                body="regression seed",
                link="/connect",
            )
        )
    db_session.add(
        Notification(
            id=uuid4(),
            tenant_id=tenant_a_id,
            user_id=None,
            type="approval_requested",
            severity="info",
            title="Already read broadcast",
            body="regression seed",
            link="/agent",
            read_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
    )
    db_session.add(
        Notification(
            id=uuid4(),
            tenant_id=tenant_a_id,
            user_id=viewer_a_id,
            type="policy_violation_block",
            severity="critical",
            title="Viewer A personal unread",
            body="regression seed",
            link="/audit",
        )
    )
    db_session.add(
        Notification(
            id=uuid4(),
            tenant_id=tenant_b_id,
            user_id=None,
            type="remediation_completed",
            severity="info",
            title="Tenant B broadcast unread",
            body="regression seed",
            link="/agent",
        )
    )
    db_session.commit()
    db_session.execute(text("SET app.current_tenant_id = ''"))

    return {
        "tenant_a_id": tenant_a_id,
        "tenant_b_id": tenant_b_id,
        "owner_a_id": owner_a_id,
        "viewer_a_id": viewer_a_id,
        "owner_b_id": owner_b_id,
    }


def test_read_all_lifecycle_authorization_and_isolation(
    client: TestClient, seeded: dict, db_session: Session
):
    """read-all returns a reliable bounded response, persists read state, and stays scoped."""
    owner_a_headers = {"Authorization": f"Bearer {OWNER_A_KEY}"}
    viewer_a_headers = {"Authorization": f"Bearer {VIEWER_A_KEY}"}
    owner_b_headers = {"Authorization": f"Bearer {OWNER_B_KEY}"}

    # Owner A sees 55 personal + 2 broadcast unread notifications (57 total).
    before = client.get("/v1/notifications", headers=owner_a_headers)
    assert before.status_code == status.HTTP_200_OK
    assert before.json()["unread_count"] == OWNER_A_UNREAD_COUNT + 2

    # The regression: read-all must answer 200 with a plainly-bounded list
    # instead of failing on a FastAPI Query default bound as the page limit.
    read_all = client.post("/v1/notifications/read-all", headers=owner_a_headers)
    assert read_all.status_code == status.HTTP_200_OK
    payload = read_all.json()
    assert payload["unread_count"] == 0
    assert len(payload["items"]) == READ_ALL_PAGE_SIZE
    assert all(item["read_at"] is not None for item in payload["items"])

    # The read state is durable, and exactly viewer A's personal notification
    # remains unread inside tenant A.
    db = OwnerTestingSessionLocal()
    try:
        db.execute(text(f"SET app.current_tenant_id = '{seeded['tenant_a_id']}'"))
        remaining_unread = (
            db.query(Notification)
            .filter(Notification.tenant_id == seeded["tenant_a_id"], Notification.read_at.is_(None))
            .all()
        )
        assert [notification.title for notification in remaining_unread] == ["Viewer A personal unread"]
    finally:
        db.close()

    # Another user's notification is untouched by owner A's read-all.
    viewer_view = client.get("/v1/notifications", headers=viewer_a_headers)
    assert viewer_view.status_code == status.HTTP_200_OK
    assert viewer_view.json()["unread_count"] == 1

    # Another tenant's notification is untouched by owner A's read-all.
    tenant_b_view = client.get("/v1/notifications", headers=owner_b_headers)
    assert tenant_b_view.status_code == status.HTTP_200_OK
    assert tenant_b_view.json()["unread_count"] == 1

    # The viewer's own read-all only affects their personal notification.
    viewer_read_all = client.post("/v1/notifications/read-all", headers=viewer_a_headers)
    assert viewer_read_all.status_code == status.HTTP_200_OK
    assert viewer_read_all.json()["unread_count"] == 0
    tenant_b_view = client.get("/v1/notifications", headers=owner_b_headers)
    assert tenant_b_view.json()["unread_count"] == 1

    # Repeating read-all on an empty unread set stays reliable (200, no unread).
    repeat = client.post("/v1/notifications/read-all", headers=owner_a_headers)
    assert repeat.status_code == status.HTTP_200_OK
    assert repeat.json()["unread_count"] == 0
    unread_only_view = client.get(
        "/v1/notifications", params={"unread_only": "true"}, headers=owner_a_headers
    )
    assert unread_only_view.status_code == status.HTTP_200_OK
    assert unread_only_view.json()["items"] == []

    # Tenant B's read-all resolves its own notification only.
    tenant_b_read_all = client.post("/v1/notifications/read-all", headers=owner_b_headers)
    assert tenant_b_read_all.status_code == status.HTTP_200_OK
    assert tenant_b_read_all.json()["unread_count"] == 0


def test_finding_status_domain_and_terminal_dispositions(
    client: TestClient, seeded: dict, db_session: Session, monkeypatch
):
    """The API, service, audit trail, and database preserve one status domain."""
    finding_id = uuid4()
    db_session.execute(text(f"SET app.current_tenant_id = '{seeded['tenant_a_id']}'"))
    db_session.add(
        Finding(
            id=finding_id,
            tenant_id=seeded["tenant_a_id"],
            framework="SOC2",
            finding_key="SOC2|AUDIT_GAP|status-regression",
            title="Status regression finding",
            description="Synthetic regression fixture",
            severity="medium",
            status=FindingStatus.OPEN.value,
            finding_type="AUDIT_GAP",
            risk_score=4.0,
        )
    )
    db_session.commit()
    db_session.execute(text("SET app.current_tenant_id = ''"))

    audit_actions: list[str] = []
    monkeypatch.setattr(
        findings_service,
        "_emit_finding_audit",
        lambda _finding_id, _tenant_id, _framework, action: audit_actions.append(action),
    )
    headers = {"Authorization": f"Bearer {OWNER_A_KEY}"}
    expected_actions = {
        FindingStatus.RESOLVED: "FINDING_RESOLVED",
        FindingStatus.FALSE_POSITIVE: "FINDING_FALSE_POSITIVE",
        FindingStatus.ACCEPTED_RISK: "FINDING_ACCEPTED_RISK",
    }
    for disposition, expected_action in expected_actions.items():
        response = client.patch(
            f"/v1/findings/{finding_id}/status",
            headers=headers,
            json={"status": disposition.value.lower()},
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["status"] == disposition.value
        assert response.json()["resolved_at"] is not None
        assert audit_actions[-1] == expected_action

    invalid = client.patch(
        f"/v1/findings/{finding_id}/status",
        headers=headers,
        json={"status": "banana"},
    )
    assert invalid.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    db_session.execute(text(f"SET app.current_tenant_id = '{seeded['tenant_a_id']}'"))
    persisted = db_session.get(Finding, finding_id)
    assert persisted.status == FindingStatus.ACCEPTED_RISK.value
    with pytest.raises(ValueError):
        findings_service.update_status(
            db_session,
            tenant_id=str(seeded["tenant_a_id"]),
            finding_id=str(finding_id),
            status="banana",
        )
    with pytest.raises(IntegrityError):
        db_session.execute(
            text("UPDATE findings SET status = 'BANANA' WHERE id = :finding_id"),
            {"finding_id": finding_id},
        )
        db_session.commit()
    db_session.rollback()
    db_session.execute(text("SET app.current_tenant_id = ''"))

    reopened = client.patch(
        f"/v1/findings/{finding_id}/status",
        headers=headers,
        json={"status": "open"},
    )
    assert reopened.status_code == status.HTTP_200_OK
    assert reopened.json()["status"] == FindingStatus.OPEN.value
    assert reopened.json()["resolved_at"] is None

    summary = client.get("/v1/findings/summary/dashboard", headers=headers)
    assert summary.status_code == status.HTTP_200_OK
    assert summary.json()["open_findings"] == 1
    assert summary.json()["resolved_findings"] == 0

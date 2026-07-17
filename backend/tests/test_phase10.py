import uuid
import os
from datetime import datetime, timedelta, timezone

import pytest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException, status
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker, Session

from main import app
from app.db.dependencies import get_db
from app.db.models import Tenant, User, APIKey, PendingApproval, ApprovalAudit
from app.core.auth import hash_key
from app.api.v1.endpoints.workflows import _verify_mfa_if_enabled
from tests.db_safety import destructive_test_urls

owner_db_url, db_url = destructive_test_urls()
owner_engine = create_engine(owner_db_url, echo=False, poolclass=StaticPool)
engine = create_engine(db_url, echo=False, poolclass=StaticPool)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, expire_on_commit=False)


@pytest.fixture(scope="module")
def db_session() -> Session:
    """Create a clean database session and apply tables/RLS contexts"""
    from app.db.base import Base
    Base.metadata.create_all(bind=owner_engine)
    
    # Truncate tables before run
    with owner_engine.connect() as conn:
        conn.execute(text("TRUNCATE TABLE approval_audit, audit_log_metadata, pending_approvals, compliance_workflows, api_keys, users, tenants CASCADE;"))
        conn.commit()
        
    db = TestingSessionLocal()
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
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def _create_admin_tenant(db_session: Session, name: str, email: str, api_key_raw: str):
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()

    db_session.execute(text(f"SET app.current_tenant_id = '{tenant_id}'"))
    db_session.add(Tenant(id=tenant_id, name=name, tier="enterprise", status="active"))
    db_session.add(User(id=user_id, tenant_id=tenant_id, email=email, role="admin", is_active=True))
    db_session.flush()
    db_session.add(APIKey(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        key_hash=hash_key(api_key_raw),
        name=f"{name} Admin Key",
        scopes=["admin", "read", "write"],
        is_active=True,
        created_by=user_id,
    ))
    db_session.commit()
    db_session.execute(text("SET app.current_tenant_id = ''"))
    return tenant_id, user_id, {"Authorization": f"Bearer {api_key_raw}"}


def _create_workflow_approval(client: TestClient, headers: dict[str, str]):
    with patch("app.orchestrator.connectors.DocumentScanner.list_documents") as mock_list, \
         patch("app.orchestrator.connectors.DocumentScanner.fetch_and_extract_text") as mock_fetch, \
         patch("requests.post") as mock_post:
        mock_list.return_value = [{"object_key": "test-doc.txt", "file_name": "test-doc.txt", "size": 1024}]
        mock_fetch.return_value = "My email is jane@example.com"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"entity_type": "EMAIL_ADDRESS"}]
        mock_post.return_value = mock_resp
        response_wf = client.post("/v1/workflows", headers=headers, json={"framework": "HIPAA"})
    assert response_wf.status_code == status.HTTP_201_CREATED
    workflow_id = response_wf.json()["workflow_id"]
    assert response_wf.json()["current_state"] == "COMPLETE"

    response_remediate = client.post(f"/v1/workflows/{workflow_id}/remediate", headers=headers)
    assert response_remediate.status_code == status.HTTP_200_OK
    return workflow_id, response_remediate.json()["approval_id"]


def test_phase10_mfa_setup_and_verification(client: TestClient, db_session: Session):
    """Verify MFA registration, TOTP validation, backup codes validation, and ApprovalAudit."""
    tenant_id, user_id, headers = _create_admin_tenant(
        db_session,
        "Test Tenant D",
        "admin@tenantD.com",
        "system_admin_key_tenant_d",
    )

    response = client.post("/v1/workflows/mfa/setup", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    mfa_data = response.json()
    assert "mfa_secret" in mfa_data
    assert "provisioning_uri" in mfa_data
    assert len(mfa_data["backup_codes"]) == 5
    backup_codes = mfa_data["backup_codes"]

    workflow_id, approval_id = _create_workflow_approval(client, headers)

    response_no_mfa = client.post(f"/v1/workflows/{workflow_id}/approve", headers=headers)
    assert response_no_mfa.status_code == status.HTTP_400_BAD_REQUEST
    assert "MFA token required" in response_no_mfa.json()["detail"]

    response_bad_mfa = client.post(
        f"/v1/workflows/{workflow_id}/approve",
        headers=headers,
        json={"totp_code": "000000"}
    )
    assert response_bad_mfa.status_code == status.HTTP_400_BAD_REQUEST
    assert "Invalid MFA token" in response_bad_mfa.json()["detail"]

    backup_code_to_use = backup_codes[0]
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
        response_backup = client.post(
            f"/v1/workflows/{workflow_id}/approve",
            headers=headers,
            json={"totp_code": backup_code_to_use}
        )
    assert response_backup.status_code == status.HTTP_200_OK
    assert response_backup.json()["approval_status"] == "APPROVED"
    assert response_backup.json()["current_state"] == "COMPLETE"

    db_session.execute(text(f"SET app.current_tenant_id = '{tenant_id}'"))
    user_db = db_session.query(User).filter(User.id == user_id).first()
    assert backup_code_to_use not in user_db.mfa_backup_codes
    assert len(user_db.mfa_backup_codes) == 4

    audit = db_session.query(ApprovalAudit).filter(ApprovalAudit.approval_id == uuid.UUID(approval_id)).first()
    assert audit is not None
    assert audit.action == "APPROVED"
    assert audit.mfa_verified is True
    assert audit.actor_id == user_id
    db_session.execute(text("SET app.current_tenant_id = ''"))


def test_phase10_production_approval_requires_mfa_enrollment(monkeypatch):
    """No-MFA approvers are blocked only in production."""
    user = User(email="admin@example.com", role="admin", is_active=True, mfa_enabled=False)

    monkeypatch.setenv("AUTHCLAW_ENV", "production")
    with pytest.raises(HTTPException) as exc:
        _verify_mfa_if_enabled(user, request=None, body=None)
    assert exc.value.status_code == status.HTTP_403_FORBIDDEN
    assert "MFA enrollment required" in exc.value.detail

    monkeypatch.setenv("AUTHCLAW_ENV", "local")
    assert _verify_mfa_if_enabled(user, request=None, body=None) == (False, None)


def test_phase10_approval_expiration(client: TestClient, db_session: Session):
    """Verify that approvals expire after 30 minutes and are recorded in ApprovalAudit."""
    tenant_id, _, headers = _create_admin_tenant(
        db_session,
        "Test Tenant E",
        "admin@tenantE.com",
        "system_admin_key_tenant_e",
    )
    workflow_id, approval_id = _create_workflow_approval(client, headers)

    db_session.execute(text(f"SET app.current_tenant_id = '{tenant_id}'"))
    approval = db_session.query(PendingApproval).filter(PendingApproval.id == uuid.UUID(approval_id)).first()
    approval.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db_session.commit()
    db_session.execute(text("SET app.current_tenant_id = ''"))

    response_expire = client.post("/v1/workflows/approvals/expire-stale", headers=headers)
    assert response_expire.status_code == status.HTTP_200_OK
    assert response_expire.json()["expired_count"] == 1

    response_status = client.get(f"/v1/workflows/{workflow_id}", headers=headers)
    assert response_status.json()["approval_status"] == "EXPIRED"
    assert response_status.json()["execution_status"] == "COMPLETED"

    db_session.execute(text(f"SET app.current_tenant_id = '{tenant_id}'"))
    audit = db_session.query(ApprovalAudit).filter(
        ApprovalAudit.approval_id == uuid.UUID(approval_id),
        ApprovalAudit.action == "EXPIRED"
    ).first()
    assert audit is not None
    assert audit.mfa_verified is False
    db_session.execute(text("SET app.current_tenant_id = ''"))

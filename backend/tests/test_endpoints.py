import pytest
from fastapi.testclient import TestClient
from fastapi import status
from sqlalchemy import text, create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker, Session
import uuid
from uuid import uuid4, UUID
import os
import base64
from main import app

# Force fallback to PostgreSQL audit logs by unsetting CLICKHOUSE_HOST for endpoints test suite
os.environ.pop("CLICKHOUSE_HOST", None)

from app.db.dependencies import get_db
from app.db.models import Tenant, User, APIKey, Policy, GatewayConfig, RedactionToken, AuditLogMetadata
from app.core.auth import hash_key
from app.core.config import settings

# Force using authclaw_app (RLS-restricted user) for database interactions in tests.
owner_db_url = os.getenv("OWNER_DATABASE_URL", settings.DATABASE_URL)
app_user = os.getenv("POSTGRES_APP_USER", "authclaw_app")
app_password = os.getenv("POSTGRES_APP_PASSWORD", "authclaw_app")
db_url = settings.DATABASE_URL.replace("authclaw:authclaw@", f"{app_user}:{app_password}@")
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
        conn.execute(text("TRUNCATE TABLE audit_log_metadata, pending_approvals, redaction_tokens, gateway_configs, policies, api_keys, users, tenants CASCADE;"))
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


def test_public_health(client: TestClient):
    """Test public health check doesn't require auth"""
    response = client.get("/health")
    assert response.status_code == status.HTTP_200_OK
    health = response.json()
    assert health["status"] == "healthy"
    assert health["service"] == "authclaw-backend"
    assert "secret_management" in health

    # Verify OpenAPI documentation loads successfully
    openapi_resp = client.get("/openapi.json")
    assert openapi_resp.status_code == status.HTTP_200_OK
    assert "paths" in openapi_resp.json()

    docs_resp = client.get("/docs")
    assert docs_resp.status_code == status.HTTP_200_OK


def test_authentication_gates(client: TestClient):
    """Test secure routes block unauthenticated/mismatched requests"""
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
    assert "Invalid or expired API Key" in response.json()["detail"]


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

    # Seed Admin User & System API Key with 'admin' scope for Tenant A to call POST /tenants
    admin_user_id = uuid4()
    db_session.execute(text(f"SET app.current_tenant_id = '{tenant_a_id}'"))
    admin_user = User(id=admin_user_id, tenant_id=tenant_a_id, email="admin@tenantA.com", role="admin", is_active=True)
    db_session.add(admin_user)
    db_session.commit()

    admin_key = "system_admin_key_value"
    admin_hash = hash_key(admin_key)
    admin_api_key = APIKey(
        id=uuid4(),
        tenant_id=tenant_a_id,
        key_hash=admin_hash,
        name="Admin Key",
        scopes=["admin", "read", "write"],
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

    # Request as Tenant A admin (admin scope) -> 201 Created
    response = client.post("/v1/tenants", json={"name": "Tenant C", "tier": "pro"}, headers=headers_admin)
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
    # Seed a token value for Tenant A: plaintext is "John Doe", encrypted is "iv + encrypted"
    # To mock matching deterministic decryption in Go gateway, we'll use a valid encrypted token
    # Let's import the Go decryption key default "authclaw-default-32-byte-key-12"
    # Decrypting will be tested against the backend crypto decrypt logic.
    # We encrypt using Python's equivalent logic for test verification:
    from app.core.crypto import get_encryption_key
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    import hashlib

    # Deterministic Encryption Mock
    plaintext = "John Doe"
    key = get_encryption_key()
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext.encode("utf-8") + bytes([pad_len] * pad_len)
    
    h = hashlib.sha256()
    h.update(plaintext.encode("utf-8"))
    h.update(key)
    iv = h.digest()[:16]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    encrypted_base64 = base64.b64encode(iv + ciphertext).decode("utf-8")

    token_hash = hashlib.sha256("[REDACTED_PERSON_abc]".encode("utf-8")).hexdigest()
    
    # Save token in DB under Tenant A
    db_session.execute(text(f"SET app.current_tenant_id = '{tenant_a_id}'"))
    token_record = RedactionToken(
        id=uuid4(),
        tenant_id=tenant_a_id,
        original_value=encrypted_base64,
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
    db_session.commit()
    db_session.execute(text("SET app.current_tenant_id = ''"))

    headers = {"Authorization": f"Bearer {api_key_raw}"}

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

    mfa_setup = client.post("/v1/workflows/mfa/setup", headers=headers)
    assert mfa_setup.status_code == status.HTTP_200_OK
    backup_code = mfa_setup.json()["backup_codes"][0]

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
            headers=headers,
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
    assert db_app_final.status == "APPROVED"
    assert db_app_final.approved_at is not None
    assert db_app_final.approver_id == user_id
    db_session.execute(text("SET app.current_tenant_id = ''"))

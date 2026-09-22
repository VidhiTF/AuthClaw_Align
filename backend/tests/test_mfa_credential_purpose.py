"""Machine credentials cannot enroll or exercise an interactive MFA factor."""
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints import auth, users, workflows
from app.core.auth import revalidate_tenant_credential


@pytest.mark.parametrize("kind", ["api_key", "platform_session", None])
@pytest.mark.parametrize("operation", ["setup", "confirm", "disable", "rotate", "reset", "assertion"])
def test_mfa_rejects_noninteractive_credentials_before_database_access(kind, operation):
    request = SimpleNamespace(state=SimpleNamespace(
        credential_kind=kind, tenant_id=uuid4(), user_id=uuid4()), headers={})
    db = MagicMock()
    db.query.return_value.filter.return_value.with_for_update.return_value.first.return_value = None
    db.query.return_value.filter.return_value.order_by.return_value.with_for_update.return_value.all.return_value = []
    calls = {
        "setup": lambda: users.setup_my_mfa(request, None, db),
        "confirm": lambda: users.confirm_my_mfa(users.MFAConfirmRequest(code="654321"), request, db),
        "disable": lambda: users.disable_my_mfa(users.MFADisableRequest(code="654321"), request, db),
        "rotate": lambda: users.regenerate_my_mfa_recovery_codes(users.MFADisableRequest(code="654321"), request, db),
        "reset": lambda: users.reset_user_mfa(uuid4(), users.MFAAdminResetRequest(code="654321"), request, db),
        "assertion": lambda: auth.create_agent_mfa_assertion(auth.AgentMFAAssertionRequest(
            code="654321", method="POST", path="/approve/test", body_sha256="a" * 64), request, db),
    }
    with pytest.raises(HTTPException) as denied:
        calls[operation]()
    assert denied.value.status_code == 403
    assert denied.value.detail == "Interactive tenant session required"
    db.query.assert_not_called()
    db.execute.assert_not_called()
    db.commit.assert_not_called()


@pytest.mark.parametrize("kind", ["session", "api_key"])
@pytest.mark.parametrize("mismatch", ["none", "tenant", "user", "revoked"])
def test_revalidation_binds_same_canonical_actor_and_tenant(kind, mismatch):
    tenant_id, user_id = uuid4(), uuid4()
    request = SimpleNamespace(state=SimpleNamespace(
        credential_kind=kind, credential_hash="test-hash", tenant_id=tenant_id, user_id=user_id))
    db = MagicMock()
    db.execute.return_value.first.return_value = None if mismatch == "revoked" else SimpleNamespace(
        tenant_id=uuid4() if mismatch == "tenant" else tenant_id,
        user_id=uuid4() if mismatch == "user" else user_id)
    if mismatch == "none":
        revalidate_tenant_credential(request, db)
        db.rollback.assert_not_called()
    else:
        with pytest.raises(HTTPException) as denied:
            revalidate_tenant_credential(request, db)
        assert denied.value.status_code == 401
        db.rollback.assert_called_once()


@pytest.mark.parametrize("headers", [
    {"authorization": "Bearer api-key-value"},
    {"x-api-key": "api-key-value"},
    {"authorization": "Bearer api-key-value", "x-api-key": "alternate"},
])
@pytest.mark.parametrize("operation", ["gateway", "remediation"])
def test_human_approval_endpoints_reject_api_keys_before_database_access(headers, operation):
    request = SimpleNamespace(
        state=SimpleNamespace(
            credential_kind="api_key", tenant_id=uuid4(), user_id=uuid4()
        ),
        headers=headers,
    )
    db = MagicMock()
    if operation == "gateway":
        call = lambda: workflows.approve_gateway_approval(
            str(uuid4()), request, None, db
        )
    else:
        call = lambda: workflows.approve_workflow(str(uuid4()), request, None, db)

    with pytest.raises(HTTPException) as denied:
        call()

    assert denied.value.status_code == 403
    assert denied.value.detail == "Interactive tenant session required"
    db.query.assert_not_called()
    db.execute.assert_not_called()
    db.commit.assert_not_called()

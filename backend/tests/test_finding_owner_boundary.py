"""Finding owners must be active users visible inside the finding's tenant."""

import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.api.v1.endpoints import findings
from app.services import findings_service


@pytest.fixture
def owner_case(monkeypatch):
    finding = SimpleNamespace(owner_user_id=None, updated_at=None)
    monkeypatch.setattr(findings_service, "get_finding", lambda *args, **kwargs: finding)
    return MagicMock(), finding, str(uuid.uuid4()), str(uuid.uuid4())


def test_unavailable_owner_cannot_be_assigned(owner_case):
    db, finding, tenant_id, owner_id = owner_case
    db.query.return_value.filter.return_value.first.return_value = None

    with pytest.raises(ValueError, match="owner"):
        findings_service.assign_owner(db, tenant_id=tenant_id, finding_id=str(uuid.uuid4()), owner_user_id=owner_id)

    assert finding.owner_user_id is None
    db.commit.assert_not_called()


def test_owner_lookup_requires_matching_tenant_and_active_user(owner_case):
    db, finding, tenant_id, owner_id = owner_case
    db.query.return_value.filter.return_value.first.return_value = SimpleNamespace(id=uuid.UUID(owner_id))

    findings_service.assign_owner(db, tenant_id=tenant_id, finding_id=str(uuid.uuid4()), owner_user_id=owner_id)

    predicates = db.query.return_value.filter.call_args.args
    sql = " AND ".join(str(predicate) for predicate in predicates)
    params = {key: value for predicate in predicates for key, value in predicate.compile().params.items()}
    assert "users.tenant_id" in sql
    assert "users.is_active" in sql
    assert uuid.UUID(tenant_id) in params.values()
    assert uuid.UUID(owner_id) in params.values()
    assert finding.owner_user_id == uuid.UUID(owner_id)


def test_unassignment_remains_supported(owner_case):
    db, finding, tenant_id, owner_id = owner_case
    finding.owner_user_id = uuid.UUID(owner_id)
    findings_service.assign_owner(db, tenant_id=tenant_id, finding_id=str(uuid.uuid4()), owner_user_id=None)
    assert finding.owner_user_id is None
    db.query.assert_not_called()


def test_request_rejects_malformed_owner_uuid():
    with pytest.raises(ValidationError):
        findings.AssignOwnerRequest(owner_user_id="invalid-uuid")


def test_assignment_endpoint_returns_generic_client_error(monkeypatch):
    def unavailable(*args, **kwargs):
        raise ValueError("Invalid or unavailable owner")

    monkeypatch.setattr(findings_service, "assign_owner", unavailable)
    with pytest.raises(HTTPException) as exc:
        findings.assign_owner(str(uuid.uuid4()), findings.AssignOwnerRequest(owner_user_id=str(uuid.uuid4())), MagicMock(), str(uuid.uuid4()))
    assert exc.value.status_code == 400
    assert exc.value.detail == "Invalid or unavailable owner"

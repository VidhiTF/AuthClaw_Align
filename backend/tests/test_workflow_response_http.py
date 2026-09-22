"""Real workflow routes and SQLite persistence; PostgreSQL RLS is tested separately.

Identity injection, MFA, throttling, notifications and graph execution are test
boundaries. Tenant filters, approval binding, commits and serialization run here.
"""

from contextlib import nullcontext
from copy import deepcopy
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import ARRAY, create_engine
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.v1.endpoints import workflows
from app.core.auth import get_tenant_db
from app.db.models import ApprovalAudit, ComplianceWorkflow, EvidenceRecord, Finding, PendingApproval, Policy, Tenant, User
from app.orchestrator import runner
from app.orchestrator.connectors import DocumentScanner
from app.services import findings_service, red_team
from tests.test_acl18_remediation_approval import _plan
from tests.test_workflow_response_contract import FIELDS, historical_verification_failure, workflow


@compiles(ARRAY, "sqlite")
def sqlite_array(_type, _compiler, **_kw):
    return "JSON"


@pytest.fixture
def api(monkeypatch):
    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    for model in (Tenant, User, PendingApproval, ComplianceWorkflow, ApprovalAudit, Policy, EvidenceRecord, Finding):
        model.__table__.create(engine)
    tenant, user = uuid4(), uuid4()
    reviewer_id = uuid4()
    payload = workflow(
        findings=[{"control": "doc", "evidence": "Entities: EMAIL_ADDRESS", "entity_count": 1}],
        remediation_plan=_plan(),
        remediation_actions=[],
        execution_result={},
        rollback_result={},
    )
    payload["tenant_id"] = str(tenant)
    payload["requester_id"] = str(user)
    with Session(engine) as db:
        db.add(Tenant(id=tenant, name="contract-test"))
        db.add(
            User(id=user, tenant_id=tenant, email="reviewer@example.invalid", role="admin", is_active=True)
        )
        db.add(User(id=reviewer_id, tenant_id=tenant, email="separate-reviewer@example.invalid",
                    role="admin", is_active=True))
        db.add(
            ComplianceWorkflow(
                id=uuid4(),
                tenant_id=tenant,
                workflow_id=payload["workflow_id"],
                framework="HIPAA",
                current_state="COMPLETE",
                execution_status="COMPLETED",
                findings=payload["findings"],
                remediation_plan=payload["remediation_plan"],
                execution_result={},
                state_data=deepcopy(payload),
            )
        )
        db.commit()
    identity = dict(
        tenant_id=tenant,
        user_id=user,
        user_role="admin",
        scopes=["admin"],
        credential_kind="session",
        credential_hash="workflow-response-session",
    )
    app = FastAPI()

    @app.middleware("http")
    async def identify(request, call_next):
        for key, value in identity.items():
            setattr(request.state, key, value)
        return await call_next(request)

    def database():
        with Session(engine) as db:
            yield db

    app.dependency_overrides[get_tenant_db] = database
    app.include_router(workflows.router, prefix="/v1/workflows")
    app.include_router(workflows.router, prefix="/api/v1/workflows", include_in_schema=False)
    monkeypatch.setattr(workflows, "check_worker_throttle", lambda *_args, **_kw: (True, 0))
    monkeypatch.setattr(workflows, "create_notification", lambda *_args, **_kw: None)
    # Exact credential revocation is exercised against PostgreSQL in
    # test_t10_postgres; this SQLite contract fixture has no authn schema.
    monkeypatch.setattr(
        workflows,
        "revalidate_tenant_credential",
        lambda *_args: SimpleNamespace(role="admin", scopes=["admin"]),
    )
    monkeypatch.setattr(
        workflows, "_verify_mfa_if_enabled", lambda *_args, **_kw: (True, datetime.now(timezone.utc))
    )
    monkeypatch.setattr(runner, "emit_audit_event", lambda *_args, **_kw: None)
    monkeypatch.setattr(runner, "workflow_advisory_lock", lambda *_args: nullcontext())
    with TestClient(app, raise_server_exceptions=False) as client:
        yield SimpleNamespace(client=client, engine=engine, identity=identity, payload=payload,
                              reviewer_id=reviewer_id)
    engine.dispose()


OPERATIONS = ("create", "list", "get", "resume", "approve", "reject", "remediate")


def request_operation(api, prefix, operation):
    url = f"{prefix}/workflows"
    if operation == "create":
        return api.client.post(url, json={"framework": "HIPAA"})
    if operation == "list":
        return api.client.get(url)
    url += "/" + api.payload["workflow_id"]
    return api.client.get(url) if operation == "get" else api.client.post(url + "/" + operation)


@pytest.mark.parametrize("prefix", ["/v1", "/api/v1"])
@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("invalid", [False, True])
def test_route_contract_and_sanitized_post_commit_errors(
    api, monkeypatch, caplog, prefix, operation, invalid
):
    if operation in {"approve", "reject"}:
        assert request_operation(api, prefix, "remediate").status_code == 200
        api.identity["user_id"] = api.reviewer_id
    payload = deepcopy(api.payload)
    if invalid:
        payload["findings"] = [{"entity_count": "private-marker"}]
        with Session(api.engine) as db:
            row = db.query(ComplianceWorkflow).one()
            row.findings = payload["findings"]
            db.commit()
    execution = Mock(return_value=payload)
    monkeypatch.setattr(runner.ComplianceWorkflowRunner, "start", execution)
    monkeypatch.setattr(runner.ComplianceWorkflowRunner, "resume", execution)
    response = request_operation(api, prefix, operation)
    if invalid:
        assert response.status_code == 500, response.text
        assert response.json() == {"detail": "Internal server error"}
        assert "private-marker" not in caplog.text + response.text
        assert "Workflow response contract validation failed" in caplog.text
    else:
        assert response.status_code == (201 if operation == "create" else 200), response.text
        result = response.json()[0] if operation == "list" else response.json()
        if operation in {"create", "resume", "approve", "reject"}:
            expected = payload
        else:
            with Session(api.engine) as db:
                expected = runner.ComplianceWorkflowRunner(db).get_status(
                    payload["workflow_id"], payload["tenant_id"]
                )
        for field in FIELDS:
            assert result[field] == expected[field]
    if operation in {"create", "resume", "approve", "reject"}:
        assert execution.call_count == 1  # Serialization must never retry execution.
    if operation in {"approve", "reject", "remediate"}:
        with Session(api.engine) as db:
            approval = db.query(PendingApproval).one()
            assert (
                approval.status
                == {"approve": "APPROVED", "reject": "REJECTED", "remediate": "PENDING"}[operation]
            )
            assert db.query(ApprovalAudit).count() == (0 if operation == "remediate" else 1)


@pytest.mark.parametrize("prefix", ["/v1", "/api/v1"])
@pytest.mark.parametrize("snapshot_actions", [False, True])
def test_persisted_historical_verification_failure_is_readable(
    api, historical_verification_failure, prefix, snapshot_actions, caplog
):
    actions = [{"id": "action-1", "status": "FAILED", "result": historical_verification_failure}]
    execution_result = {"details": [historical_verification_failure], "actions": actions}
    state_data = {"remediation_actions": actions} if snapshot_actions else {}
    with Session(api.engine) as db:
        row = db.query(ComplianceWorkflow).one()
        row.execution_result, row.state_data = execution_result, state_data
        db.commit()
    for operation in ("get", "list"):
        response = request_operation(api, prefix, operation)
        assert response.status_code == 200, response.text
        body = response.json()[0] if operation == "list" else response.json()
        assert body["execution_result"] == execution_result
        assert body["remediation_actions"] == actions
    with Session(api.engine) as db:
        row = db.query(ComplianceWorkflow).one()
        assert row.execution_result == execution_result
        assert row.state_data == state_data
    assert "verification read unavailable" not in caplog.text


def test_status_snapshot_fallback_and_malformed_list_row(api):
    with Session(api.engine) as db:
        row = db.query(ComplianceWorkflow).one()
        row.state_data = {"remediation_actions": [], "rollback_result": {}}
        row.execution_result = {
            "actions": [{"id": "legacy", "status": "SUCCEEDED"}],
            "remediation_state": "SUCCEEDED",
        }
        db.commit()
    result = request_operation(api, "/v1", "get").json()
    assert result["remediation_actions"] == [{"id": "legacy", "status": "SUCCEEDED"}]
    assert result["rollback_result"] == {}
    with Session(api.engine) as db:
        db.add(
            ComplianceWorkflow(
                id=uuid4(),
                tenant_id=api.identity["tenant_id"],
                workflow_id=str(uuid4()),
                framework="HIPAA",
                current_state="COMPLETE",
                execution_status="COMPLETED",
                findings=["malformed"],
            )
        )
        db.commit()
    response = request_operation(api, "/v1", "list")
    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}


@pytest.mark.parametrize("operation", OPERATIONS)
def test_missing_scope_is_denied_before_execution(api, operation):
    api.identity["scopes"] = []
    assert request_operation(api, "/v1", operation).status_code == 403


@pytest.mark.parametrize("operation", ["list", "get", "resume", "approve", "reject", "remediate"])
def test_other_tenant_cannot_read_or_change_workflow(api, operation):
    api.identity["tenant_id"] = uuid4()
    response = request_operation(api, "/v1", operation)
    assert response.status_code == (200 if operation == "list" else 404), response.text
    if operation == "list":
        assert response.json() == []
    with Session(api.engine) as db:
        assert db.query(ComplianceWorkflow).one().execution_status == "COMPLETED"
        assert db.query(PendingApproval).count() == 0


def test_fresh_mfa_denial_still_precedes_approval(api, monkeypatch):
    assert request_operation(api, "/v1", "remediate").status_code == 200
    api.identity["user_id"] = api.reviewer_id
    monkeypatch.setattr(workflows, "_verify_mfa_if_enabled", lambda *_args, **_kw: (False, None))
    assert request_operation(api, "/v1", "approve").status_code == 403
    with Session(api.engine) as db:
        assert db.query(PendingApproval).one().status == "PENDING"


def test_missing_workflow_on_resume_keeps_404(api):
    api.payload["workflow_id"] = str(uuid4())
    assert request_operation(api, "/v1", "resume").status_code == 404


@pytest.mark.parametrize("prefix", ["/v1", "/api/v1"])
@pytest.mark.parametrize("refused", [False, True])
def test_all_workflow_producers_remain_readable(api, monkeypatch, prefix, refused):
    # Run both production writers; only external scanner, audit and metric I/O is isolated.
    monkeypatch.setattr(DocumentScanner, "list_documents", lambda *_: [])
    monkeypatch.setattr(findings_service, "_emit_finding_audit", lambda *_: None)
    monkeypatch.setattr(red_team.event_backbone, "increment_metric", lambda *_: None)
    responses = {probe["id"]: "Sorry, I cannot do that." for probe in red_team.PROBES} if refused else {}
    tenant_id = str(api.identity["tenant_id"])
    with Session(api.engine) as db:
        compliance = runner.ComplianceWorkflowRunner(db).start(
            tenant_id, "GDPR", requester_id=str(api.identity["user_id"]))
        produced = red_team.run(db, tenant_id, responses)
        red_id = produced["run"]["workflow_id"]
        row = db.query(ComplianceWorkflow).filter_by(workflow_id=red_id).one()
        expected = {key: deepcopy(getattr(row, key)) for key in ("findings", "remediation_plan", "execution_result")}
        assert db.query(EvidenceRecord).filter_by(workflow_id=red_id).count() == len(red_team.PROBES)
        assert db.query(Finding).filter_by(workflow_id=red_id).count() == (0 if refused else len(red_team.PROBES))
    listing = api.client.get(f"{prefix}/workflows")
    assert listing.status_code == 200, listing.text
    by_id = {item["workflow_id"]: item for item in listing.json()}
    assert set(by_id) == {api.payload["workflow_id"], compliance["workflow_id"], red_id}
    detail = api.client.get(f"{prefix}/workflows/{red_id}")
    assert detail.status_code == 200, detail.text
    assert detail.json() == by_id[red_id]
    for key, value in expected.items():
        assert detail.json()[key] == value
    with Session(api.engine) as db:
        row = db.query(ComplianceWorkflow).filter_by(workflow_id=red_id).one()
        assert {key: getattr(row, key) for key in expected} == expected
    api.identity["tenant_id"] = uuid4()
    assert api.client.get(f"{prefix}/workflows").json() == []
    assert api.client.get(f"{prefix}/workflows/{red_id}").status_code == 404

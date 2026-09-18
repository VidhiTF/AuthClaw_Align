from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4
import pytest
import yaml
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from app.api.v1.endpoints import chat, policies, workflows
from app.core.auth import get_tenant_db
from app.services.policy_engine import PolicyValidationError, simulate_policy, validate_policy_yaml


def policy(pattern):
    return yaml.safe_dump({"regex_rules": [{"pattern": pattern, "action": "block", "reason": "test"}]})


@pytest.mark.parametrize("pattern", [r"(?<=prefix)secret", r"(a)\1", r"\C"])
def test_policy_rejects_patterns_unsupported_by_gateway(pattern):
    with pytest.raises(PolicyValidationError):
        validate_policy_yaml(policy(pattern))


def test_nested_quantifiers_have_linear_matching_and_literal_escape_is_supported():
    assert simulate_policy(policy("(a+)+$"), model="test", prompts=["a" * 60000 + "!"]).decision == "allow"
    assert simulate_policy(policy(r"\\C"), model="test", prompts=[r"\C"]).decision == "block"


@pytest.mark.parametrize("prompts", [["a"] * 101, ["a" * 65537]])
def test_simulation_rejects_excessive_input(prompts):
    with pytest.raises(PolicyValidationError, match="budget"):
        simulate_policy(policy("a"), model="test", prompts=prompts)


@pytest.mark.parametrize("prompts", [["a"] * 101, ["a" * 65537]])
def test_simulation_route_returns_client_error_for_input_budget(prompts):
    app = FastAPI()
    app.include_router(policies.router, prefix="/policies")
    app.dependency_overrides[get_tenant_db] = lambda: MagicMock()

    @app.middleware("http")
    async def authenticate(request, call_next):
        request.state.tenant_id = uuid4()
        request.state.scopes = ["read"]
        return await call_next(request)

    with TestClient(app) as client:
        response = client.post("/policies/simulate", json={"policy_yaml": policy("a"), "model": "test", "prompts": prompts})
    assert response.status_code == 400
    assert "budget" in response.json()["detail"]["errors"][0]["message"]


@pytest.mark.parametrize("message", ["run GDPR scan", f"apply remediation {uuid4()}"])
def test_chat_uses_workflow_throttle_and_propagates_429(monkeypatch, message):
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = SimpleNamespace(
        title="Test",
        tier="starter",
        execution_status="COMPLETED",
        remediation_plan=[{"action": "redact"}],
        state_data={"requester_id": str(uuid4())},
    )
    request = SimpleNamespace(state=SimpleNamespace(tenant_id=uuid4(), user_id=uuid4()))
    calls = []
    monkeypatch.setattr(workflows, "check_worker_throttle", lambda tenant, job, **kwargs: (calls.append(job) or False, 30))
    with pytest.raises(HTTPException) as failure:
        chat.post_message(uuid4(), chat.MessageCreateRequest(message=message), request, db)
    assert failure.value.status_code == 429
    assert calls == ["scan" if message.startswith("run") else "remediation"]


@pytest.fixture(params=[("create_workflow", "run GDPR scan", "the scan"),
                        ("remediate_workflow", f"apply remediation {uuid4()}", "remediation")])
def chat_case(request):
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = SimpleNamespace(title="Test")
    caller = SimpleNamespace(state=SimpleNamespace(tenant_id=uuid4(), user_id=uuid4()))
    name, message, operation = request.param
    return name, db, lambda: chat.post_message(uuid4(), chat.MessageCreateRequest(message=message), caller, db), f"Unable to start {operation}. Please try again later."


@pytest.mark.parametrize("error", [RuntimeError("secret-token=synthetic-provider-key"), OSError("private/path/internal.sql")])
def test_chat_internal_errors_are_logged_but_not_returned_or_persisted(chat_case, monkeypatch, caplog, error):
    name, db, post, generic = chat_case
    monkeypatch.setattr(chat, name, MagicMock(side_effect=error))
    with caplog.at_level("ERROR", logger="api.chat"):
        response = post()
    assert response["text"] == generic and response["results"] is None
    saved = [call.args[0] for call in db.add.call_args_list if call.args[0].sender == "agent"]
    assert len(saved) == 1 and saved[0].text == generic and saved[0].results is None
    assert str(error) in caplog.text and any(record.exc_info for record in caplog.records)


@pytest.mark.parametrize("status", [400, 403, 404, 429, 500, 503])
def test_chat_preserves_client_errors_and_sanitizes_server_errors(chat_case, monkeypatch, status):
    name, db, post, generic = chat_case
    error = HTTPException(status, "synthetic internal detail" if status >= 500 else "Request rejected", headers={"Retry-After": "30"})
    monkeypatch.setattr(chat, name, MagicMock(side_effect=error))
    with pytest.raises(HTTPException) as caught:
        post()
    assert caught.value.status_code == status
    if status >= 500:
        assert caught.value.detail == generic and caught.value.headers is None
    else:
        assert caught.value is error
    assert all(call.args[0].sender == "user" for call in db.add.call_args_list)


def test_chat_scan_sanitizes_actual_workflow_wrapper(monkeypatch):
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = SimpleNamespace(title="Test", tier="starter")
    monkeypatch.setattr(workflows, "check_worker_throttle", lambda *args, **kwargs: (True, 0))
    monkeypatch.setattr(workflows, "ComplianceWorkflowRunner", MagicMock(side_effect=RuntimeError("private database details")))
    with pytest.raises(HTTPException) as caught:
        chat.post_message(uuid4(), chat.MessageCreateRequest(message="run GDPR scan"), SimpleNamespace(state=SimpleNamespace(tenant_id=uuid4())), db)
    assert caught.value.status_code == 500
    assert caught.value.detail == "Unable to start the scan. Please try again later."


def test_chat_success_retains_results_and_history(chat_case, monkeypatch):
    name, db, post, _ = chat_case
    payload = {"workflow_id": str(uuid4()), "current_state": "RUNNING"}
    monkeypatch.setattr(chat, name, MagicMock(return_value=SimpleNamespace(model_dump=lambda **kwargs: payload)))
    response = post()
    assert response["results"] == payload and "Unable" not in response["text"]
    assert db.add.call_args.args[0].text == response["text"]
    assert db.add.call_args.args[0].results == payload

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
        tier="starter", execution_status="COMPLETED", remediation_plan=[{"action": "redact"}],
    )
    request = SimpleNamespace(state=SimpleNamespace(tenant_id=uuid4(), user_id=uuid4()))
    calls = []
    monkeypatch.setattr(workflows, "check_worker_throttle", lambda tenant, job, **kwargs: (calls.append(job) or False, 30))
    with pytest.raises(HTTPException) as failure:
        chat.post_message(uuid4(), chat.MessageCreateRequest(message=message), request, db)
    assert failure.value.status_code == 429
    assert calls == ["scan" if message.startswith("run") else "remediation"]

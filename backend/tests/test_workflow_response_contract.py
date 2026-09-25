"""Workflow wire contracts; fake S3 exercises the real graph/connector producers."""

import ast
import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import TypeAdapter, ValidationError

from app.api.v1.endpoints import workflows
from app.orchestrator import graph
from app.orchestrator.connectors import DocumentScanner
from app.orchestrator.remediation_state import upgrade_mutation_state
from app.services.remediation_approval import build_action_payload, compute_action_hash
from app.services import red_team
from tests.test_remediation_connector import FakeS3
from tests.test_remediation_failure_rollback import VerificationMismatchS3, VerificationReadFailureS3
from tests.test_s3_remediation_recovery import CrashAfterTargetWriteS3

FIELDS = ("findings", "remediation_plan", "remediation_actions", "execution_result", "rollback_result")


def test_workflow_writer_inventory_matches_producer_coverage():
    # New ORM producers must join test_all_workflow_producers_remain_readable.
    app_root = Path(__file__).resolve().parents[1] / "app"
    writers = set()
    for path in app_root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = {"ComplianceWorkflow"}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "app.db.models":
                names.update(alias.asname or alias.name for alias in node.names if alias.name == "ComplianceWorkflow")
        if any(isinstance(node, ast.Call) and (
            isinstance(node.func, ast.Name) and node.func.id in names
            or isinstance(node.func, ast.Attribute) and node.func.attr == "ComplianceWorkflow"
        ) for node in ast.walk(tree)):
            writers.add(path.relative_to(app_root).as_posix())
    assert writers == {"orchestrator/runner.py", "services/red_team.py"}


def workflow(**overrides):
    return dict(
        workflow_id=str(uuid4()),
        tenant_id=str(uuid4()),
        framework="HIPAA",
        current_state="COMPLETE",
        execution_status="COMPLETED",
        **overrides,
    )


def assert_round_trip(payload):
    original = deepcopy(payload)
    response = workflows.WorkflowResponse(**payload)
    app = FastAPI()

    @app.get("/probe", response_model=workflows.WorkflowResponse)
    def probe():
        return response

    with TestClient(app) as client:
        result = client.get("/probe")
    assert result.status_code == 200, result.text
    for key in FIELDS:
        assert result.json()[key] == payload.get(key)
    assert payload == original
    # Top-level defaults are still emitted, unlike a global exclude_unset change.
    assert result.json()["retry_count"] == payload.get("retry_count", 0)
    assert "completed_at" in result.json()
    return result.json()


@pytest.mark.parametrize(
    "values",
    [
        {},
        dict.fromkeys(FIELDS),
        {
            "findings": [],
            "remediation_plan": [],
            "remediation_actions": [],
            "execution_result": {},
            "rollback_result": {},
        },
        {
            "findings": [{"control": "old", "evidence": "Clean scan"}],
            "remediation_plan": [{"action": "Legacy plan", "target": {}, "diff": {}}],
            "remediation_actions": [{"id": "old", "result": None, "rollback_result": {}}],
            "execution_result": {"details": [{}]},
            "rollback_result": {"details": [{}]},
        },
    ],
)
def test_sparse_null_and_empty_payloads_preserve_wire_shape(values):
    assert_round_trip(workflow(**values))


@pytest.mark.parametrize(
    "status", ["PENDING", "RUNNING", "SUCCEEDED", "FAILED", "ROLLED_BACK", "ROLLBACK_FAILED"]
)
def test_legacy_mutation_state_remains_readable(status):
    state = upgrade_mutation_state("workflow-1", "action-1", {"status": status})
    assert_round_trip(workflow(remediation_actions=[{"status": status, "mutation_state": state}]))


@pytest.fixture
def historical_verification_failure():
    # Captured from e483d13's DocumentScanner.execute_remediation with the existing
    # VerificationReadFailureS3 fake, authclaw-test bucket, workflow-1/action-1,
    # and build_remediation_plan('tenant-a/doc.txt', 'Entities: EMAIL_ADDRESS, PHONE_NUMBER').
    return json.loads(
        (Path(__file__).parent / "fixtures/workflow_verification_failure_e483d13.json").read_text(encoding="utf-8")
    )


def test_historical_verification_failure_preserves_wire_shape(historical_verification_failure):
    result = historical_verification_failure
    action = {"id": "action-1", "status": "FAILED", "result": result}
    assert_round_trip(
        workflow(remediation_actions=[action], execution_result={"details": [result], "actions": [action]})
    )


@pytest.fixture
def scanner(monkeypatch):
    monkeypatch.setenv("AWS_ENABLED", "false")
    scanner = DocumentScanner()
    scanner.bucket = "authclaw-test"
    scanner.s3_client = FakeS3()
    monkeypatch.setattr("app.orchestrator.connectors.DocumentScanner", lambda: scanner)
    return scanner


@pytest.mark.parametrize("failure", [None, "apply", "partial", "rollback"])
def test_graph_lifecycle_payloads_and_approval_binding(scanner, monkeypatch, failure):
    monkeypatch.setattr(
        scanner,
        "list_documents",
        lambda _tenant: [
            {"object_key": "tenant-a/doc.txt", "file_name": "doc.txt"},
        ],
    )

    class Analysis:
        status_code = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def json(self):
            return [{"entity_type": "EMAIL_ADDRESS"}]

    monkeypatch.setattr("requests.Session.post", lambda *args, **kwargs: Analysis())
    state = workflow(
        findings=[], remediation_plan=[], remediation_actions=[], execution_result={}, rollback_result={}
    )
    for node in (graph.gather_evidence, graph.analyze_compliance, graph.generate_remediation_plan):
        state = node(state)
        assert_round_trip(state)
    plan = state["remediation_plan"]
    expires = datetime(2030, 1, 1, tzinfo=timezone.utc)
    before = compute_action_hash(
        tenant_id=state["tenant_id"],
        action_payload=build_action_payload(state["workflow_id"], plan),
        expires_at=expires,
    )
    serialized = assert_round_trip(state)
    after = compute_action_hash(
        tenant_id=state["tenant_id"],
        action_payload=build_action_payload(state["workflow_id"], serialized["remediation_plan"]),
        expires_at=expires,
    )
    assert before == after
    state["_create_approval"] = lambda *_: str(uuid4())
    state = graph.awaiting_approval(state)
    assert_round_trip(state)
    state["_check_approval"] = lambda *_: "APPROVED"
    state = graph.awaiting_approval(state)
    snapshots = []
    state["_persist_state"] = lambda value: snapshots.append(
        deepcopy({k: v for k, v in value.items() if not k.startswith("_")})
    )
    if failure:
        bad = deepcopy(plan[0])
        bad["target"]["bucket"] = "wrong-bucket"
        state["remediation_plan"] = [bad] if failure == "apply" else [*plan, bad]
    if failure == "rollback":

        def fail_rollback(_plan):
            raise RuntimeError("rollback unavailable")

        monkeypatch.setattr(scanner, "rollback_remediation", fail_rollback)
    for _ in range(5):
        state = graph.execute_remediation(state)
        assert_round_trip(state)
        state = graph.verify_results(state)
        assert_round_trip(state)
        if state["current_state"] != "EXECUTE_REMEDIATION":
            break
    if state["current_state"] == "ROLLBACK_REMEDIATION":
        state = graph.rollback_remediation(state)
    assert (
        state["remediation_state"]
        == {None: "SUCCEEDED", "apply": "FAILED", "partial": "ROLLED_BACK", "rollback": "ROLLBACK_FAILED"}[
            failure
        ]
    )
    assert_round_trip(state)
    for snapshot in snapshots:
        assert_round_trip(snapshot)


def test_crash_recovery_payloads(scanner):
    scanner.s3_client = CrashAfterTargetWriteS3()
    plan = scanner.build_remediation_plan("tenant-a/doc.txt", "EMAIL_ADDRESS")
    prepared = scanner.prepare_remediation("w", "a", plan)
    prepared["phase"] = "APPLYING"
    assert_round_trip(workflow(remediation_actions=[{"mutation_state": prepared}]))
    with pytest.raises(SystemExit):
        scanner.apply_prepared_remediation(prepared, plan)
    resumed = scanner.prepare_remediation("w", "a", plan, prepared)
    result = scanner.apply_prepared_remediation(resumed, plan)
    assert result["mutation_state"]["mutation"]["reconciled"] is True
    assert_round_trip(workflow(execution_result={"details": [result]}))


def test_unversioned_s3_object_preserves_null_version_ids(scanner):
    scanner.s3_client.objects["tenant-a/doc.txt"].pop("VersionId")
    plan = scanner.build_remediation_plan("tenant-a/doc.txt", "EMAIL_ADDRESS")
    result = scanner.execute_remediation("w", "a", plan)
    assert result["rollback_ref"]["before_version_id"] is None
    assert result["mutation_state"]["original"]["version_id"] is None
    assert_round_trip(workflow(execution_result={"details": [result]}))


@pytest.mark.parametrize("s3_type", [VerificationMismatchS3, VerificationReadFailureS3])
def test_post_mutation_failure_keeps_recoverable_response(scanner, s3_type):
    scanner.s3_client = s3_type()
    original = scanner.s3_client.objects["tenant-a/doc.txt"]["Body"]
    plan = scanner.build_remediation_plan("tenant-a/doc.txt", "EMAIL_ADDRESS")
    state = graph.execute_remediation(
        workflow(remediation_plan=[{"finding_control": "tenant-a/doc.txt", **plan}])
    )
    assert_round_trip(state)
    state = graph.verify_results(state)
    assert state["current_state"] == "ROLLBACK_REMEDIATION"
    state = graph.rollback_remediation(state)
    assert state["rollback_result"]["rollback_successful"] == 1
    assert scanner.s3_client.objects["tenant-a/doc.txt"]["Body"] == original
    assert_round_trip(state)


def test_registered_openapi_has_concrete_nested_contracts():
    app = FastAPI()
    app.include_router(workflows.router, prefix="/v1/workflows")
    assert_workflow_openapi(app.openapi())
    summary = app.openapi()["components"]["schemas"]["VerificationSummary"]
    assert summary["additionalProperties"] is False
    assert summary["properties"]["error"]["anyOf"] == [{"type": "string"}, {"type": "null"}]


def assert_workflow_openapi(spec):
    schemas = spec["components"]["schemas"]
    visited = set()

    def check(node):
        assert node, "untyped schema"
        if "$ref" in node:
            name = node["$ref"].rsplit("/", 1)[1]
            if name not in visited:
                visited.add(name)
                check(schemas[name])
        if node.get("type") == "array":
            check(node["items"])
        if node.get("type") == "object":
            assert node.get("additionalProperties") is not True
            assert node.get("properties") or isinstance(node.get("additionalProperties"), dict)
            for value in node.get("properties", {}).values():
                check(value)
            if isinstance(node.get("additionalProperties"), dict):
                check(node["additionalProperties"])
        for branch in node.get("anyOf", []) + node.get("oneOf", []):
            check(branch)

    for variant in ("WorkflowResponse", "RedTeamWorkflowResponse"):
        for name in FIELDS:
            field = schemas[variant]["properties"][name]
            assert {"type": "null"} in field["anyOf"]
            check(field)
    assert schemas["WorkflowResponse"]["properties"]["framework"]["not"] == {"const": "RED_TEAM"}
    assert schemas["RedTeamWorkflowResponse"]["properties"]["framework"]["const"] == "RED_TEAM"
    for path, method, status_code in (
        ("", "get", "200"),
        ("", "post", "201"),
        ("/{workflow_id}", "get", "200"),
        *(
            (f"/{{workflow_id}}/{action}", "post", "200")
            for action in ("resume", "approve", "reject", "remediate")
        ),
    ):
        response = spec["paths"]["/v1/workflows" + path][method]["responses"][status_code]["content"][
            "application/json"
        ]["schema"]
        if method == "get" and not path:
            response = response["items"]
        expected = [{"$ref": f"#/components/schemas/{name}"} for name in ("WorkflowResponse", "RedTeamWorkflowResponse")]
        if method == "post" and not path:
            assert response == expected[0]
        else:
            assert response["oneOf"] == expected


@pytest.mark.parametrize("framework", ["HIPAA", "GDPR", "SOC2", "LEGACY_CUSTOM", "RED_TEAM"])
def test_framework_selects_variant_without_changing_sparse_payload(framework):
    payload = workflow(findings=[], remediation_plan=[], execution_result={})
    payload["framework"] = framework
    adapter = TypeAdapter(workflows.WorkflowResponseVariant)
    result = adapter.validate_python(payload)
    expected = workflows.RedTeamWorkflowResponse if framework == "RED_TEAM" else workflows.WorkflowResponse
    assert type(result) is expected
    assert adapter.dump_python(result, mode="json") == result.model_dump(mode="json")
    for field in FIELDS:
        assert result.model_dump()[field] == payload.get(field)


@pytest.mark.parametrize("framework,field,value", [
    ("RED_TEAM", "findings", [{"control": "compliance-only"}]),
    ("RED_TEAM", "findings", [{"matched_signals": [42]}]),
    ("RED_TEAM", "remediation_plan", [{"action": "compliance-only"}]),
    ("RED_TEAM", "execution_result", {"actions_failed": 1}),
    ("RED_TEAM", "execution_result", {"failed": "1"}),
    ("RED_TEAM", "execution_result", {"simulation_only": "false"}),
    ("RED_TEAM", "execution_result", {"posture": "go", "unknown": True}),
    ("HIPAA", "findings", [red_team._grade(red_team.PROBES[0], None, None)]),
    ("HIPAA", "remediation_plan", ["red-team reason"]),
    ("HIPAA", "execution_result", {"posture": "go"}),
])
def test_framework_variant_rejects_incompatible_or_malformed_payload(framework, field, value):
    payload = workflow(**{field: value})
    payload["framework"] = framework
    with pytest.raises(ValidationError):
        TypeAdapter(workflows.WorkflowResponseVariant).validate_python(payload)


@pytest.mark.parametrize(
    "field,value",
    [
        ("findings", ["not an object"]),
        ("findings", [{"entity_count": "2"}]),
        ("remediation_plan", [{"diff": {"commands": [5]}}]),
        ("remediation_plan", [{"target": {"credentials": "private-marker"}}]),
        ("remediation_plan", [{"diff": {"terraform": ["undefined format"]}}]),
        ("remediation_actions", [{"attempts": True}]),
        ("execution_result", {"actions_failed": "private-marker"}),
        ("execution_result", {"details": [{"before_verification": {"entity_counts": {"PERSON": "2"}}}]}),
        ("execution_result", {"details": [{"after_verification": {"error": 42}}]}),
        ("execution_result", {"details": [{"after_verification": {"error": "failed", "unknown": True}}]}),
        ("rollback_result", {"details": [5]}),
    ],
)
def test_invalid_nested_payload_is_rejected(field, value):
    with pytest.raises(ValidationError):
        workflows.WorkflowResponse(**workflow(**{field: value}))

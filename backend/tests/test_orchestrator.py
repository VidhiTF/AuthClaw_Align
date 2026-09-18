import uuid

import pytest

from app.orchestrator.graph import (
    ComplianceState,
    ExecutionStatus,
    WorkflowState,
    gather_evidence,
    analyze_compliance,
    generate_remediation_plan,
    awaiting_approval,
    execute_remediation,
    rollback_remediation,
    verify_results,
    RemediationActionStatus,
    RemediationState,
)
from app.orchestrator import runner as workflow_runner


@pytest.fixture(autouse=True)
def _mock_document_scan(monkeypatch):
    from app.orchestrator import connectors
    import requests

    class PresidioResponse:
        status_code = 200

        def json(self):
            return [{"entity_type": "EMAIL_ADDRESS"} for _ in range(20)]

    def list_documents(_scanner, tenant_id):
        return [
            {"object_key": f"tenant-{tenant_id}/doc-{idx}.txt", "file_name": f"doc-{idx}.txt"}
            for idx in range(1, 4)
        ]

    monkeypatch.setattr(connectors.DocumentScanner, "list_documents", list_documents)
    monkeypatch.setattr(connectors.DocumentScanner, "fetch_and_extract_text", lambda *_args: "jane@example.com")
    monkeypatch.setattr(
        connectors.DocumentScanner,
        "execute_remediation",
        lambda _scanner, workflow_id, action_id, plan_item: {
            "connector": "aws_s3",
            "control": plan_item.get("finding_control", ""),
            "target": plan_item.get("target", {}),
            "status": "success",
            "details": "Redacted sensitive data",
            "mutation_id": action_id,
            "before_verification": {"total": 1},
            "after_verification": {"total": 0},
            "rollback_ref": {"backup_key": "backup", "target_key": plan_item.get("finding_control", "")},
        },
    )
    monkeypatch.setattr(
        connectors.DocumentScanner,
        "rollback_remediation",
        lambda _scanner, rollback_plan: {
            "connector": "aws_s3",
            "control": rollback_plan.get("control", ""),
            "status": "rolled_back",
            "details": "Restored S3 object",
        },
    )
    monkeypatch.setattr(requests, "post", lambda *_args, **_kwargs: PresidioResponse())


def _make_initial_state(
    framework: str = "HIPAA",
    tenant_id: str = None,
    workflow_id: str = None,
    auto_approve: bool = False,
) -> ComplianceState:
    """Create a fresh initial state with mock callbacks."""
    tid = tenant_id or str(uuid.uuid4())
    wid = workflow_id or str(uuid.uuid4())

    audit_calls = []

    def mock_emit(wf_id, t_id, r_id, transition, action, status):
        audit_calls.append({
            "workflow_id": wf_id, "tenant_id": t_id, "request_id": r_id,
            "transition": transition, "action": action, "status": status,
        })

    persist_calls = []

    def mock_persist(state):
        persist_calls.append(dict(state))

    approval_id = str(uuid.uuid4())

    def mock_create_approval(t_id, wf_id, plan):
        return approval_id

    def mock_check_approval(a_id):
        return "APPROVED" if auto_approve else "PENDING"

    state: ComplianceState = {
        "workflow_id": wid,
        "tenant_id": tid,
        "request_id": f"req-{wid[:8]}",
        "framework": framework,
        "current_state": WorkflowState.GATHER_EVIDENCE.value,
        "findings": [],
        "risk_score": 0.0,
        "remediation_plan": [],
        "approval_status": "",
        "approval_id": "",
        "execution_status": ExecutionStatus.RUNNING.value,
        "execution_result": {},
        "error_message": "",
        "retry_count": 0,
        "started_at": "2024-01-01T00:00:00+00:00",
        "updated_at": "2024-01-01T00:00:00+00:00",
        "completed_at": "",
        "_emit_audit": mock_emit,
        "_persist_state": mock_persist,
        "_create_approval": mock_create_approval,
        "_check_approval": mock_check_approval,
    }

    # Attach tracking lists for assertions
    state["_audit_calls"] = audit_calls
    state["_persist_calls"] = persist_calls
    state["_approval_id"] = approval_id

    return state


class TestWorkflowHappyPath:
    """Full workflow execution through all nodes with auto-approved remediation."""

    def test_full_workflow_with_auto_approve(self):
        """HIPAA workflow: gather → analyze → plan → approval → execute → verify → complete."""
        state = _make_initial_state(framework="HIPAA", auto_approve=True)
        audit_calls = state["_audit_calls"]

        # Step through each node manually (not via graph.invoke to control approval)
        state = gather_evidence(state)
        assert state["current_state"] == WorkflowState.ANALYZE_COMPLIANCE.value
        assert len(state["findings"]) == 3

        state = analyze_compliance(state)
        assert state["current_state"] == WorkflowState.GENERATE_REMEDIATION_PLAN.value
        assert state["risk_score"] == 1.0

        state = generate_remediation_plan(state)
        assert state["current_state"] == WorkflowState.COMPLETE.value
        assert len(state["remediation_plan"]) == 3  # 3 non-compliant findings

        # Manually transition to AWAITING_APPROVAL to simulate remediation trigger
        state["current_state"] = WorkflowState.AWAITING_APPROVAL.value
        state["execution_status"] = ExecutionStatus.PAUSED.value
        state["approval_id"] = ""

        # First call creates approval, sets PAUSED
        state = awaiting_approval(state)
        assert state["approval_status"] == "PENDING"
        assert state["execution_status"] == ExecutionStatus.PAUSED.value
        assert state["approval_id"] != ""

        # Second call checks approval → APPROVED
        state = awaiting_approval(state)
        assert state["approval_status"] == "APPROVED"
        assert state["current_state"] == WorkflowState.EXECUTE_REMEDIATION.value

        state = execute_remediation(state)
        assert state["current_state"] == WorkflowState.VERIFY_RESULTS.value
        assert state["execution_result"]["actions_executed"] == 3

        state = verify_results(state)
        assert state["current_state"] == WorkflowState.COMPLETE.value
        assert state["execution_status"] == ExecutionStatus.COMPLETED.value
        assert state["completed_at"] != ""

        # Verify audit events emitted at every transition
        assert len(audit_calls) >= 7  # start + each transition


class TestApprovalPauseResume:
    """Workflow pauses at AWAITING_APPROVAL and resumes after status changes."""

    def test_pause_and_resume(self):
        """Workflow pauses when approval is PENDING, resumes when APPROVED."""
        state = _make_initial_state(framework="GDPR", auto_approve=False)

        # Execute up to approval
        state = gather_evidence(state)
        state = analyze_compliance(state)
        state = generate_remediation_plan(state)

        # Create approval → PAUSED
        state = awaiting_approval(state)
        assert state["execution_status"] == ExecutionStatus.PAUSED.value
        assert state["approval_status"] == "PENDING"

        # Check again while still PENDING → stays PAUSED
        persist_count = len(state["_persist_calls"])
        state = awaiting_approval(state)
        assert state["execution_status"] == ExecutionStatus.PAUSED.value
        assert len(state["_persist_calls"]) == persist_count + 1
        assert state["_persist_calls"][-1]["approval_status"] == "PENDING"
        assert state["_persist_calls"][-1]["execution_status"] == ExecutionStatus.PAUSED.value

        # Simulate external approval
        state["_check_approval"] = lambda aid: "APPROVED"
        state = awaiting_approval(state)
        assert state["approval_status"] == "APPROVED"
        assert state["current_state"] == WorkflowState.EXECUTE_REMEDIATION.value
        assert state["execution_status"] == ExecutionStatus.RUNNING.value

        # Complete remaining nodes
        state = execute_remediation(state)
        state = verify_results(state)
        assert state["current_state"] == WorkflowState.COMPLETE.value


class TestRecovery:
    """Workflow can be recovered from a persisted state snapshot."""

    def test_recovery_from_execute_remediation(self):
        """Simulate crash at EXECUTE_REMEDIATION and recover."""
        original = _make_initial_state(framework="SOC2", auto_approve=True)

        # Execute up to the point where we "crash"
        state = gather_evidence(original)
        state = analyze_compliance(state)
        state = generate_remediation_plan(state)
        state = awaiting_approval(state)  # creates approval
        state = awaiting_approval(state)  # approves

        assert state["current_state"] == WorkflowState.EXECUTE_REMEDIATION.value

        # Simulate persisted state snapshot (strip callbacks)
        snapshot = {k: v for k, v in state.items() if not k.startswith("_")}

        # "Recover" by re-injecting callbacks and continuing
        recovered_state = {
            **snapshot,
            "_emit_audit": original["_emit_audit"],
            "_persist_state": original["_persist_state"],
            "_create_approval": original["_create_approval"],
            "_check_approval": original["_check_approval"],
        }

        # Resume from EXECUTE_REMEDIATION
        recovered_state = execute_remediation(recovered_state)
        assert recovered_state["current_state"] == WorkflowState.VERIFY_RESULTS.value

        recovered_state = verify_results(recovered_state)
        assert recovered_state["current_state"] == WorkflowState.COMPLETE.value
        assert recovered_state["execution_status"] == ExecutionStatus.COMPLETED.value


class TestRemediationRollback:
    """Remediation tracks action state and rolls back after terminal failure."""

    def test_failed_remediation_rolls_back_successful_actions(self, monkeypatch):
        from app.orchestrator import connectors

        state = _make_initial_state(framework="HIPAA", auto_approve=True)
        state.update({
            "current_state": WorkflowState.EXECUTE_REMEDIATION.value,
            "remediation_plan": [
                {
                    "finding_control": "tenant/doc-success.txt",
                    "action": "Simulate successful remediation",
                    "priority": "high",
                },
                {
                    "finding_control": "tenant/doc-fail.txt",
                    "action": "Simulate failed remediation",
                    "priority": "high",
                },
            ],
        })

        def fake_execute_remediation(_scanner, workflow_id, action_id, plan_item):
            if plan_item.get("finding_control", "").endswith("doc-fail.txt"):
                raise RuntimeError("redaction write failed")
            return {
                "connector": "aws_s3",
                "control": plan_item.get("finding_control", ""),
                "status": "success",
                "details": "Redacted sensitive data",
                "rollback_ref": {"backup_key": "backup", "target_key": plan_item.get("finding_control", "")},
            }

        monkeypatch.setattr(
            connectors.DocumentScanner,
            "execute_remediation",
            fake_execute_remediation,
        )

        state = execute_remediation(state)
        assert state["current_state"] == WorkflowState.VERIFY_RESULTS.value
        assert state["remediation_state"] == RemediationState.PARTIAL_FAILED.value
        assert state["execution_result"]["actions_successful"] == 1
        assert state["execution_result"]["actions_failed"] == 1
        audit_actions = [event["action"] for event in state["_audit_calls"]]
        assert "remediation_action_started" in audit_actions
        assert "remediation_action_succeeded" in audit_actions
        assert "remediation_action_failed" in audit_actions

        while state["current_state"] != WorkflowState.ROLLBACK_REMEDIATION.value:
            state = verify_results(state)
            if state["current_state"] == WorkflowState.EXECUTE_REMEDIATION.value:
                state = execute_remediation(state)

        assert state["retry_count"] == 3
        state = rollback_remediation(state)

        assert state["current_state"] == WorkflowState.FAILED.value
        assert state["execution_status"] == ExecutionStatus.FAILED.value
        assert state["remediation_state"] == RemediationState.ROLLED_BACK.value
        assert state["rollback_result"]["rollback_successful"] == 1
        audit_actions = [event["action"] for event in state["_audit_calls"]]
        assert "remediation_action_rollback_started" in audit_actions
        assert "remediation_action_rolled_back" in audit_actions

        statuses = {
            action["finding_control"]: action["status"]
            for action in state["remediation_actions"]
        }
        assert statuses["tenant/doc-success.txt"] == RemediationActionStatus.ROLLED_BACK.value
        assert statuses["tenant/doc-fail.txt"] == RemediationActionStatus.FAILED.value

    def test_action_audit_extra_trace_reaches_publisher_payload(self, monkeypatch):
        sent_events = []

        def capture_event(producer, tenant_id, event):
            sent_events.append({"key": tenant_id, "value": event})

        # The publisher now persists an outbox before transport delivery. This
        # runner test checks its event boundary; transport has separate tests.
        monkeypatch.setattr(workflow_runner, "_init_kafka_producer", lambda: None)
        monkeypatch.setattr(workflow_runner.event_backbone, "publish_audit_event", capture_event)

        workflow_runner.emit_audit_event(
            workflow_id="workflow-123",
            tenant_id="tenant-123",
            request_id="request-123",
            transition="REMEDIATION_ACTION_FAILED",
            action="remediation_action_failed",
            status="failed",
            extra_trace=[
                "action_id=action-123",
                "control=tenant/doc.txt",
                "attempt=3",
                "error=write failed",
            ],
        )

        assert len(sent_events) == 1
        event = sent_events[0]["value"]
        assert sent_events[0]["key"] == "tenant-123"
        assert event["action"] == "workflow:remediation_action_failed"
        assert "workflow_id=workflow-123" in event["execution_trace"]
        assert "transition=REMEDIATION_ACTION_FAILED" in event["execution_trace"]
        assert "action_id=action-123" in event["execution_trace"]
        assert "control=tenant/doc.txt" in event["execution_trace"]

        workflow_runner.emit_audit_event(
            workflow_id="workflow-123",
            tenant_id="tenant-123",
            request_id="request-123",
            transition="REMEDIATION_ACTION_FAILED",
            action="remediation_action_failed",
            status="failed",
            extra_trace=[
                "action_id=action-123",
                "control=tenant/doc.txt",
                "attempt=3",
                "error=write failed",
            ],
        )
        assert sent_events[1]["value"]["id"] == event["id"]


class TestTenantIsolation:
    """Workflows from different tenants produce independent state."""

    def test_two_tenants_independent_workflows(self):
        """Two tenants running concurrent workflows produce independent results."""
        tenant_a = str(uuid.uuid4())
        tenant_b = str(uuid.uuid4())

        state_a = _make_initial_state(framework="HIPAA", tenant_id=tenant_a)
        state_b = _make_initial_state(framework="GDPR", tenant_id=tenant_b)

        # Execute both independently
        state_a = gather_evidence(state_a)
        state_b = gather_evidence(state_b)

        state_a = analyze_compliance(state_a)
        state_b = analyze_compliance(state_b)

        # Verify independent state
        assert state_a["tenant_id"] == tenant_a
        assert state_b["tenant_id"] == tenant_b
        assert state_a["workflow_id"] != state_b["workflow_id"]
        assert state_a["framework"] == "HIPAA"
        assert state_b["framework"] == "GDPR"

        a_controls = [f["control"] for f in state_a["findings"]]
        b_controls = [f["control"] for f in state_b["findings"]]
        assert all(control.startswith(f"tenant-{tenant_a}/") for control in a_controls)
        assert all(control.startswith(f"tenant-{tenant_b}/") for control in b_controls)
        assert a_controls != b_controls

        # Audit trails are tenant-scoped
        audit_a = state_a["_audit_calls"]
        audit_b = state_b["_audit_calls"]
        for event in audit_a:
            assert event["tenant_id"] == tenant_a
        for event in audit_b:
            assert event["tenant_id"] == tenant_b

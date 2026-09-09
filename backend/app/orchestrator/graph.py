"""
LangGraph compliance orchestrator

Workflow states:
  GATHER_EVIDENCE → ANALYZE_COMPLIANCE → GENERATE_REMEDIATION_PLAN
  → AWAITING_APPROVAL → EXECUTE_REMEDIATION → VERIFY_RESULTS → COMPLETE

All state transitions emit audit events through the existing Kafka pipeline.
Workflow state is persisted to PostgreSQL for crash recovery.
"""

import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Optional, TypedDict

from langgraph.graph import StateGraph, END
import os

logger = logging.getLogger("orchestrator")


# Workflow States


class WorkflowState(str, Enum):
    GATHER_EVIDENCE = "GATHER_EVIDENCE"
    ANALYZE_COMPLIANCE = "ANALYZE_COMPLIANCE"
    GENERATE_REMEDIATION_PLAN = "GENERATE_REMEDIATION_PLAN"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    EXECUTE_REMEDIATION = "EXECUTE_REMEDIATION"
    VERIFY_RESULTS = "VERIFY_RESULTS"
    ROLLBACK_REMEDIATION = "ROLLBACK_REMEDIATION"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


class ExecutionStatus(str, Enum):
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class RemediationState(str, Enum):
    NOT_STARTED = "NOT_STARTED"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    RETRYING = "RETRYING"
    SUCCEEDED = "SUCCEEDED"
    PARTIAL_FAILED = "PARTIAL_FAILED"
    ROLLING_BACK = "ROLLING_BACK"
    ROLLED_BACK = "ROLLED_BACK"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"
    FAILED = "FAILED"


class RemediationActionStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"


def calculate_severity(entity_count: int) -> str:
    if entity_count >= 11:
        return "critical"
    if entity_count >= 4:
        return "high"
    if entity_count >= 1:
        return "medium"
    return "info"


# Graph State Schema


class ComplianceState(TypedDict, total=False):
    """LangGraph state schema for the compliance workflow."""
    workflow_id: str
    tenant_id: str
    request_id: str
    framework: str  # GDPR, HIPAA, SOC2
    current_state: str
    findings: list[dict]
    risk_score: float
    remediation_plan: list[dict]
    remediation_state: str
    remediation_actions: list[dict]
    rollback_result: dict
    approval_status: str
    approval_id: str
    execution_status: str
    execution_result: dict
    error_message: str
    retry_count: int
    started_at: str
    updated_at: str
    completed_at: str
    # Callbacks injected by the runner — graph nodes must only use state.get("_cb") pattern
    _emit_audit: Any  # callable(workflow_id, tenant_id, request_id, transition, action, status)
    _persist_state: Any  # callable(state) -> None
    _create_approval: Any  # callable(tenant_id, workflow_id, plan) -> approval_id
    _check_approval: Any  # callable(approval_id) -> status string
    _store_evidence: Any
    _store_finding: Any


# Node Implementations


def gather_evidence(state: ComplianceState) -> ComplianceState:
    """GATHER_EVIDENCE: Collect documents from S3 and scan for PII/PHI."""
    logger.info("[%s] Gathering evidence for %s", state["workflow_id"], state["framework"])
    
    tenant_id = state["tenant_id"]
    findings = []
    
    try:
        from app.orchestrator.connectors import DocumentScanner
        scanner = DocumentScanner()
        docs = scanner.list_documents(tenant_id)
        
        presidio_url = os.getenv("PRESIDIO_URL", "http://localhost:3000")
        if not presidio_url.endswith("/analyze"):
            presidio_url = f"{presidio_url.rstrip('/')}/analyze"
        import requests
        
        for doc in docs:
            try:
                # Fetch text
                text_content = scanner.fetch_and_extract_text(doc["object_key"], doc["file_name"])
                if not text_content.strip():
                    continue
                
                # Analyze with Presidio
                payload = {
                    "text": text_content,
                    "language": "en",
                    "entities": ["EMAIL_ADDRESS", "PERSON", "PHONE_NUMBER", "US_SSN", "CREDIT_CARD"]
                }
                resp = requests.post(presidio_url, json=payload, timeout=10)
                if resp.status_code == 200:
                    results = resp.json()
                    if results:
                        entity_types = list(set([r["entity_type"] for r in results]))
                        findings.append({
                            "control": doc["object_key"],
                            "description": f"Found {len(results)} sensitive entities in document",
                            "status": "non_compliant",
                            "evidence": f"Entities: {', '.join(entity_types)}",
                            "entity_count": len(results)
                        })
                        store_fn = state.get("_store_evidence")
                        if store_fn:
                            try:
                                severity = calculate_severity(len(results))
                                store_fn(
                                    state["tenant_id"],
                                    state["workflow_id"],
                                    state["framework"],
                                    "s3_document",
                                    doc["object_key"],
                                    "pii_detected",
                                    {
                                        "object_key": doc["object_key"],
                                        "file_name": doc.get("file_name", ""),
                                        "entity_count": len(results),
                                        "entity_types": entity_types,
                                        "presidio_results": results,
                                    },
                                    severity,
                                )
                            except Exception as _ev_exc:
                                logger.warning(
                                    "Evidence storage failed for %s (non-fatal): %s",
                                    doc["object_key"], _ev_exc,
                                )
                    else:
                        findings.append({
                            "control": doc["object_key"],
                            "description": "Document contains no detected sensitive data",
                            "status": "compliant",
                            "evidence": "Clean scan",
                            "entity_count": 0
                        })
                        store_fn = state.get("_store_evidence")
                        if store_fn:
                            try:
                                store_fn(
                                    state["tenant_id"],
                                    state["workflow_id"],
                                    state["framework"],
                                    "s3_document",
                                    doc["object_key"],
                                    "scan_result",
                                    {
                                        "object_key": doc["object_key"],
                                        "file_name": doc.get("file_name", ""),
                                        "entity_count": 0,
                                        "result": "clean",
                                    },
                                    "info",
                                )
                            except Exception as _ev_exc:
                                logger.warning(
                                    "Evidence storage failed for clean scan %s (non-fatal): %s",
                                    doc["object_key"], _ev_exc,
                                )
                else:
                    logger.warning("Presidio returned %d for %s", resp.status_code, doc["object_key"])
            except Exception as e:
                logger.error("Failed to process document %s: %s", doc["object_key"], e)
                
    except Exception as e:
        logger.error("Evidence gathering failed: %s", e)
    
    emit = state.get("_emit_audit")
    if emit:
        emit(state["workflow_id"], state["tenant_id"], state.get("request_id", ""),
             "GATHER_EVIDENCE→ANALYZE_COMPLIANCE", "gather_evidence", "completed")
    
    persist = state.get("_persist_state")
    new_state = {
        **state,
        "findings": findings,
        "current_state": WorkflowState.ANALYZE_COMPLIANCE.value,
        "updated_at": datetime.now(tz=timezone.utc).isoformat(),
    }
    if persist:
        persist(new_state)
    return new_state


def analyze_compliance(state: ComplianceState) -> ComplianceState:
    """ANALYZE_COMPLIANCE: Score findings based on number of sensitive entities."""
    logger.info("[%s] Analyzing compliance for %s", state["workflow_id"], state["framework"])
    
    findings = state.get("findings", [])
    non_compliant = [f for f in findings if f.get("status") == "non_compliant"]
    total_entities = sum(f.get("entity_count", 0) for f in non_compliant)
    
    # Simple risk score: maxes out at 1.0 around 50 entities
    risk_score = min(1.0, total_entities / 50.0)
    if not findings:
        risk_score = 0.0
    
    emit = state.get("_emit_audit")
    if emit:
        emit(state["workflow_id"], state["tenant_id"], state.get("request_id", ""),
             "ANALYZE_COMPLIANCE→GENERATE_REMEDIATION_PLAN", "analyze_compliance", "completed")
    
    persist = state.get("_persist_state")
    new_state = {
        **state,
        "risk_score": round(risk_score, 2),
        "current_state": WorkflowState.GENERATE_REMEDIATION_PLAN.value,
        "updated_at": datetime.now(tz=timezone.utc).isoformat(),
    }
    if persist:
        persist(new_state)
    return new_state


def generate_remediation_plan(state: ComplianceState) -> ComplianceState:
    """GENERATE_REMEDIATION_PLAN: Create target-bound remediation actions for documents with PII."""
    logger.info("[%s] Generating remediation plan", state["workflow_id"])
    
    findings = state.get("findings", [])
    non_compliant = [f for f in findings if f.get("status") == "non_compliant"]
    
    from app.orchestrator.connectors import DocumentScanner

    scanner = DocumentScanner()
    plan = []
    for finding in non_compliant:
        priority = "high" if state.get("risk_score", 0) > 0.5 else "medium"
        connector_plan = scanner.build_remediation_plan(finding["control"], finding["evidence"])
        plan.append({
            "finding_control": finding["control"],
            "action": f"Redact sensitive data in S3 object ({finding['evidence']})",
            "priority": priority,
            "estimated_effort": "1 hour",
            **connector_plan,
            "steps": [
                f"Create rollback copy for S3 object: {finding['control']}",
                "Redact detected sensitive values",
                "Overwrite the approved S3 target through the audited remediation connector",
                "Verify before/after sensitive-entity counts",
            ],
            "proposed_change": {
                "summary": f"Redact sensitive data in S3 object ({finding['evidence']})",
                "target": connector_plan.get("target", {}),
                "preview": connector_plan.get("diff", {}).get("preview", []),
            },
            "risk": {
                "level": "high",
                "destructive": True,
                "impact": "The approved S3 object will be overwritten with a redacted copy.",
            },
            "rollback": {
                "strategy": "Restore the pre-change S3 backup created before mutation.",
                "trigger": "Verification failure or an operator-requested rollback.",
                "evidence": "The backup reference and restore verification are recorded in the audit trace.",
            },
        })
        
        store_finding_fn = state.get("_store_finding")
        if store_finding_fn:
            try:
                entity_count = finding.get("entity_count", 0)
                finding_severity = calculate_severity(entity_count)
                
                # Extract clean filename
                raw_control = finding["control"]
                file_name = raw_control.split("/")[-1] if "/" in raw_control else raw_control
                
                store_finding_fn(
                    state["tenant_id"],
                    state["workflow_id"],
                    None,  # evidence_id not tracked in state
                    state["framework"],
                    "PII_EXPOSURE",
                    finding["control"],
                    f"PII detected in {file_name}",
                    finding["description"],
                    finding_severity,
                    "OPEN",
                    state.get("risk_score", 0.0),
                    plan[-1]["action"] + "\n\nSteps:\n- " + "\n- ".join(plan[-1]["steps"])
                )
            except Exception as e:
                logger.warning("Finding storage failed (non-fatal): %s", e)
    
    # Scans execute without immediate approval, completing the scan stage
    next_state = WorkflowState.COMPLETE.value
    
    emit = state.get("_emit_audit")
    if emit:
        emit(state["workflow_id"], state["tenant_id"], state.get("request_id", ""),
             "GENERATE_REMEDIATION_PLAN→COMPLETE", "generate_plan", "completed")
    
    persist = state.get("_persist_state")
    new_state = {
        **state,
        "remediation_plan": plan,
        "current_state": next_state,
        "execution_status": ExecutionStatus.COMPLETED.value,
        "completed_at": datetime.now(tz=timezone.utc).isoformat(),
        "updated_at": datetime.now(tz=timezone.utc).isoformat(),
    }
    if persist:
        persist(new_state)
    return new_state


def awaiting_approval(state: ComplianceState) -> ComplianceState:
    """AWAITING_APPROVAL: Create or check a HITL approval request."""
    logger.info("[%s] Awaiting approval", state["workflow_id"])
    
    approval_id = state.get("approval_id")
    
    if not approval_id:
        # First entry: create the approval request
        create_fn = state.get("_create_approval")
        if create_fn:
            approval_id = create_fn(
                state["tenant_id"],
                state["workflow_id"],
                state.get("remediation_plan", []),
            )
        else:
            # No approval function — auto-approve for testing
            approval_id = str(uuid.uuid4())
        
        emit = state.get("_emit_audit")
        if emit:
            emit(state["workflow_id"], state["tenant_id"], state.get("request_id", ""),
                 "AWAITING_APPROVAL", "create_approval", "pending")
        
        persist = state.get("_persist_state")
        new_state = {
            **state,
            "approval_id": approval_id,
            "approval_status": "PENDING",
            "execution_status": ExecutionStatus.PAUSED.value,
            "updated_at": datetime.now(tz=timezone.utc).isoformat(),
        }
        if persist:
            persist(new_state)
        return new_state
    
    # Subsequent entry: check approval status
    check_fn = state.get("_check_approval")
    status = "PENDING"
    if check_fn:
        status = check_fn(approval_id)
    
    if status == "APPROVED":
        next_state = WorkflowState.EXECUTE_REMEDIATION.value
        exec_status = ExecutionStatus.RUNNING.value
    elif status == "REJECTED":
        next_state = WorkflowState.COMPLETE.value
        exec_status = ExecutionStatus.COMPLETED.value
    elif status == "EXPIRED":
        next_state = WorkflowState.COMPLETE.value
        exec_status = ExecutionStatus.COMPLETED.value
    else:  # PENDING — stay paused
        persist = state.get("_persist_state")
        new_state = {
            **state,
            "approval_status": status,
            "execution_status": ExecutionStatus.PAUSED.value,
            "updated_at": datetime.now(tz=timezone.utc).isoformat(),
        }
        if persist:
            persist(new_state)
        return new_state
    
    emit = state.get("_emit_audit")
    if emit:
        emit(state["workflow_id"], state["tenant_id"], state.get("request_id", ""),
             f"AWAITING_APPROVAL→{next_state}", "approval_resolved", status.lower())
    
    persist = state.get("_persist_state")
    new_state = {
        **state,
        "approval_status": status,
        "current_state": next_state,
        "execution_status": exec_status,
        "updated_at": datetime.now(tz=timezone.utc).isoformat(),
    }
    if persist:
        persist(new_state)
    return new_state


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _remediation_action_id(index: int, action: dict) -> str:
    identity = "|".join([
        str(index),
        action.get("finding_control", ""),
        action.get("action", ""),
    ])
    return str(uuid.uuid5(uuid.NAMESPACE_URL, identity))


def _build_remediation_actions(plan: list[dict], previous_actions: list[dict] | None) -> list[dict]:
    previous_by_id = {
        item.get("id"): item
        for item in (previous_actions or [])
        if item.get("id")
    }

    actions = []
    for index, plan_item in enumerate(plan):
        action_id = _remediation_action_id(index, plan_item)
        existing = previous_by_id.get(action_id, {})
        actions.append({
            "id": action_id,
            "index": index,
            "finding_control": plan_item.get("finding_control", ""),
            "action": plan_item.get("action", "Unknown action"),
            "connector": plan_item.get("connector", "aws_s3"),
            "target": plan_item.get("target", {}),
            "diff": plan_item.get("diff", {}),
            "destructive": bool(plan_item.get("destructive")),
            "priority": plan_item.get("priority", "medium"),
            "status": existing.get("status", RemediationActionStatus.PENDING.value),
            "attempts": existing.get("attempts", 0),
            "last_error": existing.get("last_error", ""),
            "started_at": existing.get("started_at", ""),
            "updated_at": existing.get("updated_at", ""),
            "completed_at": existing.get("completed_at", ""),
            "result": existing.get("result"),
            "rollback_plan": existing.get("rollback_plan"),
            "rollback_result": existing.get("rollback_result"),
            "mutation_state": existing.get("mutation_state"),
        })

    return actions


def _summarize_remediation_actions(actions: list[dict], remediation_state: str) -> dict:
    successful = [
        action for action in actions
        if action.get("status") in (
            RemediationActionStatus.SUCCEEDED.value,
            RemediationActionStatus.ROLLED_BACK.value,
        )
    ]
    failed = [
        action for action in actions
        if action.get("status") in (
            RemediationActionStatus.FAILED.value,
            RemediationActionStatus.ROLLBACK_FAILED.value,
        )
    ]
    return {
        "remediation_state": remediation_state,
        "actions_executed": len(actions),
        "actions_successful": len(successful),
        "actions_failed": len(failed),
        "rollback_required": any(
            action.get("status") == RemediationActionStatus.SUCCEEDED.value
            or bool((action.get("rollback_plan") or {}).get("rollback_ref"))
            for action in actions
        ) and bool(failed),
        "details": [
            action.get("result") or {
                "connector": "S3Document",
                "control": action.get("finding_control", ""),
                "status": action.get("status", ""),
                "details": action.get("last_error", ""),
            }
            for action in actions
        ],
        "actions": actions,
    }


def _get_remediation_actions(state: ComplianceState) -> list[dict]:
    if state.get("remediation_actions"):
        return state.get("remediation_actions", [])
    result = state.get("execution_result") or {}
    return result.get("actions", [])


def _persist_remediation_progress(state: ComplianceState, actions: list[dict]) -> None:
    persist = state.get("_persist_state")
    if not persist:
        return
    persist({
        **state,
        "remediation_state": RemediationState.EXECUTING.value,
        "remediation_actions": actions,
        "current_state": WorkflowState.EXECUTE_REMEDIATION.value,
        "updated_at": _now_iso(),
    })


def _trace_value(value: Any, limit: int = 180) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return text[:limit - 3] + "..."


def _emit_remediation_action_audit(
    state: ComplianceState,
    action: dict,
    transition: str,
    audit_action: str,
    status: str,
    extra_trace: list[str] | None = None,
) -> None:
    emit = state.get("_emit_audit")
    if not emit:
        return

    trace = [
        f"action_id={action.get('id', '')}",
        f"action_index={action.get('index', '')}",
        f"control={_trace_value(action.get('finding_control', ''))}",
        f"attempt={action.get('attempts', 0)}",
        f"action_status={action.get('status', '')}",
    ]
    if extra_trace:
        trace.extend(extra_trace)

    try:
        emit(
            state["workflow_id"],
            state["tenant_id"],
            state.get("request_id", ""),
            transition,
            audit_action,
            status,
            trace,
        )
    except TypeError:
        # Unit tests and older integrations may still provide the original 6-arg callback.
        emit(
            state["workflow_id"],
            state["tenant_id"],
            state.get("request_id", ""),
            transition,
            audit_action,
            status,
        )


def execute_remediation(state: ComplianceState) -> ComplianceState:
    """EXECUTE_REMEDIATION: Apply the approved remediation plan through real connectors."""
    logger.info("[%s] Executing remediation", state["workflow_id"])
    
    plan = state.get("remediation_plan", [])
    
    try:
        from app.orchestrator.connectors import DocumentScanner
        scanner = DocumentScanner()
    except Exception as e:
        logger.error("Failed to initialize DocumentScanner: %s", e)
        scanner = None
    
    actions = _build_remediation_actions(plan, _get_remediation_actions(state))
    
    for action in actions:
        if action.get("status") in (
            RemediationActionStatus.SUCCEEDED.value,
            RemediationActionStatus.ROLLED_BACK.value,
        ):
            continue

        plan_item = plan[action.get("index", 0)] if action.get("index", 0) < len(plan) else {}
        control = action.get("finding_control", "")
        now = _now_iso()
        action.update({
            "status": RemediationActionStatus.RUNNING.value,
            "attempts": action.get("attempts", 0) + 1,
            "started_at": action.get("started_at") or now,
            "updated_at": now,
            "last_error": "",
        })
        _emit_remediation_action_audit(
            state,
            action,
            "REMEDIATION_ACTION_STARTED",
            "remediation_action_started",
            "running",
        )

        res = None
        try:
            if not scanner:
                raise RuntimeError("Scanner not initialized")

            durable_s3_protocol = (
                getattr(scanner, "s3_client", None) is not None
                and (plan_item.get("target") or {}).get("type") == "s3_object"
                and hasattr(scanner, "prepare_remediation")
                and hasattr(scanner, "apply_prepared_remediation")
            )
            if durable_s3_protocol:
                prepared = scanner.prepare_remediation(
                    state["workflow_id"],
                    action["id"],
                    plan_item,
                    action.get("mutation_state"),
                )
                action["mutation_state"] = prepared
                _persist_remediation_progress(state, actions)
                if prepared.get("phase") in {"CONFLICTED", "ROLLBACK_CONFLICTED", "UNKNOWN"}:
                    raise RuntimeError(prepared.get("conflict") or "Remediation state requires operator reconciliation")
                prepared["phase"] = "APPLYING"
                _persist_remediation_progress(state, actions)
                res = scanner.apply_prepared_remediation(prepared, plan_item)
            else:
                res = scanner.execute_remediation(state["workflow_id"], action["id"], plan_item)
            if res.get("mutation_state"):
                action["mutation_state"] = res["mutation_state"]
            if res.get("rollback_ref"):
                action["rollback_plan"] = {
                    "mode": "aws_s3_restore_backup",
                    "control": control,
                    "action": "Restore original S3 object from AuthClaw rollback copy",
                    "rollback_ref": res["rollback_ref"],
                }
            status = str(res.get("status", "")).lower()
            if status not in ("success", "succeeded", "completed"):
                raise RuntimeError(res.get("details") or f"Remediation returned status {status}")

            action.update({
                "status": RemediationActionStatus.SUCCEEDED.value,
                "result": res,
                "rollback_plan": {
                    "mode": "aws_s3_restore_backup",
                    "control": control,
                    "action": "Restore original S3 object from AuthClaw rollback copy",
                    "rollback_ref": res.get("rollback_ref", {}),
                },
                "completed_at": _now_iso(),
                "updated_at": _now_iso(),
            })
            _emit_remediation_action_audit(
                state,
                action,
                "REMEDIATION_ACTION_SUCCEEDED",
                "remediation_action_succeeded",
                "succeeded",
                [
                    f"connector={res.get('connector', 'aws_s3')}",
                    f"result_status={res.get('status', '')}",
                    f"target={_trace_value(res.get('target', {}).get('uri', control))}",
                    f"mutation_id={res.get('mutation_id', '')}",
                ],
            )
        except Exception as e:
            mutation_state = action.get("mutation_state") or {}
            mutation = mutation_state.get("mutation") or {}
            if mutation.get("etag") and hasattr(scanner, "rollback_ref_from_state"):
                action["rollback_plan"] = {
                    "mode": "aws_s3_restore_backup",
                    "control": control,
                    "action": "Restore original S3 object from AuthClaw rollback copy",
                    "rollback_ref": scanner.rollback_ref_from_state(mutation_state),
                }
            action.update({
                "status": RemediationActionStatus.FAILED.value,
                "last_error": str(e),
                "result": res or {
                    "connector": plan_item.get("connector", "aws_s3"),
                    "control": control,
                    "target": plan_item.get("target"),
                    "status": "failed",
                    "details": str(e),
                },
                "updated_at": _now_iso(),
            })
            _emit_remediation_action_audit(
                state,
                action,
                "REMEDIATION_ACTION_FAILED",
                "remediation_action_failed",
                "failed",
                [f"error={_trace_value(e)}"],
            )
            
    failed_count = len([
        action for action in actions
        if action.get("status") == RemediationActionStatus.FAILED.value
    ])
    remediation_state = (
        RemediationState.SUCCEEDED.value
        if failed_count == 0
        else RemediationState.PARTIAL_FAILED.value
    )
    result = _summarize_remediation_actions(actions, remediation_state)
    
    emit = state.get("_emit_audit")
    if emit:
        emit(state["workflow_id"], state["tenant_id"], state.get("request_id", ""),
             "EXECUTE_REMEDIATION→VERIFY_RESULTS", "execute_remediation", "completed")
    
    persist = state.get("_persist_state")
    new_state = {
        **state,
        "remediation_state": remediation_state,
        "remediation_actions": actions,
        "execution_result": result,
        "current_state": WorkflowState.VERIFY_RESULTS.value,
        "updated_at": _now_iso(),
    }
    if persist:
        persist(new_state)
    return new_state


def verify_results(state: ComplianceState) -> ComplianceState:
    """VERIFY_RESULTS: Verify that remediation was successful."""
    logger.info("[%s] Verifying results", state["workflow_id"])
    
    result = state.get("execution_result", {})
    failed = result.get("actions_failed", 0)
    
    if failed > 0:
        actions = _get_remediation_actions(state)
        mutated_failure = any(
            action.get("status") == RemediationActionStatus.FAILED.value
            and bool((action.get("rollback_plan") or {}).get("rollback_ref"))
            for action in actions
        )
        # Retry logic
        retry_count = state.get("retry_count", 0)
        if retry_count < 3 and not mutated_failure:
            emit = state.get("_emit_audit")
            if emit:
                emit(state["workflow_id"], state["tenant_id"], state.get("request_id", ""),
                     "VERIFY_RESULTS→EXECUTE_REMEDIATION", "verify_results", "retry")
            persist = state.get("_persist_state")
            new_state = {
                **state,
                "current_state": WorkflowState.EXECUTE_REMEDIATION.value,
                "remediation_state": RemediationState.RETRYING.value,
                "retry_count": retry_count + 1,
                "updated_at": _now_iso(),
            }
            if persist:
                persist(new_state)
            return new_state
        # Max retries exceeded
        actions = _get_remediation_actions(state)
        has_rollback_candidates = any(
            action.get("status") == RemediationActionStatus.SUCCEEDED.value
            or bool((action.get("rollback_plan") or {}).get("rollback_ref"))
            for action in actions
        )
        if has_rollback_candidates:
            emit = state.get("_emit_audit")
            if emit:
                emit(state["workflow_id"], state["tenant_id"], state.get("request_id", ""),
                     "VERIFY_RESULTS->ROLLBACK_REMEDIATION", "verify_results", "rollback_required")
            persist = state.get("_persist_state")
            new_state = {
                **state,
                "current_state": WorkflowState.ROLLBACK_REMEDIATION.value,
                "remediation_state": RemediationState.ROLLING_BACK.value,
                "error_message": (
                    "Post-mutation verification failed; rollback required"
                    if mutated_failure
                    else "Max retries exceeded during verification; rollback required"
                ),
                "updated_at": _now_iso(),
            }
            if persist:
                persist(new_state)
            return new_state

        emit = state.get("_emit_audit")
        if emit:
            emit(state["workflow_id"], state["tenant_id"], state.get("request_id", ""),
                 "VERIFY_RESULTS→FAILED", "verify_results", "max_retries_exceeded")
        persist = state.get("_persist_state")
        new_state = {
            **state,
            "current_state": WorkflowState.FAILED.value,
            "execution_status": ExecutionStatus.FAILED.value,
            "remediation_state": RemediationState.FAILED.value,
            "error_message": "Max retries exceeded during verification",
            "updated_at": _now_iso(),
        }
        if persist:
            persist(new_state)
        return new_state
    
    emit = state.get("_emit_audit")
    if emit:
        emit(state["workflow_id"], state["tenant_id"], state.get("request_id", ""),
             "VERIFY_RESULTS→COMPLETE", "verify_results", "passed")
    
    persist = state.get("_persist_state")
    now = _now_iso()
    new_state = {
        **state,
        "current_state": WorkflowState.COMPLETE.value,
        "execution_status": ExecutionStatus.COMPLETED.value,
        "remediation_state": RemediationState.SUCCEEDED.value,
        "updated_at": now,
        "completed_at": now,
    }
    if persist:
        persist(new_state)
    return new_state


# Routing logic


def rollback_remediation(state: ComplianceState) -> ComplianceState:
    """ROLLBACK_REMEDIATION: Revert successful remediation actions after terminal failure."""
    logger.info("[%s] Rolling back remediation", state["workflow_id"])

    actions = _get_remediation_actions(state)
    rollback_details = []
    rollback_succeeded = 0
    rollback_failed = 0

    # Roll back in reverse execution order.
    for action in sorted(actions, key=lambda item: item.get("index", 0), reverse=True):
        if action.get("status") == RemediationActionStatus.ROLLED_BACK.value:
            rollback_succeeded += 1
            rollback_details.append(action.get("rollback_result") or {})
            continue

        if action.get("status") != RemediationActionStatus.SUCCEEDED.value and not (
            action.get("status") == RemediationActionStatus.FAILED.value
            and (action.get("rollback_plan") or {}).get("rollback_ref")
        ):
            continue

        _emit_remediation_action_audit(
            state,
            action,
            "REMEDIATION_ACTION_ROLLBACK_STARTED",
            "remediation_action_rollback_started",
            "running",
            [f"rollback_mode={action.get('rollback_plan', {}).get('mode', 'unknown')}"],
        )

        try:
            from app.orchestrator.connectors import DocumentScanner
            scanner = DocumentScanner()
            rollback_result = scanner.rollback_remediation(action.get("rollback_plan") or {})
            action.update({
                "status": RemediationActionStatus.ROLLED_BACK.value,
                "rollback_result": rollback_result,
                "updated_at": _now_iso(),
            })
            rollback_details.append(rollback_result)
            rollback_succeeded += 1
            _emit_remediation_action_audit(
                state,
                action,
                "REMEDIATION_ACTION_ROLLED_BACK",
                "remediation_action_rolled_back",
                "rolled_back",
                [
                    f"rollback_mode={action.get('rollback_plan', {}).get('mode', 'unknown')}",
                    f"rollback_status={rollback_result.get('status', '')}",
                ],
            )
        except Exception as exc:
            rollback_result = {
                "connector": "S3Document",
                "control": action.get("finding_control", ""),
                "status": "rollback_failed",
                "details": str(exc),
            }
            action.update({
                "status": RemediationActionStatus.ROLLBACK_FAILED.value,
                "rollback_result": rollback_result,
                "last_error": str(exc),
                "updated_at": _now_iso(),
            })
            rollback_details.append(rollback_result)
            rollback_failed += 1
            _emit_remediation_action_audit(
                state,
                action,
                "REMEDIATION_ACTION_ROLLBACK_FAILED",
                "remediation_action_rollback_failed",
                "failed",
                [f"error={_trace_value(exc)}"],
            )

    rollback_result = {
        "rollback_attempted": rollback_succeeded + rollback_failed,
        "rollback_successful": rollback_succeeded,
        "rollback_failed": rollback_failed,
        "details": rollback_details,
    }
    remediation_state = (
        RemediationState.ROLLED_BACK.value
        if rollback_failed == 0
        else RemediationState.ROLLBACK_FAILED.value
    )
    execution_result = _summarize_remediation_actions(actions, remediation_state)

    emit = state.get("_emit_audit")
    if emit:
        emit(state["workflow_id"], state["tenant_id"], state.get("request_id", ""),
             "ROLLBACK_REMEDIATION->FAILED", "rollback_remediation",
             "completed" if rollback_failed == 0 else "failed")

    persist = state.get("_persist_state")
    now = _now_iso()
    new_state = {
        **state,
        "current_state": WorkflowState.FAILED.value,
        "execution_status": ExecutionStatus.FAILED.value,
        "remediation_state": remediation_state,
        "remediation_actions": actions,
        "execution_result": execution_result,
        "rollback_result": rollback_result,
        "error_message": (
            "Remediation failed after retries; rollback completed"
            if rollback_failed == 0
            else "Remediation failed after retries; rollback failed"
        ),
        "updated_at": now,
        "completed_at": now,
    }
    if persist:
        persist(new_state)
    return new_state


def route_after_plan(state: ComplianceState) -> str:
    """Route after GENERATE_REMEDIATION_PLAN based on whether a plan exists."""
    if state.get("current_state") == WorkflowState.COMPLETE.value:
        return END
    return "awaiting_approval"


def route_after_approval(state: ComplianceState) -> str:
    """Route after AWAITING_APPROVAL based on approval status."""
    status = state.get("approval_status", "PENDING")
    if status == "APPROVED":
        return "execute_remediation"
    if status in ("REJECTED", "EXPIRED"):
        return END
    # PENDING — workflow pauses here
    return END  # Will be resumed later


def route_after_verify(state: ComplianceState) -> str:
    """Route after VERIFY_RESULTS — retry or complete."""
    cs = state.get("current_state", "")
    if cs == WorkflowState.EXECUTE_REMEDIATION.value:
        return "execute_remediation"  # retry
    if cs == WorkflowState.ROLLBACK_REMEDIATION.value:
        return "rollback_remediation"
    if cs == WorkflowState.FAILED.value:
        return END
    return END  # COMPLETE


# Build the graph


def build_compliance_graph() -> StateGraph:
    """Build and compile the LangGraph compliance workflow."""
    graph = StateGraph(ComplianceState)

    # Add nodes
    graph.add_node("gather_evidence", gather_evidence)
    graph.add_node("analyze_compliance", analyze_compliance)
    graph.add_node("generate_remediation_plan", generate_remediation_plan)
    graph.add_node("awaiting_approval", awaiting_approval)
    graph.add_node("execute_remediation", execute_remediation)
    graph.add_node("verify_results", verify_results)
    graph.add_node("rollback_remediation", rollback_remediation)

    # Set entry point
    graph.set_entry_point("gather_evidence")

    # Edges
    graph.add_edge("gather_evidence", "analyze_compliance")
    graph.add_edge("analyze_compliance", "generate_remediation_plan")
    graph.add_conditional_edges("generate_remediation_plan", route_after_plan,
                                {"awaiting_approval": "awaiting_approval", END: END})
    graph.add_conditional_edges("awaiting_approval", route_after_approval,
                                {"execute_remediation": "execute_remediation", END: END})
    graph.add_edge("execute_remediation", "verify_results")
    graph.add_conditional_edges("verify_results", route_after_verify,
                                {
                                    "execute_remediation": "execute_remediation",
                                    "rollback_remediation": "rollback_remediation",
                                    END: END,
                                })
    graph.add_edge("rollback_remediation", END)

    return graph.compile()

"""
Compliance workflow runner

Bridges the LangGraph compliance graph with AuthClaw infrastructure:
  - PostgreSQL persistence (ComplianceWorkflow model)
  - Kafka audit event emission
  - HITL approval via pending_approvals table
  - Crash recovery and resumption
"""

import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.models import ApprovalAudit, ComplianceWorkflow, PendingApproval
from app.orchestrator.graph import (
    ComplianceState,
    ExecutionStatus,
    WorkflowState,
    RemediationState,
    build_compliance_graph,
    awaiting_approval,
    execute_remediation,
    rollback_remediation,
    verify_results,
)
from app.services import event_backbone, evidence_service, findings_service
from app.services.remediation_approval import (
    build_action_payload,
    compute_action_hash,
    evaluate_approval,
)
from app.orchestrator.workflow_lock import workflow_advisory_lock

logger = logging.getLogger("orchestrator.runner")


_kafka_producer = None


def _init_kafka_producer():
    """Lazy-init a Kafka producer for audit events. Non-fatal if unavailable."""
    global _kafka_producer
    if _kafka_producer is not None:
        return
    try:
        _kafka_producer = event_backbone.make_kafka_producer()
        logger.info("Kafka producer initialized for orchestrator audit events")
    except Exception as exc:
        logger.warning("Kafka producer unavailable — audit events logged to stdout only: %s", exc)


def emit_audit_event(
    workflow_id: str,
    tenant_id: str,
    request_id: str,
    transition: str,
    action: str,
    status: str,
    extra_trace: Optional[list[str]] = None,
) -> None:
    """Emit a workflow audit event through the Kafka pipeline."""
    execution_trace = [
        f"workflow_id={workflow_id}",
        f"transition={transition}",
    ]
    if extra_trace:
        execution_trace.extend(extra_trace)

    event = event_backbone.audit_event(
        event_type="workflow",
        tenant_id=tenant_id,
        subject_id=workflow_id,
        identity_action=f"{transition}:{action}:{status}:{request_id or ''}",
        request_id=request_id or "",
        action=f"workflow:{action}",
        reason=f"{transition} [{status}]",
        provider="orchestrator",
        trace=execution_trace,
    )

    _init_kafka_producer()
    if exc := event_backbone.publish_audit_event(_kafka_producer, tenant_id, event):
        logger.warning("Failed to emit audit event to Kafka: %s", exc)

    logger.info(
        "[AUDIT] workflow=%s tenant=%s transition=%s action=%s status=%s",
        workflow_id, tenant_id, transition, action, status,
    )


def _persist_state_to_db(db: Session, state: ComplianceState) -> None:
    """Write the current workflow state snapshot to PostgreSQL."""
    workflow_id = state.get("workflow_id", "")
    tenant_id = state.get("tenant_id", "")
    wf = db.query(ComplianceWorkflow).filter(
        ComplianceWorkflow.workflow_id == workflow_id
    ).first()

    if not wf:
        logger.warning("Workflow %s not found in DB for persistence", workflow_id)
        return

    wf.current_state = state.get("current_state", wf.current_state)
    wf.findings = state.get("findings")
    wf.risk_score = state.get("risk_score")
    wf.remediation_plan = state.get("remediation_plan")
    wf.approval_status = state.get("approval_status")
    wf.execution_status = state.get("execution_status", "RUNNING")
    if state.get("approval_id"):
        wf.approval_id = uuid.UUID(state["approval_id"]) if isinstance(state["approval_id"], str) else state["approval_id"]
    else:
        wf.approval_id = None
    wf.execution_result = state.get("execution_result")
    wf.error_message = state.get("error_message")
    wf.retry_count = state.get("retry_count", 0)
    wf.updated_at = datetime.now(tz=timezone.utc)

    if state.get("completed_at"):
        try:
            wf.completed_at = datetime.fromisoformat(state["completed_at"])
        except (ValueError, TypeError):
            pass

    # Store full state snapshot for crash recovery (exclude internal callbacks)
    safe_state = {k: v for k, v in state.items() if not k.startswith("_")}
    wf.state_data = safe_state

    db.commit()
    logger.debug("Persisted workflow %s state=%s", workflow_id, wf.current_state)


def _create_approval_in_db(
    db: Session,
    tenant_id: str,
    workflow_id: str,
    plan: list,
    requester_id: Optional[str] = None,
    *,
    commit: bool = True,
) -> str:
    """Create a pending_approvals record for HITL review."""
    approval_id = str(uuid.uuid4())

    if not requester_id:
        raise RuntimeError("Authenticated workflow requester is required for approval creation")
    try:
        resolved_requester_id = uuid.UUID(str(requester_id))
    except (ValueError, TypeError) as exc:
        raise RuntimeError("Authenticated workflow requester is invalid") from exc

    expires_at = datetime.now(tz=timezone.utc) + timedelta(minutes=30)
    action_payload = build_action_payload(workflow_id, plan)

    approval = PendingApproval(
        id=uuid.UUID(approval_id),
        tenant_id=uuid.UUID(tenant_id),
        action_id=workflow_id,
        action_type="remediation",
        action_description=f"Compliance remediation plan ({len(plan)} actions)",
        action_payload=action_payload,
        action_hash=compute_action_hash(
            tenant_id=tenant_id,
            action_payload=action_payload,
            expires_at=expires_at,
        ),
        status="PENDING",
        requester_id=resolved_requester_id,
        expires_at=expires_at,
    )

    db.add(approval)
    if commit:
        db.commit()

    logger.info("Created approval %s for workflow %s", approval_id, workflow_id)
    return approval_id


def _make_store_evidence_fn(db: Session):
    """
    Return a closure that matches the _store_evidence callback signature expected
    by graph nodes.  The closure forwards to evidence_service.create_evidence()
    and is entirely non-fatal — a failure here must never break the workflow.

    Signature passed to graph state:
      store_fn(tenant_id, workflow_id, framework, source_type, source_reference,
               evidence_type, evidence_data, severity) -> None
    """
    def _store(tenant_id, workflow_id, framework, source_type, source_reference,
               evidence_type, evidence_data, severity="info"):
        try:
            evidence_service.create_evidence(
                db,
                tenant_id=tenant_id,
                workflow_id=workflow_id,
                framework=framework,
                source_type=source_type,
                source_reference=source_reference,
                evidence_type=evidence_type,
                evidence_data=evidence_data,
                severity=severity,
            )
        except Exception as exc:
            logger.warning(
                "[evidence] create_evidence failed (non-fatal) workflow=%s: %s",
                workflow_id, exc,
            )
    return _store


def _make_store_finding_fn(db: Session):
    def _store(tenant_id, workflow_id, evidence_id, framework, finding_type, source_reference, title, description, severity="medium", status="OPEN", risk_score=0.0, remediation_summary=None):
        try:
            # Look up EvidenceRecord to ensure tight traceability
            if not evidence_id:
                from app.db.models import EvidenceRecord
                import uuid
                evidence = db.query(EvidenceRecord).filter_by(
                    tenant_id=uuid.UUID(tenant_id),
                    workflow_id=workflow_id,
                    source_reference=source_reference
                ).order_by(EvidenceRecord.created_at.desc()).first()
                
                if evidence:
                    evidence_id = str(evidence.id)

            findings_service.create_finding(
                db,
                tenant_id=tenant_id,
                workflow_id=workflow_id,
                evidence_id=evidence_id,
                framework=framework,
                finding_type=finding_type,
                source_reference=source_reference,
                title=title,
                description=description,
                severity=severity,
                status=status,
                risk_score=risk_score,
                remediation_summary=remediation_summary
            )
        except Exception as exc:
            logger.warning(
                "[finding] create_finding failed (non-fatal) workflow=%s: %s",
                workflow_id, exc,
            )
    return _store


def _record_approval_audit(
    db: Session,
    approval: PendingApproval,
    actor_id: uuid.UUID,
    action: str,
    reason: str,
) -> None:
    db.add(
        ApprovalAudit(
            id=uuid.uuid4(),
            tenant_id=approval.tenant_id,
            approval_id=approval.id,
            actor_id=actor_id,
            action=action,
            action_hash=approval.action_hash,
            reason=reason,
            details={
                "action_id": approval.action_id,
                "action_type": approval.action_type,
                "status": approval.status,
            },
            mfa_verified=approval.mfa_verified,
            mfa_timestamp=approval.mfa_timestamp,
        )
    )


def _check_approval_in_db(
    db: Session,
    approval_id: str,
    tenant_id: str,
    actor_id: str,
    workflow_id: str,
    current_plan: list,
) -> str:
    """Validate and atomically consume a remediation approval."""
    try:
        approval = db.query(PendingApproval).filter(
            PendingApproval.id == uuid.UUID(approval_id),
            PendingApproval.tenant_id == uuid.UUID(tenant_id),
            PendingApproval.action_type == "remediation",
        ).with_for_update().first()
    except ValueError:
        return "EXPIRED"

    if not approval:
        return "EXPIRED"

    # A rejected decision is terminal; no second approval-row UPDATE is needed.
    if approval.status == "REJECTED" and approval.action_id == workflow_id:
        return "REJECTED"

    now = datetime.now(tz=timezone.utc)
    plan = (approval.action_payload or {}).get("plan") or []
    destructive = any(bool(item.get("destructive")) for item in plan if isinstance(item, dict))
    if approval.status == "APPROVED" and destructive:
        mfa_timestamp = approval.mfa_timestamp
        if mfa_timestamp and mfa_timestamp.tzinfo is None:
            mfa_timestamp = mfa_timestamp.replace(tzinfo=timezone.utc)
        if not approval.mfa_verified or not mfa_timestamp or mfa_timestamp < now - timedelta(minutes=30):
            approval.status = "EXPIRED"
            approval.resolution_reason = "Fresh MFA expired before remediation execution"
            _record_approval_audit(
                db, approval, uuid.UUID(actor_id), "EXPIRED", approval.resolution_reason
            )
            event_backbone.increment_metric("remediation_approval_expired_total")
            db.commit()
            return "EXPIRED"

    decision = evaluate_approval(
        approval=approval,
        tenant_id=tenant_id,
        actor_id=actor_id,
        workflow_id=workflow_id,
        current_plan=current_plan,
        now=now,
    )
    if not decision.allowed:
        if decision.status in {"EXPIRED", "ALTERED"}:
            approval.status = decision.status
        approval.resolution_reason = decision.reason
        _record_approval_audit(
            db, approval, uuid.UUID(actor_id), f"{decision.status}_REJECTED", decision.reason
        )
        event_backbone.increment_metric(
            f"remediation_approval_{decision.status.lower()}_rejected_total"
        )
        db.commit()
        if decision.status in {"EXPIRED", "REPLAYED", "ALTERED", "USER_MISMATCH", "ACTION_MISMATCH"}:
            return "EXPIRED"
        return approval.status

    approval.status = "CONSUMED"
    approval.consumed_at = now
    approval.consumed_by_id = uuid.UUID(actor_id)
    approval.resolution_reason = "Approval consumed for one remediation execution"
    _record_approval_audit(db, approval, uuid.UUID(actor_id), "CONSUMED", approval.resolution_reason)
    event_backbone.increment_metric("remediation_approval_consumed_total")
    db.commit()
    return "APPROVED"


class ComplianceWorkflowRunner:
    """Manages the lifecycle of a compliance workflow execution."""

    def __init__(self, db: Session):
        self.db = db
        self.graph = build_compliance_graph()

    def start(
        self,
        tenant_id: str,
        framework: str,
        request_id: Optional[str] = None,
        requester_id: Optional[str] = None,
    ) -> dict:
        """Start a new compliance workflow."""
        workflow_id = str(uuid.uuid4())
        now = datetime.now(tz=timezone.utc)

        # Create DB record
        db_workflow = ComplianceWorkflow(
            id=uuid.uuid4(),
            tenant_id=uuid.UUID(tenant_id),
            workflow_id=workflow_id,
            request_id=request_id or "",
            framework=framework,
            current_state=WorkflowState.GATHER_EVIDENCE.value,
            execution_status=ExecutionStatus.RUNNING.value,
            started_at=now,
            updated_at=now,
        )

        self.db.add(db_workflow)
        self.db.commit()

        emit_audit_event(workflow_id, tenant_id, request_id or "",
                         "START→GATHER_EVIDENCE", "workflow_start", "running")

        # Build initial state with callback bindings
        initial_state: ComplianceState = {
            "workflow_id": workflow_id,
            "tenant_id": tenant_id,
            "requester_id": requester_id,
            "request_id": request_id or "",
            "framework": framework,
            "current_state": WorkflowState.GATHER_EVIDENCE.value,
            "findings": [],
            "risk_score": 0.0,
            "remediation_plan": [],
            "remediation_state": RemediationState.NOT_STARTED.value,
            "remediation_actions": [],
            "rollback_result": {},
            "approval_status": "",
            "approval_id": "",
            "execution_status": ExecutionStatus.RUNNING.value,
            "execution_result": {},
            "error_message": "",
            "retry_count": 0,
            "started_at": now.isoformat(),
            "updated_at": now.isoformat(),
            "completed_at": "",
            "_emit_audit": emit_audit_event,
            "_persist_state": lambda s: _persist_state_to_db(self.db, s),
            "_create_approval": lambda tid, wid, plan: _create_approval_in_db(
                self.db, tid, wid, plan, requester_id=requester_id
            ),
            "_check_approval": lambda aid: _check_approval_in_db(self.db, aid),
            "_store_evidence": _make_store_evidence_fn(self.db),
            "_store_finding": _make_store_finding_fn(self.db),
        }

        # Execute the graph
        try:
            final_state = self.graph.invoke(initial_state)
        except Exception as exc:
            logger.error("Workflow %s failed: %s", workflow_id, exc)
            emit_audit_event(workflow_id, tenant_id, request_id or "",
                             "FAILED", "workflow_error", str(exc))
            # Update DB
            wf = self.db.query(ComplianceWorkflow).filter(
                ComplianceWorkflow.workflow_id == workflow_id
            ).first()
            if wf:
                wf.execution_status = ExecutionStatus.FAILED.value
                wf.error_message = str(exc)
                wf.current_state = WorkflowState.FAILED.value
                wf.updated_at = datetime.now(tz=timezone.utc)
                self.db.commit()
            raise

        # Return sanitized state (no internal callbacks)
        return {k: v for k, v in final_state.items() if not k.startswith("_")}

    def _drive_remediation_states(self, state: ComplianceState) -> ComplianceState:
        """Continue active remediation nodes until pause or terminal state."""
        for _ in range(12):
            current = state.get("current_state")
            if current == WorkflowState.EXECUTE_REMEDIATION.value:
                state = execute_remediation(state)
                continue
            if current == WorkflowState.VERIFY_RESULTS.value:
                state = verify_results(state)
                continue
            if current == WorkflowState.ROLLBACK_REMEDIATION.value:
                state = rollback_remediation(state)
                continue
            break
        return state

    def resume(
        self,
        workflow_id: str,
        tenant_id: str,
        actor_id: Optional[str] = None,
    ) -> dict:
        """Resume a paused workflow (e.g., after approval)."""
        lock_key = int(uuid.UUID(workflow_id).int & 0x7fffffffffffffff)
        with workflow_advisory_lock(self.db, lock_key, workflow_id):
            wf = self.db.query(ComplianceWorkflow).filter(
                ComplianceWorkflow.workflow_id == workflow_id,
                ComplianceWorkflow.tenant_id == uuid.UUID(tenant_id),
            ).first()

            if not wf:
                raise ValueError(f"Workflow {workflow_id} not found for tenant {tenant_id}")

            if wf.execution_status not in (ExecutionStatus.PAUSED.value, ExecutionStatus.RUNNING.value):
                raise ValueError(
                    f"Workflow {workflow_id} cannot be resumed (status={wf.execution_status})"
                )

            # Restore state from snapshot
            state_data = wf.state_data or {}
            state: ComplianceState = {
                **state_data,
                "execution_status": ExecutionStatus.RUNNING.value,
                "_emit_audit": emit_audit_event,
                "_persist_state": lambda s: _persist_state_to_db(self.db, s),
                "_create_approval": lambda tid, wid, plan: _create_approval_in_db(
                    self.db,
                    tid,
                    wid,
                    plan,
                    requester_id=state.get("requester_id"),
                ),
                "_check_approval": lambda aid: _check_approval_in_db(
                    self.db,
                    aid,
                    tenant_id,
                    actor_id or "",
                    workflow_id,
                    wf.remediation_plan or [],
                ),
                "_store_evidence": _make_store_evidence_fn(self.db),
                "_store_finding": _make_store_finding_fn(self.db),
            }

            emit_audit_event(workflow_id, tenant_id, state.get("request_id", ""),
                             f"RESUME→{wf.current_state}", "workflow_resume", "running")

            # Update DB status
            wf.execution_status = ExecutionStatus.RUNNING.value
            wf.updated_at = datetime.now(tz=timezone.utc)
            self.db.commit()

            # Execute remaining nodes from current state
            try:
                current = wf.current_state

                if current == WorkflowState.AWAITING_APPROVAL.value:
                    state = awaiting_approval(state)
                    approval_status = state.get("approval_status", "PENDING")
                    if approval_status == "APPROVED":
                        state = self._drive_remediation_states(state)
                elif current in (
                    WorkflowState.EXECUTE_REMEDIATION.value,
                    WorkflowState.VERIFY_RESULTS.value,
                    WorkflowState.ROLLBACK_REMEDIATION.value,
                ):
                    state = self._drive_remediation_states(state)

            except Exception as exc:
                logger.error("Workflow %s resume failed: %s", workflow_id, exc)
                emit_audit_event(workflow_id, tenant_id, state.get("request_id", ""),
                                 "FAILED", "workflow_resume_error", str(exc))
                wf.execution_status = ExecutionStatus.FAILED.value
                wf.error_message = str(exc)
                wf.updated_at = datetime.now(tz=timezone.utc)
                self.db.commit()
                raise
            return {k: v for k, v in state.items() if not k.startswith("_")}

    def get_status(self, workflow_id: str, tenant_id: str) -> Optional[dict]:
        """Get the current status of a workflow."""
        wf = self.db.query(ComplianceWorkflow).filter(
            ComplianceWorkflow.workflow_id == workflow_id,
            ComplianceWorkflow.tenant_id == uuid.UUID(tenant_id),
        ).first()

        if not wf:
            return None

        state_data = wf.state_data or {}
        execution_result = wf.execution_result or {}
        return {
            "workflow_id": wf.workflow_id,
            "tenant_id": str(wf.tenant_id),
            "framework": wf.framework,
            "current_state": wf.current_state,
            "execution_status": wf.execution_status,
            "risk_score": wf.risk_score,
            "findings": wf.findings,
            "remediation_plan": wf.remediation_plan,
            "remediation_state": state_data.get("remediation_state") or execution_result.get("remediation_state"),
            "remediation_actions": state_data.get("remediation_actions") or execution_result.get("actions"),
            "rollback_result": state_data.get("rollback_result"),
            "approval_status": wf.approval_status,
            "approval_id": str(wf.approval_id) if wf.approval_id else None,
            "execution_result": wf.execution_result,
            "error_message": wf.error_message,
            "retry_count": wf.retry_count,
            "started_at": wf.started_at.isoformat() if wf.started_at else None,
            "updated_at": wf.updated_at.isoformat() if wf.updated_at else None,
            "completed_at": wf.completed_at.isoformat() if wf.completed_at else None,
        }

    def recover_interrupted(self, tenant_id: str) -> list[dict]:
        """Find and recover workflows that were interrupted (RUNNING but not completed)."""
        interrupted = self.db.query(ComplianceWorkflow).filter(
            ComplianceWorkflow.tenant_id == uuid.UUID(tenant_id),
            ComplianceWorkflow.execution_status.in_(["RUNNING"]),
            ComplianceWorkflow.completed_at.is_(None),
        ).all()

        results = []
        for wf in interrupted:
            try:
                result = self.resume(wf.workflow_id, tenant_id)
                results.append({"workflow_id": wf.workflow_id, "status": "recovered", "state": result})
            except Exception as exc:
                results.append({"workflow_id": wf.workflow_id, "status": "failed", "error": str(exc)})

        return results

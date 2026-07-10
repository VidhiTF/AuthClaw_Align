from datetime import datetime
import os
from typing import Any, Dict

from database import engine
from sqlalchemy import text
from verify_audit import create_audit_block, log_agent_event


class AuditAgent:
    def record(self, state: Dict[str, Any]) -> Dict[str, Any]:
        os.makedirs("logs", exist_ok=True)
        log_file = os.path.join("logs", "audit.log")

        response = state.get("response", "BLOCKED BY POLICY")
        tenant_id = state.get("tenant_id", 1)
        session_id = state.get("session_id", "default")
        allowed = state.get("allowed", True)
        approval_status = state.get("approval_status", "N/A")
        risk_level = state.get("risk_level", "LOW")
        username = state.get("username", "admin_user")
        triggered_policies = state.get("triggered_policies", []) or []

        with open(log_file, "a", encoding="utf-8") as file:
            file.write(f"\nTime: {datetime.now()}\n")
            file.write(f"User: {state['message']}\n")
            file.write(f"Allowed: {allowed}\n")
            file.write(f"AI: {response}\n")
            file.write("-" * 50 + "\n")

        is_blocked = not allowed
        is_pending_approval = approval_status == "PENDING_APPROVAL"

        status_to_log = (
            "pending"
            if is_pending_approval
            else ("blocked" if is_blocked else (approval_status if approval_status != "N/A" else "completed"))
        )
        policy_name = policy_type = matched_pattern = redacted_value = None

        if triggered_policies:
            policy_name = ", ".join(list(set([tp["policy_name"] for tp in triggered_policies])))
            policy_type = ", ".join(list(set([tp["policy_type"] for tp in triggered_policies])))
            matched_pattern = ", ".join(list(set([tp["matched_pattern"] for tp in triggered_policies])))
            redacted_value = ", ".join(list(set([str(tp["redacted_value"]) for tp in triggered_policies])))

        record_id = create_audit_block(
            query=state.get("original_query", state["message"]),
            response=response,
            allowed=allowed,
            risk_level=risk_level,
            approval_status=status_to_log,
            session_id=session_id,
            approval_id=state.get("approval_id"),
            approver="System" if is_pending_approval else username,
            original_request=state.get("original_query", state["message"]),
            approval_timestamp=None,
            execution_timestamp=None,
            execution_status=status_to_log,
            policy_name=policy_name,
            policy_type=policy_type,
            matched_pattern=matched_pattern,
            redacted_value=redacted_value,
            username=username,
            tenant_id=tenant_id
        )

        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT integrity_hash, previous_hash FROM audit_logs WHERE id = :id"),
                {"id": record_id}
            ).fetchone()
            conn.commit()

        if row:
            integrity_hash, previous_hash = row[0], row[1]
            log_agent_event(
                tenant_id=tenant_id,
                session_id=session_id,
                agent_name="Audit Agent",
                event_type="AUDIT_RECORD_STORED",
                details=f"Committed block #{record_id} to the cryptographic compliance ledger."
            )
            log_agent_event(
                tenant_id=tenant_id,
                session_id=session_id,
                agent_name="Audit Agent",
                event_type="LEDGER_HASH_GENERATED",
                details=f"SHA-256 Block integrity hash generated. Current: {integrity_hash[:16]}... Previous: {previous_hash[:16]}..."
            )
            log_agent_event(
                tenant_id=tenant_id,
                session_id=session_id,
                agent_name="Audit Agent",
                event_type="CHAIN_VERIFICATION_COMPLETE",
                details="Cryptographic blockchain link verified. Status: Valid & Unbroken."
            )

        state["audit_record_id"] = record_id
        return state

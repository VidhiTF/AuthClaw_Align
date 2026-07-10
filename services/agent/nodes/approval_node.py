from state import AuthState
from approval_store import create_approval


import time
import concurrent.futures

def _approval_reason(state: AuthState) -> str:
    if state.get("unknown_provider_risk"):
        return "unknown_provider_risk"
    if state.get("security_policy_action") == "require_approval" or state.get("block_category") in {"pii", "secrets", "sensitive_data"}:
        return "sensitive_data"
    if state.get("policy_decision") in {"REQUIRE_APPROVAL", "BLOCK"} or state.get("block_reason") == "policy_violation":
        return "policy_violation"
    if state.get("risk_level") == "HIGH":
        return "high_risk"
    return "high_risk"


def approval_node(state: AuthState):
    print("[Approval Start]", flush=True)
    start_time = time.perf_counter()

    # If already approved via HITL, don't create a new approval request
    if state.get("approval_status") == "APPROVED":
        print("APPROVAL NODE: Already approved")
        duration = time.perf_counter() - start_time
        print(f"[Approval End] Duration: {duration:.4f}s", flush=True)
        return state

    if state["risk_level"] == "HIGH":
        session_id = state.get("session_id", "")
        reason = _approval_reason(state)
        
        # Enforce 5s hard timeout on approval creation
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        try:
            future = executor.submit(
                create_approval,
                query=state["message"],
                risk_level=state["risk_level"],
                session_id=session_id,
                tenant_id=state.get("tenant_id"),
                request_id=state.get("request_id"),
                reason=reason,
                metadata={
                    "policy_decision": state.get("policy_decision"),
                    "security_policy_action": state.get("security_policy_action"),
                    "block_category": state.get("block_category"),
                    "block_reason": state.get("block_reason"),
                },
            )
            record = future.result(timeout=5.0)
        except concurrent.futures.TimeoutError as te:
            print("[Approval End] Timeout occurred", flush=True)
            raise TimeoutError("Approval creation timed out after 5 seconds") from te
        finally:
            executor.shutdown(wait=False)

        state["approval_id"]     = record["approval_id"]
        state["approval_status"] = "PENDING_APPROVAL"
        state["approval_reason"] = reason

        print(f"APPROVAL NODE: Created approval {record['approval_id']}")

    else:
        state["approval_status"] = "APPROVED"
        print("APPROVAL NODE: Auto approved")

    duration = time.perf_counter() - start_time
    print(f"[Approval End] Duration: {duration:.4f}s", flush=True)
    return state

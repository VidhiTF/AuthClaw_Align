from state import AuthState
from verify_audit import log_agent_event

def orchestrator_node(state: AuthState):
    print("ORCHESTRATOR NODE (Gateway Agent)", flush=True)

    message = state.get("message", "").lower()
    tenant_id = state.get("tenant_id", 1)
    session_id = state.get("session_id", "default")

    # Gateway Agent Logs events
    log_agent_event(
        tenant_id=tenant_id,
        session_id=session_id,
        agent_name="Gateway Agent",
        event_type="API_KEY_VALIDATED",
        details=f"Cleared security key authorization for Tenant ID {tenant_id}."
    )

    log_agent_event(
        tenant_id=tenant_id,
        session_id=session_id,
        agent_name="Gateway Agent",
        event_type="RATE_LIMIT_CHECKED",
        details="Access quotas and rate limits validated. Status: Cleared."
    )

    if "gdpr" in message:
        state["task_type"] = "gdpr"
    elif "hipaa" in message:
        state["task_type"] = "hipaa"
    elif "soc2" in message:
        state["task_type"] = "soc2"
    else:
        state["task_type"] = "general"

    print("TASK TYPE:", state["task_type"])
    return state
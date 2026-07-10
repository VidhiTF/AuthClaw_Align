from services.decision_engine import apply_decision
from state import AuthState
from verify_audit import log_agent_event


def decision_node(state: AuthState):
    print("[Decision Engine Start]", flush=True)
    apply_decision(state)

    log_agent_event(
        tenant_id=state.get("tenant_id", 1),
        session_id=state.get("session_id", "default"),
        agent_name="Decision Engine",
        event_type="DECISION_EVALUATED",
        details=f"Decision: {state.get('decision')} ({state.get('decision_reason')}).",
    )

    print("[Decision Engine End]", flush=True)
    return state

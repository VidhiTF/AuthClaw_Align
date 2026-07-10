from memory import add_message
from services.security_agent import SecurityAgent
from state import AuthState
from verify_audit import log_agent_event


def response_checks_node(state: AuthState):
    print("[AuthClaw Checks Start]", flush=True)

    session_id = state.get("session_id", "default")
    tenant_id = state.get("tenant_id", 1)
    username = state.get("username", "admin_user")
    response = state.get("response", "")

    log_agent_event(
        tenant_id=tenant_id,
        session_id=session_id,
        agent_name="Security Agent",
        event_type="OUTPUT_PII_SCAN_START",
        details="Scanning upstream provider response for sensitive data leakage."
    )
    log_agent_event(
        tenant_id=tenant_id,
        session_id=session_id,
        agent_name="AuthClaw Checks",
        event_type="OUTPUT_PII_SCAN_START",
        details="Scanning upstream provider response for sensitive data leakage."
    )

    checked_response, output_triggers = SecurityAgent().sanitize_output(response, username, tenant_id)

    if output_triggers:
        policy_names = ", ".join(list(set([t["policy_name"] for t in output_triggers])))
        log_agent_event(
            tenant_id=tenant_id,
            session_id=session_id,
            agent_name="Security Agent",
            event_type="OUTPUT_PII_REDACTED",
            details=f"Redacted sensitive data matching {policy_names} before returning to the client."
        )
    else:
        log_agent_event(
            tenant_id=tenant_id,
            session_id=session_id,
            agent_name="Security Agent",
            event_type="OUTPUT_PII_SCAN_CLEAN",
            details="Response checks passed. No sensitive data leaks detected."
        )

    if "triggered_policies" not in state or state["triggered_policies"] is None:
        state["triggered_policies"] = []
    state["triggered_policies"].extend(output_triggers)

    add_message(session_id, "assistant", checked_response)

    print("[AuthClaw Checks End]", flush=True)
    return {
        **state,
        "response": checked_response
    }

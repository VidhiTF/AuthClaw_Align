from memory import add_message
from services.security_agent import SecurityAgent
from verify_audit import log_agent_event
import time

def redact_node(state):
    print("[Redaction Start] (Policy Agent)", flush=True)
    start_time = time.perf_counter()

    message = state["message"]
    username = state.get("username", "admin_user")
    tenant_id = state.get("tenant_id", 1)
    session_id = state.get("session_id", "default")

    result = SecurityAgent().inspect_input(message, username, tenant_id)
    redacted = result.sanitized_text
    triggered = result.findings
    state["security_approved"] = result.approved
    state["security_findings"] = triggered
    state["security_policy_action"] = "allow"
    finding_actions = {str(t.get("action", "redact")).lower() for t in triggered}
    if "block" in finding_actions:
        state["allowed"] = False
        state["block_reason"] = "Sensitive data policy blocked the request before provider execution."
        state["block_category"] = "sensitive_data"
        state["policy_decision"] = "block"
        state["security_policy_action"] = "block"
    elif "require_approval" in finding_actions:
        state["security_policy_action"] = "require_approval"
        state["risk_level"] = "HIGH"

    # Log Security Agent events
    if triggered:
        policy_names = ", ".join(list(set([t["policy_name"] for t in triggered])))
        log_agent_event(
            tenant_id=tenant_id,
            session_id=session_id,
            agent_name="Security Agent",
            event_type="PII_DETECTED",
            details=f"Sensitive items matching {policy_names} identified in user query. Actions: {', '.join(sorted(finding_actions))}."
        )
        log_agent_event(
            tenant_id=tenant_id,
            session_id=session_id,
            agent_name="Security Agent",
            event_type="SYNTHETIC_REPLACEMENT_APPLIED",
            details="Context-preserving synthetic replacements and masks applied to prompts."
        )
    else:
        log_agent_event(
            tenant_id=tenant_id,
            session_id=session_id,
            agent_name="Security Agent",
            event_type="PII_SCAN_CLEAN",
            details="Sensitive data scan completed. No PII or PHI detected."
        )

    if "triggered_policies" not in state or state["triggered_policies"] is None:
        state["triggered_policies"] = []

    state["triggered_policies"].extend(triggered)

    print("REDACT NODE:", redacted, state["triggered_policies"])

    state["message"] = redacted
    
    # Save the redacted user prompt immediately
    add_message(session_id, "user", redacted)

    duration = time.perf_counter() - start_time
    print(f"[Redaction End] Duration: {duration:.4f}s", flush=True)
    return state

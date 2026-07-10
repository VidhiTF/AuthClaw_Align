from services.provider_router import ProviderRouter
from state import AuthState
from verify_audit import log_agent_event


def provider_router_node(state: AuthState):
    print("[Provider Router Start]", flush=True)

    if not state.get("allowed", True) or state.get("approval_status") == "PENDING_APPROVAL":
        print("[Provider Router End] Skipped", flush=True)
        return state

    tenant_id = state.get("tenant_id", 1)
    session_id = state.get("session_id", "default")

    selection = ProviderRouter(tenant_id=tenant_id).select()
    state["provider_client"] = selection.provider
    state["provider"] = selection.provider_name
    state["model"] = selection.model
    state["route_id"] = selection.route_id
    state["provider_route_source"] = selection.source

    log_agent_event(
        tenant_id=tenant_id,
        session_id=session_id,
        agent_name="Provider Router",
        event_type="PROVIDER_ROUTE_SELECTED",
        details=(
            f"Selected {selection.provider_name} model {selection.model} "
            f"from {selection.source}."
        ),
    )

    print("[Provider Router End]", flush=True)
    return state

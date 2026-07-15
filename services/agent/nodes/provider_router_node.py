import os

from providers.gateway_provider import GatewayProvider
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

    gateway_api_key = state.get("gateway_api_key")
    gateway_url = os.getenv("AUTHCLAW_GO_GATEWAY_URL")
    if gateway_api_key and gateway_url:
        provider_name = state.get("provider") or os.getenv("MODEL_PROVIDER", "gemini")
        if provider_name == "AuthClaw Gateway":
            provider_name = os.getenv("MODEL_PROVIDER", "gemini")
        provider = GatewayProvider(
            api_key=gateway_api_key,
            provider_name=provider_name,
            model_name=None if state.get("model") == "authclaw-gateway" else state.get("model"),
            api_url=gateway_url,
        )
        state["provider_client"] = provider
        state["provider"] = provider.provider_name
        state["model"] = provider.model_name
        state["route_id"] = None
        state["provider_route_source"] = "go_gateway"
        selection = None
    else:
        selection = ProviderRouter(tenant_id=tenant_id).select()

    if selection:
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
            f"Selected {state['provider']} model {state['model']} "
            f"from {state['provider_route_source']}."
        ),
    )

    print("[Provider Router End]", flush=True)
    return state

from memory import get_history
from providers import get_provider
from redaction import stream_redact_sensitive_tokens
from verify_audit import log_agent_event
import time
import concurrent.futures


def _offline_provider_fallback(error_message: str) -> str:
    return (
        "[Offline Fallback] The configured model provider is currently unavailable. "
        "AuthClaw completed the gateway security, policy, and audit checks, but the "
        "upstream LLM call could not be completed. Check the Providers page, API "
        "credentials, and outbound network access, then try again."
    )


def _build_prompt(state) -> str:
    context = state.get("context", "")
    session_id = state.get("session_id", "default")
    history = get_history(session_id)

    history_text = ""
    for msg in history:
        role = msg.get("role", "user")
        content = msg.get("content")
        if content is None:
            if role == "blocked":
                category = msg.get("category", "policy_violation")
                content = f"[Blocked: {category}]"
            elif role == "system" and "approvalId" in msg:
                content = f"[Pending Approval: {msg.get('approvalId')}]"
            else:
                content = ""
        history_text += f"{role}: {content}\n"

    return f"""
You are a compliance assistant.

Conversation History:
{history_text}

Compliance Context:
{context}

User Question:
{state['message']}
"""


def _resolve_provider(state):
    provider = state.get("provider_client")
    if provider is None:
        provider = get_provider()
        state["provider"] = provider.__class__.__name__
        state["model"] = getattr(provider, "model_name", "authclaw-gateway")
        state["provider_route_source"] = "legacy_provider_fallback"
    return provider


def _provider_token_stream(provider, prompt: str):
    for method_name in ("stream_generate", "generate_stream", "stream"):
        method = getattr(provider, method_name, None)
        if callable(method):
            yield from method(prompt)
            return
    yield provider.generate(prompt)


def stream_llm_node(state):
    """
    Additive streaming path for gateway callers that can consume chunks.
    Existing graph execution still calls llm_node and keeps the old response
    contract unchanged.
    """
    if state.get("approval_status") == "PENDING_APPROVAL":
        return
    if not state.get("allowed", True):
        yield "Policy Violation"
        return

    tenant_id = state.get("tenant_id", 1)
    session_id = state.get("session_id", "default")
    username = state.get("username", "admin_user")
    prompt = _build_prompt(state)

    try:
        provider = _resolve_provider(state)
        log_agent_event(
            tenant_id=tenant_id,
            session_id=session_id,
            agent_name="LLM Provider",
            event_type="STREAM_ROUTE_SELECTED",
            details=(
                f"Selected streaming model route: {state.get('provider')} "
                f"({state.get('model')}) via {state.get('provider_route_source')}."
            )
        )
        token_stream = _provider_token_stream(provider, prompt)
    except Exception as exc:
        token_stream = iter([_offline_provider_fallback(str(exc))])
        state["provider_status"] = "offline_fallback"
        state["provider_error"] = str(exc)

    for chunk in stream_redact_sensitive_tokens(token_stream, username=username, tenant_id=tenant_id):
        yield chunk


def llm_node(state):

    print("ENTERED LLM NODE")

    # Defensive guard: never call the LLM for pending approval requests
    if state.get("approval_status") == "PENDING_APPROVAL":
        print("LLM NODE: Skipping — approval_status is PENDING_APPROVAL", flush=True)
        return state

    if not state["allowed"]:
        return {
            **state,
            "response": "Policy Violation"
        }

    session_id = state.get(
        "session_id",
        "default"
    )
    tenant_id = state.get("tenant_id", 1)
    prompt = _build_prompt(state)

    print("[Provider Start]", flush=True)
    start_time = time.perf_counter()

    try:
        provider = _resolve_provider(state)
        
        log_agent_event(
            tenant_id=tenant_id,
            session_id=session_id,
            agent_name="LLM Provider",
            event_type="ROUTE_SELECTED",
            details=(
                f"Selected model route: {state.get('provider')} "
                f"({state.get('model')}) via {state.get('provider_route_source')}."
            )
        )
        
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        try:
            future = executor.submit(provider.generate, prompt)
            final_response = future.result(timeout=30.0)
        except concurrent.futures.TimeoutError as te:
            print("[Provider End] Timeout occurred", flush=True)
            raise TimeoutError("Model provider generate call timed out after 30 seconds") from te
        finally:
            executor.shutdown(wait=False)
        duration = time.perf_counter() - start_time
        print(f"[Provider End] Duration: {duration:.4f}s", flush=True)
        
        log_agent_event(
            tenant_id=tenant_id,
            session_id=session_id,
            agent_name="LLM Provider",
            event_type="PROVIDER_RESPONSE_RECEIVED",
            details="Received response successfully from upstream provider."
        )
        
    except Exception as e:
        duration = time.perf_counter() - start_time
        print(f"[Provider End] Duration: {duration:.4f}s", flush=True)
        print(f"LLM Node Provider error: {e}. Returning offline fallback response.")
        
        log_agent_event(
            tenant_id=tenant_id,
            session_id=session_id,
            agent_name="LLM Provider",
            event_type="PROVIDER_FAILOVER",
            details=f"Primary model connection failed: {str(e)}. Falling back to offline provider response."
        )
        final_response = _offline_provider_fallback(str(e))
        state["provider_status"] = "offline_fallback"
        state["provider_error"] = str(e)

    return {
        **state,
        "response": final_response
    }

from typing import Any, Dict, List, Literal, Optional, TypedDict


ProviderStatus = Literal["ready", "ok", "offline_fallback"]
ProviderErrorCode = Literal["provider_timeout", "provider_unavailable", "provider_failure"]


class ProviderError(TypedDict):
    code: ProviderErrorCode
    detail: str


class AuthState(TypedDict, total=False):

    # User Input
    message: str

    session_id: str
    request_id: str
    correlation_id: str
    route_id: Optional[str]
    provider: str
    provider_client: Any
    provider_route_source: Optional[str]
    gateway_api_key: Optional[str]
    model: str
    decision: str
    decision_reason: str
    username: str
    requester_id: str
    original_request_id: Optional[str]
    idempotency_key: Optional[str]
    pre_effect_check: Any

    # Policy Check
    allowed: bool
    block_reason: str
    block_category: str
    security_approved: bool
    security_findings: List[Dict]
    security_policy_action: str
    policy_decision: str
    policy_versions: List[Dict[str, Any]]

    # LLM Response
    response: str

    # RAG Context
    context: str

    # Memory
    history: List[Dict]

    # Task Classification
    task_type: str

    # Risk Engine
    risk_level: str

    # HITL Workflow
    approval_status: str
    approval_id: str
    approval_reason: str

    approved_by: str
    approval_comment: str

    # Policy and Redaction Triggers
    triggered_policies: List[Dict]
    original_query: str
    tenant_id: int
    audit_record_id: int
    provider_status: ProviderStatus
    provider_error: ProviderError


# This inventory is asserted by the graph-boundary tests. Keep it aligned with
# node inputs, node outputs, and fields returned to gateway callers.
GRAPH_STATE_CONTRACT = {
    "inputs": {
        "message", "session_id", "request_id", "correlation_id", "tenant_id",
        "username", "requester_id", "original_request_id", "gateway_api_key", "route_id",
        "provider", "model", "approval_id", "approval_status", "idempotency_key",
        "pre_effect_check",
    },
    "node_outputs": {
        "task_type", "original_query", "security_approved", "security_findings",
        "security_policy_action", "triggered_policies", "allowed", "block_reason",
        "block_category", "policy_decision", "policy_versions", "risk_level",
        "decision", "decision_reason", "approval_id", "approval_status",
        "approval_reason", "provider_client", "provider", "model", "route_id",
        "provider_route_source", "context", "response", "provider_status",
        "provider_error", "audit_record_id",
    },
    "caller_outputs": {
        "request_id", "correlation_id", "original_request_id", "tenant_id",
        "username", "requester_id", "allowed", "block_reason", "block_category", "risk_level",
        "decision", "approval_id", "approval_status", "approval_reason",
        "policy_versions", "provider", "model", "route_id", "response",
        "provider_status", "provider_error", "audit_record_id",
    },
}

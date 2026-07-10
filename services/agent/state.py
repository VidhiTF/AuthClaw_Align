from typing import TypedDict, List, Dict


class AuthState(TypedDict, total=False):

    # User Input
    message: str

    session_id: str
    request_id: str
    route_id: str
    provider: str
    provider_client: object
    provider_route_source: str
    model: str
    decision: str
    decision_reason: str

    # Policy Check
    allowed: bool
    block_reason: str
    block_category: str

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

    approved_by: str
    approval_comment: str

    # Policy and Redaction Triggers
    triggered_policies: List[Dict]
    original_query: str
    tenant_id: int

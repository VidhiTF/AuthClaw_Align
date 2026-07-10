from langgraph.graph import StateGraph, END

from state import AuthState

from nodes.orchestrator_node import orchestrator_node
from nodes.redact_node import redact_node
from nodes.policy_node import policy_node
from nodes.rag_node import rag_node
from nodes.llm_node import llm_node
from nodes.response_checks_node import response_checks_node
from nodes.audit_node import audit_node
from nodes.risk_node import risk_node
from nodes.approval_node import approval_node
from nodes.decision_node import decision_node
from nodes.provider_router_node import provider_router_node


def route_after_policy(state):

    if state.get("allowed", True):
        return "risk"

    return "audit"


def route_after_approval(state):
    """
    Route after the approval node.
    APPROVED  → continue to RAG → LLM → audit
    PENDING   → route to audit node before halting (no LLM, no RAG)
    """
    # Approved requests route through provider_router before RAG and LLM.
    if state.get("approval_status") == "APPROVED":
        return "provider_router"

    return "audit"


workflow = StateGraph(AuthState)

# Nodes

workflow.add_node(
    "orchestrator",
    orchestrator_node
)

workflow.add_node(
    "redact",
    redact_node
)

workflow.add_node(
    "policy",
    policy_node
)

workflow.add_node(
    "risk",
    risk_node
)

workflow.add_node(
    "approval",
    approval_node
)

workflow.add_node(
    "decision",
    decision_node
)

workflow.add_node(
    "provider_router",
    provider_router_node
)

workflow.add_node(
    "rag",
    rag_node
)

workflow.add_node(
    "llm",
    llm_node
)

workflow.add_node(
    "response_checks",
    response_checks_node
)

workflow.add_node(
    "audit",
    audit_node
)

# Entry Point

workflow.set_entry_point(
    "orchestrator"
)

# Flow

workflow.add_edge(
    "orchestrator",
    "redact"
)

workflow.add_edge(
    "redact",
    "policy"
)

workflow.add_conditional_edges(
    "policy",
    route_after_policy,
    {
        "risk": "risk",
        "audit": "audit"
    }
)

workflow.add_edge(
    "risk",
    "decision"
)

workflow.add_edge(
    "decision",
    "approval"
)

workflow.add_conditional_edges(
    "approval",
    route_after_approval,
    {
        "provider_router": "provider_router",
        "audit": "audit"
    }
)

workflow.add_edge(
    "provider_router",
    "rag"
)

workflow.add_edge(
    "rag",
    "llm"
)

workflow.add_edge(
    "llm",
    "response_checks"
)

workflow.add_edge(
    "response_checks",
    "audit"
)

workflow.add_edge(
    "audit",
    END
)

graph = workflow.compile()

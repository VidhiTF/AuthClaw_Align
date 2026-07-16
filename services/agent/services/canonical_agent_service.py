"""Stable response contract for versioned agent capabilities."""

from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional


class CanonicalExecutionError(ValueError):
    """Raised when a canonical execution request is invalid."""


def build_agent_execution_context(
    *,
    tenant_id: int,
    request_id: str,
    correlation_id: Optional[str],
    session_id: Optional[str],
) -> Dict[str, Any]:
    """Create the tenant and correlation fields passed into LangGraph state."""
    return {
        "tenant_id": tenant_id,
        "request_id": request_id,
        "correlation_id": correlation_id or request_id,
        "session_id": session_id or f"session-{request_id}",
    }


@dataclass
class CanonicalAgentService:
    """Wrap existing capabilities in a consistent tenant-scoped API envelope."""

    rag_retriever: Callable[[str], str]
    remediation_runtime_factory: Callable[[], Any]

    @staticmethod
    def _envelope(
        *,
        operation: str,
        tenant_id: int,
        correlation_id: str,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            "api_version": "v1",
            "operation": operation,
            "status": "completed",
            "tenant_id": tenant_id,
            "correlation_id": correlation_id,
            "data": data,
        }

    def execute_rag(
        self,
        *,
        message: Optional[str],
        tenant_id: int,
        correlation_id: str,
    ) -> Dict[str, Any]:
        if not message or not message.strip():
            raise CanonicalExecutionError("message is required for rag execution")
        query = message.strip()
        return self._envelope(
            operation="rag",
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            data={"query": query, "context": self.rag_retriever(query)},
        )

    def create_remediation_plan(
        self,
        *,
        finding_id: Optional[int],
        tenant_id: int,
        correlation_id: str,
    ) -> Dict[str, Any]:
        if finding_id is None or finding_id < 1:
            raise CanonicalExecutionError(
                "finding_id must be a positive integer for remediation_plan execution"
            )
        plan = self.remediation_runtime_factory().create_plan(tenant_id, finding_id)
        return self._envelope(
            operation="remediation_plan",
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            data={"plan": plan},
        )

    def format_chat(
        self,
        *,
        formatted_result: Dict[str, Any],
        tenant_id: int,
        correlation_id: str,
    ) -> Dict[str, Any]:
        envelope = self._envelope(
            operation="chat",
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            data=formatted_result,
        )
        envelope["status"] = formatted_result.get("status", "completed")
        return envelope

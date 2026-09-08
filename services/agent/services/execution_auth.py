"""Authorization contract for the multiplexed canonical agent endpoint."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from services.rbac_matrix import agent_operation_allowed
from services.role_contract import normalize_role


@dataclass(frozen=True)
class AgentExecutionIdentity:
    tenant_id: int
    user_id: str
    role: str


def authorize_agent_operation(
    payload: Mapping[str, object],
    operation: str,
    tenant_id: int,
) -> AgentExecutionIdentity:
    role = normalize_role(payload.get("role"))
    if not agent_operation_allowed(role, operation):
        raise PermissionError("Role is not authorized for this agent operation.")

    user_id = payload.get("sub") or payload.get("email") or payload.get("user_id")
    if not isinstance(user_id, str) or not user_id.strip():
        raise ValueError("Authenticated user identity required.")

    return AgentExecutionIdentity(
        tenant_id=int(tenant_id),
        user_id=user_id.strip(),
        role=role or "",
    )

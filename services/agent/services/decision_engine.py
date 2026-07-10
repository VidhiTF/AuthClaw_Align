from dataclasses import dataclass
from typing import Any, Dict


DECISION_ALLOW = "ALLOW"
DECISION_BLOCK = "BLOCK"
DECISION_REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


@dataclass
class DecisionResult:
    action: str
    reason: str
    risk_level: str


class DecisionEngine:
    def evaluate(self, state: Dict[str, Any]) -> DecisionResult:
        allowed = state.get("allowed", True)
        risk_level = state.get("risk_level", "LOW")
        approval_status = state.get("approval_status")

        if not allowed:
            return DecisionResult(
                action=DECISION_BLOCK,
                reason=state.get("block_reason", "policy_violation"),
                risk_level=risk_level,
            )

        if approval_status == "APPROVED":
            return DecisionResult(
                action=DECISION_ALLOW,
                reason="approval_already_granted",
                risk_level=risk_level,
            )

        if approval_status == "PENDING_APPROVAL" or risk_level == "HIGH":
            return DecisionResult(
                action=DECISION_REQUIRE_APPROVAL,
                reason="high_risk_request",
                risk_level=risk_level,
            )

        return DecisionResult(
            action=DECISION_ALLOW,
            reason="policy_and_risk_checks_passed",
            risk_level=risk_level,
        )


def apply_decision(state: Dict[str, Any]) -> Dict[str, Any]:
    result = DecisionEngine().evaluate(state)
    state["decision"] = result.action
    state["decision_reason"] = result.reason
    return state

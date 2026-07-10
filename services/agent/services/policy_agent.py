from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List

from services.policy_engine import (
    ACTION_ALLOW,
    ACTION_BLOCK,
    ACTION_REDACT,
    ACTION_REQUIRE_APPROVAL,
    PolicyEngine,
)


@dataclass
class PolicyAgentResult:
    approved: bool
    policy_decision: str
    violated_policies: List[Dict[str, Any]] = field(default_factory=list)
    reason: str = ""
    category: str = ""
    redacted_text: str = ""
    risk_level: str = "LOW"
    policy_versions: List[Dict[str, Any]] = field(default_factory=list)


class PolicyAgent:
    def evaluate(self, text: str, username: str = "system", tenant_id: int = None) -> PolicyAgentResult:
        result = PolicyEngine().evaluate(text, tenant_id=tenant_id, username=username)
        for policy in result.findings:
            policy.setdefault("username", username)
            policy.setdefault("timestamp", datetime.now())
            policy.setdefault("tenant_id", tenant_id)

        approved = result.action in {ACTION_ALLOW, ACTION_REDACT}
        category = result.triggered_categories[0].lower() if result.triggered_categories else ""
        return PolicyAgentResult(
            approved=approved,
            policy_decision=result.action,
            violated_policies=result.findings,
            reason=result.reason,
            category=category,
            redacted_text=result.redacted_text,
            risk_level=result.risk_level,
            policy_versions=result.policy_versions,
        )

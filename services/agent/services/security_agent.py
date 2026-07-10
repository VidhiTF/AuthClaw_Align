from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

from redaction import redact_sensitive_data_rich
from risk import calculate_risk
from services.response_inspection import ResponseInspectionService


@dataclass
class SecurityAgentResult:
    approved: bool
    risk_level: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    sanitized_text: str = ""


class SecurityAgent:
    prompt_injection_terms = (
        "ignore previous instructions",
        "ignore all instructions",
        "reveal system prompt",
        "show internal system prompts",
        "disable audit",
        "disable logging",
        "bypass policies",
    )

    def inspect_input(self, text: str, username: str = "system", tenant_id=None) -> SecurityAgentResult:
        risk_level = calculate_risk(text)
        sanitized_text, triggered = redact_sensitive_data_rich(text, username, tenant_id)
        findings = list(triggered)

        lowered = text.lower()
        for term in self.prompt_injection_terms:
            if term in lowered:
                findings.append({
                    "policy_name": "Security Agent",
                    "policy_type": "prompt_injection",
                    "matched_pattern": term,
                    "redacted_value": "N/A",
                    "confidence": 0.97,
                    "action": "block",
                    "username": username,
                })

        actions = {str(finding.get("action", "")).lower() for finding in findings}
        approved = "block" not in actions
        if "block" in actions or "require_approval" in actions:
            risk_level = "HIGH"
        elif findings and risk_level == "LOW":
            risk_level = "MEDIUM"
        return SecurityAgentResult(
            approved=approved,
            risk_level=risk_level,
            findings=findings,
            sanitized_text=sanitized_text,
        )

    def classify_risk(self, text: str) -> str:
        return calculate_risk(text)

    def sanitize_output(self, text: str, username: str = "system", tenant_id=None) -> Tuple[str, List[Dict[str, Any]]]:
        return ResponseInspectionService().inspect(text, username, tenant_id)

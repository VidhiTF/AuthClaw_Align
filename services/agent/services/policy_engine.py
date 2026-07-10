import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import text

from database import engine
from services.sensitive_data_detection import SECRET_TYPES, SensitiveDataDetector


ACTION_ALLOW = "ALLOW"
ACTION_REDACT = "REDACT"
ACTION_BLOCK = "BLOCK"
ACTION_REQUIRE_APPROVAL = "REQUIRE_APPROVAL"

ACTION_PRIORITY = {
    ACTION_ALLOW: 0,
    ACTION_REDACT: 1,
    ACTION_REQUIRE_APPROVAL: 2,
    ACTION_BLOCK: 3,
}

LIFECYCLE_ALLOWED_RULE_KEYS = {
    "action",
    "allowed_topics",
    "blocked_keywords",
    "blocked_topics",
    "categories",
    "category",
    "category_actions",
    "pii_redaction",
    "secret_detection",
    "actions",
}

CATEGORY_PRIORITY = {
    "PROMPT_INJECTION": 0,
    "SECURITY_BYPASS": 1,
    "DATA_EXFILTRATION": 2,
    "SECRETS": 3,
    "PII": 4,
    "FINANCIAL_DATA": 5,
    "MEDICAL_DATA": 6,
    "LEGAL_DATA": 7,
    "CUSTOMER_DEFINED_TOPICS": 8,
}

CATEGORY_ALIASES = {
    "pii": "PII",
    "personal_data": "PII",
    "secrets": "SECRETS",
    "secret": "SECRETS",
    "prompt_injection": "PROMPT_INJECTION",
    "jailbreak": "PROMPT_INJECTION",
    "financial": "FINANCIAL_DATA",
    "financial_data": "FINANCIAL_DATA",
    "medical": "MEDICAL_DATA",
    "medical_data": "MEDICAL_DATA",
    "legal": "LEGAL_DATA",
    "legal_data": "LEGAL_DATA",
    "customer_topic": "CUSTOMER_DEFINED_TOPICS",
    "customer_defined_topics": "CUSTOMER_DEFINED_TOPICS",
    "data_exfiltration": "DATA_EXFILTRATION",
    "security_bypass": "SECURITY_BYPASS",
    "custom": "CUSTOMER_DEFINED_TOPICS",
}

ENTITY_CATEGORIES = {
    "email": "PII",
    "phone": "PII",
    "aadhaar": "PII",
    "pan": "PII",
    "name": "PII",
    "address": "PII",
    "ssn": "PII",
    "credit_card": "FINANCIAL_DATA",
    "financial_identifier": "FINANCIAL_DATA",
    "iban": "FINANCIAL_DATA",
    "medical_identifier": "MEDICAL_DATA",
}

PROMPT_INJECTION_PATTERNS = (
    "ignore previous instructions",
    "ignore all instructions",
    "ignore all company policies",
    "bypass policy",
    "bypass policies",
    "reveal system prompt",
    "show internal system prompts",
    "forget your instructions",
    "developer mode",
    "jailbreak",
)

SECURITY_BYPASS_PATTERNS = (
    "disable logging",
    "disable security logging",
    "disable monitoring",
    "disable audit trails",
    "disable audit logging",
    "disable guardrails",
    "turn off logging",
    "turn off monitoring",
    "turn off audit",
    "bypass security",
    "disable security",
    "remove restrictions",
    "bypass authentication",
    "disable access control",
)

DATA_EXFILTRATION_PATTERNS = (
    "export customer data",
    "export all customer data",
    "export customer record",
    "export every customer",
    "export production database",
    "show me every customer ssn",
    "show me every customer's ssn",
    "show me every customers ssn",
    "reveal ssn",
    "reveal every customer ssn",
    "reveal admin passwords",
    "reveal passwords",
    "reveal hidden admin passwords",
    "reveal secrets",
    "dump database",
    "database dump",
    "download database",
    "download all users",
    "extract records",
    "customer emails",
    "export user data",
    "exfiltrate",
    "steal data",
    "leak data",
)

LEGAL_PATTERNS = (
    "legal advice",
    "lawsuit strategy",
    "privileged communication",
    "attorney client",
    "contract clause",
    "settlement agreement",
)

MEDICAL_PATTERNS = (
    "diagnosis",
    "medical record",
    "patient",
    "prescription",
    "treatment plan",
    "health history",
)

FINANCIAL_PATTERNS = (
    "bank account",
    "routing number",
    "credit card",
    "wire transfer",
    "tax id",
    "financial statement",
)


@dataclass
class TenantPolicy:
    id: Optional[int]
    name: str
    type: str
    rules: Dict[str, Any]
    enabled: bool = True
    tenant_id: Optional[int] = None
    version: int = 1
    status: str = "published"
    severity_level: str = "MEDIUM"


@dataclass
class PolicyFinding:
    policy_name: str
    policy_type: str
    category: str
    action: str
    matched_pattern: str
    reason: str
    confidence: float = 0.8
    policy_id: Optional[int] = None
    policy_version: int = 1
    redacted_value: str = "N/A"
    value_hash: Optional[str] = None
    detector: str = "policy_engine"
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self, username: str = "system", tenant_id: Optional[int] = None) -> Dict[str, Any]:
        return {
            "policy_name": self.policy_name,
            "policy_type": self.policy_type,
            "category": self.category,
            "action": self.action.lower() if self.action else "allow",
            "matched_pattern": self.matched_pattern,
            "reason": self.reason,
            "confidence": round(float(self.confidence), 4),
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "redacted_value": self.redacted_value,
            "value_hash": self.value_hash,
            "detector": self.detector,
            "username": username,
            "tenant_id": tenant_id,
            "timestamp": self.timestamp,
        }


@dataclass
class PolicyEvaluationResult:
    action: str
    allowed: bool
    risk_level: str
    redacted_text: str
    findings: List[Dict[str, Any]]
    policy_versions: List[Dict[str, Any]]
    triggered_categories: List[str]
    reason: str = ""


class PolicyEngine:
    """
    Formal tenant-owned policy evaluator.

    Policy rules remain JSON for backward compatibility, but evaluation is
    normalized into categories and one final governance action.
    """

    def evaluate(
        self,
        text_value: str,
        tenant_id: Optional[int] = None,
        username: str = "system",
        policies: Optional[List[TenantPolicy]] = None,
    ) -> PolicyEvaluationResult:
        active_policies = policies if policies is not None else self.load_policies(tenant_id)
        detector = SensitiveDataDetector(tenant_id=tenant_id)
        redacted_text, detector_findings = detector.redact(text_value, username=username)

        findings: List[PolicyFinding] = []
        findings.extend(self._detector_findings(detector_findings, active_policies))
        findings.extend(self._baseline_security_findings(text_value))
        findings.extend(self._topic_findings(text_value, active_policies))
        findings.extend(self._keyword_findings(text_value, active_policies))

        final_action = self._final_action([finding.action for finding in findings])
        if final_action == ACTION_ALLOW and detector_findings:
            final_action = ACTION_REDACT

        risk_level = self._risk_level(final_action, findings)
        allowed = final_action in {ACTION_ALLOW, ACTION_REDACT}
        reason = self._reason(final_action, findings)

        return PolicyEvaluationResult(
            action=final_action,
            allowed=allowed,
            risk_level=risk_level,
            redacted_text=redacted_text,
            findings=[finding.to_dict(username=username, tenant_id=tenant_id) for finding in findings],
            policy_versions=[
                {
                    "policy_id": policy.id,
                    "name": policy.name,
                    "version": policy.version,
                    "status": policy.status,
                }
                for policy in active_policies
            ],
            triggered_categories=sorted(
                {finding.category for finding in findings},
                key=lambda category: CATEGORY_PRIORITY.get(category, 100),
            ),
            reason=reason,
        )

    def simulate(self, policy_payload: Dict[str, Any], sample_text: str, tenant_id: Optional[int], username: str) -> Dict[str, Any]:
        policy = TenantPolicy(
            id=policy_payload.get("id"),
            name=policy_payload.get("name", "Simulation Policy"),
            type=policy_payload.get("type", "Custom"),
            rules=self.parse_rules(policy_payload.get("rules", {})),
            enabled=bool(policy_payload.get("enabled", True)),
            tenant_id=tenant_id,
            version=int(policy_payload.get("version", 1) or 1),
            status="draft",
            severity_level=policy_payload.get("severity_level", "MEDIUM"),
        )
        result = self.evaluate(sample_text, tenant_id=tenant_id, username=username, policies=[policy])
        return {
            "status": "success",
            "simulation": True,
            "decision": result.action,
            "allowed": result.allowed,
            "risk_level": result.risk_level,
            "redacted_text": result.redacted_text,
            "findings": result.findings,
            "triggered_categories": result.triggered_categories,
            "policy_versions": result.policy_versions,
        }

    def load_policies(self, tenant_id: Optional[int]) -> List[TenantPolicy]:
        params = {}
        if tenant_id is not None:
            params["tenant_id"] = tenant_id
            sql = """
                SELECT id, name, type, rules, enabled, tenant_id,
                       COALESCE(version, 1) AS version,
                       COALESCE(status, 'published') AS status,
                       COALESCE(severity_level, 'MEDIUM') AS severity_level
                FROM policies
                WHERE enabled = TRUE
                  AND (tenant_id = :tenant_id OR tenant_id IS NULL)
                  AND COALESCE(status, 'published') IN ('published', 'active')
                ORDER BY id ASC
            """
        else:
            sql = """
                SELECT id, name, type, rules, enabled, tenant_id,
                       COALESCE(version, 1) AS version,
                       COALESCE(status, 'published') AS status,
                       COALESCE(severity_level, 'MEDIUM') AS severity_level
                FROM policies
                WHERE enabled = TRUE
                  AND tenant_id IS NULL
                  AND COALESCE(status, 'published') IN ('published', 'active')
                ORDER BY id ASC
            """
        with engine.connect() as conn:
            rows = conn.execute(text(sql), params).fetchall()
        return [self._policy_from_row(row) for row in rows]

    def parse_rules(self, rules: Any) -> Dict[str, Any]:
        if isinstance(rules, dict):
            return rules
        if rules is None:
            return {}
        try:
            parsed = json.loads(rules)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}

    def _policy_from_row(self, row) -> TenantPolicy:
        item = dict(row._mapping)
        return TenantPolicy(
            id=item.get("id"),
            name=item.get("name") or "Unnamed Policy",
            type=item.get("type") or "Custom",
            rules=self.parse_rules(item.get("rules")),
            enabled=bool(item.get("enabled", True)),
            tenant_id=item.get("tenant_id"),
            version=int(item.get("version") or 1),
            status=item.get("status") or "published",
            severity_level=item.get("severity_level") or "MEDIUM",
        )

    def _detector_findings(self, detector_findings: List[Dict[str, Any]], policies: List[TenantPolicy]) -> List[PolicyFinding]:
        findings = []
        for item in detector_findings:
            entity = str(item.get("matched_pattern", "")).lower()
            category = "SECRETS" if entity in SECRET_TYPES else ENTITY_CATEGORIES.get(entity, "PII")
            policy = self._matching_policy_for_category(category, policies)
            action = self._action_for_category(category, policy) or self._normalize_action(item.get("action")) or ACTION_REDACT
            findings.append(
                PolicyFinding(
                    policy_name=policy.name if policy else "Sensitive Data Detection",
                    policy_type=policy.type if policy else category,
                    category=category,
                    action=action,
                    matched_pattern=entity,
                    reason=f"{category} detected by {item.get('detector', 'detector')}",
                    confidence=float(item.get("confidence", 0.8)),
                    policy_id=policy.id if policy else None,
                    policy_version=policy.version if policy else 1,
                    redacted_value=str(item.get("redacted_value", "N/A")),
                    value_hash=item.get("value_hash"),
                    detector=str(item.get("detector", "sensitive_data")),
                )
            )
        return findings

    def _baseline_security_findings(self, text_value: str) -> List[PolicyFinding]:
        lowered = text_value.lower()
        findings = []
        for pattern in PROMPT_INJECTION_PATTERNS:
            if pattern in lowered:
                findings.append(
                    PolicyFinding(
                        policy_name="Baseline Prompt Injection Defense",
                        policy_type="prompt_injection",
                        category="PROMPT_INJECTION",
                        action=ACTION_BLOCK,
                        matched_pattern=pattern,
                        reason="Prompt injection pattern matched",
                        confidence=0.97,
                    )
                )
        for pattern in SECURITY_BYPASS_PATTERNS:
            if pattern in lowered:
                findings.append(
                    PolicyFinding(
                        policy_name="Baseline Security Bypass Defense",
                        policy_type="security_bypass",
                        category="SECURITY_BYPASS",
                        action=ACTION_BLOCK,
                        matched_pattern=pattern,
                        reason="Security bypass pattern matched",
                        confidence=0.96,
                    )
                )
        for pattern in DATA_EXFILTRATION_PATTERNS:
            if pattern in lowered:
                findings.append(
                    PolicyFinding(
                        policy_name="Baseline Data Exfiltration Defense",
                        policy_type="data_exfiltration",
                        category="DATA_EXFILTRATION",
                        action=ACTION_BLOCK,
                        matched_pattern=pattern,
                        reason="Data exfiltration pattern matched",
                        confidence=0.96,
                    )
                )
        return findings

    def _topic_findings(self, text_value: str, policies: List[TenantPolicy]) -> List[PolicyFinding]:
        findings: List[PolicyFinding] = []
        lowered = text_value.lower()
        built_ins = [
            ("FINANCIAL_DATA", FINANCIAL_PATTERNS),
            ("MEDICAL_DATA", MEDICAL_PATTERNS),
            ("LEGAL_DATA", LEGAL_PATTERNS),
        ]
        for category, patterns in built_ins:
            policy = self._matching_policy_for_category(category, policies)
            if not policy:
                continue
            for pattern in patterns:
                if pattern in lowered:
                    findings.append(self._topic_finding(policy, category, pattern, "Built-in category topic matched"))

        for policy in policies:
            rules = policy.rules
            for topic in self._list_rules(rules, "blocked_topics"):
                if topic.lower() in lowered:
                    findings.append(self._topic_finding(policy, "CUSTOMER_DEFINED_TOPICS", topic, "Tenant blocked topic matched"))
            allowed_topics = self._list_rules(rules, "allowed_topics")
            if allowed_topics and not any(topic.lower() in lowered for topic in allowed_topics):
                findings.append(self._topic_finding(policy, "CUSTOMER_DEFINED_TOPICS", "outside_allowed_topics", "Prompt is outside tenant allowed topics"))
        return findings

    def _keyword_findings(self, text_value: str, policies: List[TenantPolicy]) -> List[PolicyFinding]:
        findings: List[PolicyFinding] = []
        lowered = text_value.lower()
        for policy in policies:
            for keyword in self._list_rules(policy.rules, "blocked_keywords"):
                if keyword.lower() in lowered:
                    category = self._category_for_policy(policy) or "CUSTOMER_DEFINED_TOPICS"
                    action = self._normalize_action(policy.rules.get("action")) or ACTION_BLOCK
                    findings.append(
                        PolicyFinding(
                            policy_name=policy.name,
                            policy_type=policy.type,
                            category=category,
                            action=action,
                            matched_pattern=keyword,
                            reason="Tenant policy keyword matched",
                            confidence=0.9,
                            policy_id=policy.id,
                            policy_version=policy.version,
                        )
                    )
        return findings

    def _topic_finding(self, policy: TenantPolicy, category: str, pattern: str, reason: str) -> PolicyFinding:
        return PolicyFinding(
            policy_name=policy.name,
            policy_type=policy.type,
            category=category,
            action=self._action_for_category(category, policy) or self._normalize_action(policy.rules.get("action")) or ACTION_REQUIRE_APPROVAL,
            matched_pattern=pattern,
            reason=reason,
            confidence=0.86,
            policy_id=policy.id,
            policy_version=policy.version,
        )

    def _matching_policy_for_category(self, category: str, policies: List[TenantPolicy]) -> Optional[TenantPolicy]:
        normalized = self._normalize_category(category)
        for policy in policies:
            if normalized in self._policy_categories(policy):
                return policy
        return None

    def _policy_categories(self, policy: TenantPolicy) -> List[str]:
        rules = policy.rules
        categories = self._list_rules(rules, "categories")
        if isinstance(rules.get("category"), str):
            categories.append(rules["category"])
        if rules.get("pii_redaction") or "pii" in str(policy.type).lower():
            categories.append("PII")
        if rules.get("secret_detection"):
            categories.append("SECRETS")
        if self._list_rules(rules, "blocked_topics") or self._list_rules(rules, "allowed_topics"):
            categories.append("CUSTOMER_DEFINED_TOPICS")
        policy_type = self._normalize_category(policy.type)
        if policy_type:
            categories.append(policy_type)
        return sorted({self._normalize_category(category) for category in categories if self._normalize_category(category)})

    def _category_for_policy(self, policy: TenantPolicy) -> str:
        categories = self._policy_categories(policy)
        return categories[0] if categories else "CUSTOMER_DEFINED_TOPICS"

    def _action_for_category(self, category: str, policy: Optional[TenantPolicy]) -> Optional[str]:
        if not policy:
            return None
        rules = policy.rules
        category_key = self._normalize_category(category).lower()
        category_rules = rules.get("category_actions") or rules.get("actions") or {}
        for key, value in category_rules.items():
            if self._normalize_category(key).lower() == category_key:
                return self._normalize_action(value)
        return self._normalize_action(rules.get("action"))

    def _normalize_category(self, category: Any) -> str:
        key = str(category or "").strip().lower().replace(" ", "_").replace("-", "_")
        return CATEGORY_ALIASES.get(key, key.upper() if key else "")

    def _normalize_action(self, action: Any) -> Optional[str]:
        key = str(action or "").strip().lower().replace("-", "_").replace(" ", "_")
        if key in {"allow", "allowed"}:
            return ACTION_ALLOW
        if key in {"redact", "mask", "hash", "tokenize"}:
            return ACTION_REDACT
        if key in {"block", "deny", "blocked", "block_or_review"}:
            return ACTION_BLOCK
        if key in {"approval", "require_approval", "approval_required", "human_approval"}:
            return ACTION_REQUIRE_APPROVAL
        return None

    def _list_rules(self, rules: Dict[str, Any], key: str) -> List[str]:
        value = rules.get(key, [])
        if isinstance(value, str):
            return [value]
        if isinstance(value, Iterable):
            return [str(item) for item in value if str(item).strip()]
        return []

    def _final_action(self, actions: List[str]) -> str:
        if not actions:
            return ACTION_ALLOW
        return max((self._normalize_action(action) or ACTION_ALLOW for action in actions), key=lambda action: ACTION_PRIORITY[action])

    def _risk_level(self, final_action: str, findings: List[PolicyFinding]) -> str:
        if final_action == ACTION_BLOCK:
            return "HIGH"
        if final_action == ACTION_REQUIRE_APPROVAL:
            return "HIGH"
        if final_action == ACTION_REDACT or findings:
            return "MEDIUM"
        return "LOW"

    def _reason(self, final_action: str, findings: List[PolicyFinding]) -> str:
        if final_action == ACTION_ALLOW:
            return "policy_checks_passed"
        if not findings:
            return "policy_action_required"
        strongest = max(findings, key=lambda finding: ACTION_PRIORITY.get(finding.action, 0))
        return strongest.reason


def record_policy_history(
    tenant_id: Optional[int],
    policy_id: Optional[int],
    action: str,
    actor: str,
    before_rules: Optional[Dict[str, Any]] = None,
    after_rules: Optional[Dict[str, Any]] = None,
    version: int = 1,
    status: str = "published",
) -> None:
    with engine.connect() as conn:
        conn.execute(
            text("""
                INSERT INTO policy_audit_history (
                    tenant_id, policy_id, action, actor, before_rules, after_rules, version, status, created_at
                )
                VALUES (
                    :tenant_id, :policy_id, :action, :actor, :before_rules, :after_rules, :version, :status, NOW()
                )
            """),
            {
                "tenant_id": tenant_id,
                "policy_id": policy_id,
                "action": action,
                "actor": actor,
                "before_rules": json.dumps(before_rules) if before_rules is not None else None,
                "after_rules": json.dumps(after_rules) if after_rules is not None else None,
                "version": version,
                "status": status,
            },
        )
        conn.commit()


def validate_policy_rules_for_lifecycle(rules: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if not isinstance(rules, dict):
        return ["Policy rules must be a JSON object."]

    if not any(key in rules for key in LIFECYCLE_ALLOWED_RULE_KEYS):
        errors.append("Policy rules must contain at least one enforceable control.")

    unknown_keys = sorted(set(rules) - LIFECYCLE_ALLOWED_RULE_KEYS)
    if unknown_keys:
        errors.append(f"Policy rules contain unsupported keys: {', '.join(unknown_keys)}.")

    engine = PolicyEngine()
    action = rules.get("action")
    if action is not None and engine._normalize_action(action) is None:
        errors.append(f"Policy action '{action}' is not supported.")

    for key in ("blocked_keywords", "blocked_topics", "allowed_topics", "categories"):
        if key not in rules:
            continue
        value = rules.get(key)
        if isinstance(value, str):
            items = [value]
        elif isinstance(value, Iterable) and not isinstance(value, dict):
            items = list(value)
        else:
            errors.append(f"Policy rules.{key} must be a string or list of strings.")
            continue
        if key != "allowed_topics" and len([item for item in items if str(item).strip()]) == 0:
            errors.append(f"Policy rules.{key} must contain at least one non-empty value.")
        for item in items:
            if not isinstance(item, str) or not item.strip():
                errors.append(f"Policy rules.{key} contains an empty or non-string value.")
                break

    for key in ("category_actions", "actions"):
        if key not in rules:
            continue
        value = rules.get(key)
        if not isinstance(value, dict):
            errors.append(f"Policy rules.{key} must be an object.")
            continue
        for category, category_action in value.items():
            if not isinstance(category, str) or not category.strip():
                errors.append(f"Policy rules.{key} contains an invalid category name.")
                break
            if engine._normalize_action(category_action) is None:
                errors.append(f"Policy rules.{key}.{category} action '{category_action}' is not supported.")

    for key in ("pii_redaction", "secret_detection"):
        if key in rules and not isinstance(rules.get(key), bool):
            errors.append(f"Policy rules.{key} must be a boolean.")

    return errors

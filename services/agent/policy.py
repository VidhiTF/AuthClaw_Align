import os
import json
import logging
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger("authclaw.policy")

POLICY_FILE_PATH = os.getenv("POLICY_FILE_PATH", "policies.yaml")
OPA_POLICY_URL = os.getenv("AUTHCLAW_OPA_POLICY_URL", "http://localhost:8181/v1/data/authclaw/policy")
OPA_TIMEOUT_SECONDS = float(os.getenv("AUTHCLAW_OPA_TIMEOUT_SECONDS", "0.25"))
OPA_CIRCUIT_BREAK_SECONDS = float(os.getenv("AUTHCLAW_OPA_CIRCUIT_BREAK_SECONDS", "30"))

_cached_policy = None
_opa_disabled_until = 0.0
_db_policies_cache = {}


def _truthy(value: str, default: bool = True) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def opa_enabled() -> bool:
    return _truthy(os.getenv("AUTHCLAW_OPA_ENABLED"), True)


def opa_required() -> bool:
    env = os.getenv("AUTHCLAW_ENV", "development").strip().lower()
    return env in {"production", "prod"} or _truthy(os.getenv("AUTHCLAW_OPA_REQUIRED"), False)


def _opa_fail_closed(reason: str) -> Dict[str, Any]:
    return {
        "allowed": False,
        "decision": "BLOCK",
        "reason": reason,
        "category": "opa_enforcement",
        "risk_level": "HIGH",
        "findings": [
            {
                "policy_name": "OPA enforcement availability",
                "category": "OPA",
                "action": "BLOCK",
                "reason": reason,
                "confidence": "fail-closed",
            }
        ],
    }


def compile_policy_to_rego(policy: Dict[str, Any]) -> str:
    """
    Generates a deterministic Rego module from AuthClaw YAML policy controls.
    The bundle covers keyword, prompt-injection, secret, PII, PHI, and financial
    redaction categories so sync and gateway enforcement share one policy shape.
    """
    blocked = sorted({str(item).lower() for item in policy.get("blocked_keywords", [])})
    high_risk = sorted({str(item).lower() for item in policy.get("high_risk_keywords", [])})
    medium_risk = sorted({str(item).lower() for item in policy.get("medium_risk_keywords", [])})
    package = (policy.get("opa") or {}).get("package", "authclaw.policy")
    prompt_injection = [
        "ignore previous instructions",
        "ignore all instructions",
        "reveal system prompt",
        "show internal system prompts",
        "forget your instructions",
        "developer mode",
        "jailbreak",
        "bypass policy",
    ]
    security_bypass = [
        "disable logging",
        "disable audit logging",
        "disable monitoring",
        "disable guardrails",
        "bypass security",
        "bypass authentication",
        "disable access control",
    ]
    data_exfiltration = [
        "dump database",
        "export customer data",
        "export production database",
        "download all users",
        "reveal secrets",
        "reveal passwords",
        "exfiltrate",
    ]
    secret_regexes = [
        r"(?i)\beyJ[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}\b",
        r"\bA(KIA|SIA)[A-Z0-9]{16}\b",
        r"\bsk-[A-Za-z0-9_-]{16,}\b",
        r"\bsk-ant-[A-Za-z0-9_-]{16,}\b",
        r"\bSG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        r"\bAIza[0-9A-Za-z_-]{20,}\b",
        r"(?i)\b(api[_-]?key|secret|access[_-]?token|password)\s*[:=]\s*[\"']?[A-Za-z0-9._~+/=-]{12,}",
    ]
    pii_regexes = [
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        r"(?i)(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3,5}\)?[\s.-]?)\d{3,5}[\s.-]?\d{3,6}\b",
        r"\b\d{3}-\d{2}-\d{4}\b",
    ]
    phi_regexes = [
        r"(?i)\b(patient|medical record|mrn|diagnosis|prescription|treatment plan)\b",
    ]
    financial_regexes = [
        r"\b(?:\d[ -]*?){13,19}\b",
        r"(?i)\b(bank account|routing number|iban|wire transfer)\b",
    ]
    return "\n".join(
        [
            f"package {package}",
            "",
            "default allow := true",
            "default decision := \"ALLOW\"",
            "default reason := \"Allowed by AuthClaw OPA policy\"",
            "",
            f"blocked_keywords := {json.dumps(blocked)}",
            f"high_risk_keywords := {json.dumps(high_risk)}",
            f"medium_risk_keywords := {json.dumps(medium_risk)}",
            f"prompt_injection_keywords := {json.dumps(prompt_injection)}",
            f"security_bypass_keywords := {json.dumps(security_bypass)}",
            f"data_exfiltration_keywords := {json.dumps(data_exfiltration)}",
            f"secret_regexes := {json.dumps(secret_regexes)}",
            f"pii_regexes := {json.dumps(pii_regexes)}",
            f"phi_regexes := {json.dumps(phi_regexes)}",
            f"financial_regexes := {json.dumps(financial_regexes)}",
            "",
            "normalized_text := lower(sprintf(\"%v\", [input.text]))",
            "body_text := lower(sprintf(\"%v\", [input.context.body]))",
            "combined_text := concat(\" \", [normalized_text, body_text])",
            "",
            "block if {",
            "  some keyword in blocked_keywords",
            "  contains(combined_text, keyword)",
            "}",
            "",
            "block if {",
            "  some keyword in prompt_injection_keywords",
            "  contains(combined_text, keyword)",
            "}",
            "",
            "block if {",
            "  some keyword in security_bypass_keywords",
            "  contains(combined_text, keyword)",
            "}",
            "",
            "block if {",
            "  some keyword in data_exfiltration_keywords",
            "  contains(combined_text, keyword)",
            "}",
            "",
            "block if {",
            "  some pattern in secret_regexes",
            "  regex.match(pattern, combined_text)",
            "}",
            "",
            "requires_approval if {",
            "  some keyword in high_risk_keywords",
            "  contains(combined_text, keyword)",
            "}",
            "",
            "requires_redaction if {",
            "  some pattern in pii_regexes",
            "  regex.match(pattern, combined_text)",
            "}",
            "",
            "requires_redaction if {",
            "  some pattern in phi_regexes",
            "  regex.match(pattern, combined_text)",
            "}",
            "",
            "requires_redaction if {",
            "  some pattern in financial_regexes",
            "  regex.match(pattern, combined_text)",
            "}",
            "",
            "medium_risk if {",
            "  some keyword in medium_risk_keywords",
            "  contains(combined_text, keyword)",
            "}",
            "",
            "allow := false if block",
            "allow := false if requires_approval",
            "decision := \"BLOCK\" if block",
            "decision := \"REQUIRE_APPROVAL\" if {",
            "  not block",
            "  requires_approval",
            "}",
            "decision := \"REDACT\" if {",
            "  not block",
            "  not requires_approval",
            "  requires_redaction",
            "}",
            "decision := \"REDACT\" if {",
            "  not block",
            "  not requires_approval",
            "  not requires_redaction",
            "  medium_risk",
            "}",
            "reason := \"Blocked by AuthClaw OPA policy\" if block",
            "reason := \"High-risk action requires approval\" if {",
            "  not block",
            "  requires_approval",
            "}",
            "reason := \"Sensitive data requires redaction\" if {",
            "  not block",
            "  not requires_approval",
            "  requires_redaction",
            "}",
            "risk_level := \"HIGH\" if block",
            "risk_level := \"HIGH\" if requires_approval",
            "risk_level := \"MEDIUM\" if requires_redaction",
            "risk_level := \"LOW\" if {",
            "  not block",
            "  not requires_approval",
            "  not requires_redaction",
            "}",
            "",
            "findings contains finding if {",
            "  some keyword in blocked_keywords",
            "  contains(combined_text, keyword)",
            "  finding := {\"policy_name\": \"OPA blocked keyword\", \"category\": \"CUSTOMER_DEFINED_TOPICS\", \"action\": \"BLOCK\", \"matched\": keyword}",
            "}",
            "",
            "findings contains finding if {",
            "  some keyword in prompt_injection_keywords",
            "  contains(combined_text, keyword)",
            "  finding := {\"policy_name\": \"OPA prompt injection\", \"category\": \"PROMPT_INJECTION\", \"action\": \"BLOCK\", \"matched\": keyword}",
            "}",
            "",
            "findings contains finding if {",
            "  some keyword in security_bypass_keywords",
            "  contains(combined_text, keyword)",
            "  finding := {\"policy_name\": \"OPA security bypass\", \"category\": \"SECURITY_BYPASS\", \"action\": \"BLOCK\", \"matched\": keyword}",
            "}",
            "",
            "findings contains finding if {",
            "  some keyword in data_exfiltration_keywords",
            "  contains(combined_text, keyword)",
            "  finding := {\"policy_name\": \"OPA data exfiltration\", \"category\": \"DATA_EXFILTRATION\", \"action\": \"BLOCK\", \"matched\": keyword}",
            "}",
            "",
            "findings contains finding if {",
            "  some pattern in secret_regexes",
            "  regex.match(pattern, combined_text)",
            "  finding := {\"policy_name\": \"OPA secret detector\", \"category\": \"SECRETS\", \"action\": \"BLOCK\", \"matched\": pattern}",
            "}",
            "",
            "findings contains finding if {",
            "  some pattern in pii_regexes",
            "  regex.match(pattern, combined_text)",
            "  finding := {\"policy_name\": \"OPA PII detector\", \"category\": \"PII\", \"action\": \"REDACT\", \"matched\": pattern}",
            "}",
            "",
            "findings contains finding if {",
            "  some pattern in phi_regexes",
            "  regex.match(pattern, combined_text)",
            "  finding := {\"policy_name\": \"OPA PHI detector\", \"category\": \"MEDICAL_DATA\", \"action\": \"REDACT\", \"matched\": pattern}",
            "}",
            "",
            "findings contains finding if {",
            "  some pattern in financial_regexes",
            "  regex.match(pattern, combined_text)",
            "  finding := {\"policy_name\": \"OPA financial detector\", \"category\": \"FINANCIAL_DATA\", \"action\": \"REDACT\", \"matched\": pattern}",
            "}",
        ]
    )


def build_opa_bundle(policy: Dict[str, Any]) -> Dict[str, Any]:
    rego = compile_policy_to_rego(policy)
    opa_config = policy.get("opa") or {}
    manifest = {
        "revision": opa_config.get("bundle_version") or policy.get("version"),
        "roots": ["authclaw"],
        "metadata": {
            "policy_version": policy.get("version"),
            "package": opa_config.get("package", "authclaw.policy"),
            "fail_closed": bool(opa_config.get("fail_closed", True)),
        },
    }
    return {
        ".manifest": manifest,
        "authclaw.rego": rego,
    }


def write_opa_bundle(policy: Dict[str, Any], bundle_dir: str) -> Dict[str, Any]:
    bundle = build_opa_bundle(policy)
    target = Path(bundle_dir)
    target.mkdir(parents=True, exist_ok=True)
    (target / ".manifest").write_text(json.dumps(bundle[".manifest"], indent=2, sort_keys=True), encoding="utf-8")
    (target / "authclaw.rego").write_text(bundle["authclaw.rego"], encoding="utf-8")
    return bundle


def _normalize_opa_result(result: Any) -> Dict[str, Any]:
    if isinstance(result, dict) and "result" in result:
        result = result["result"]
    if not isinstance(result, dict):
        return {}

    decision = str(result.get("decision") or "").upper()
    allowed_value = result.get("allow", result.get("allowed"))
    if allowed_value is None:
        allowed = decision not in {"BLOCK", "DENY", "REQUIRE_APPROVAL"}
    else:
        allowed = bool(allowed_value)

    if result.get("block") is True:
        decision = "BLOCK"
        allowed = False
    elif result.get("requires_approval") is True and decision == "":
        decision = "REQUIRE_APPROVAL"
        allowed = False
    elif decision == "":
        decision = "ALLOW" if allowed else "BLOCK"

    findings = result.get("findings") or result.get("matched_policies") or []
    if isinstance(findings, dict):
        findings = [findings]

    return {
        "allowed": allowed,
        "decision": decision,
        "reason": result.get("reason") or result.get("explanation") or "OPA policy decision",
        "category": result.get("category") or "opa",
        "findings": findings if isinstance(findings, list) else [],
        "risk_level": result.get("risk_level"),
    }


def evaluate_opa_policy(text: str, tenant_id=None, context: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Best-effort OPA evaluator. Returns an empty dict when OPA is disabled,
    down, or returns a shape AuthClaw cannot safely interpret.
    """
    global _opa_disabled_until
    required = opa_required()
    if not opa_enabled():
        if required:
            return _opa_fail_closed("OPA enforcement is required but AUTHCLAW_OPA_ENABLED is false.")
        return {}
    if time.time() < _opa_disabled_until:
        if required:
            return _opa_fail_closed("OPA enforcement is required but the OPA circuit breaker is open.")
        return {}

    payload = {
        "input": {
            "text": text or "",
            "tenant_id": tenant_id,
            "context": context or {},
        }
    }
    request = urllib.request.Request(
        OPA_POLICY_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=OPA_TIMEOUT_SECONDS) as response:  # nosec B310
            if response.status < 200 or response.status >= 300:
                if required:
                    return _opa_fail_closed(f"OPA policy endpoint returned HTTP {response.status}.")
                return {}
            body = json.loads(response.read().decode("utf-8") or "{}")
            return _normalize_opa_result(body)
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        _opa_disabled_until = time.time() + OPA_CIRCUIT_BREAK_SECONDS
        logger.info("OPA unavailable; falling back to local policy engine: %s", type(exc).__name__)
        if required:
            return _opa_fail_closed(f"OPA enforcement is required but unavailable: {type(exc).__name__}.")
        return {}

def get_policy() -> Dict[str, Any]:
    """
    Returns the currently cached policy, loading it from policies.yaml if not cached.
    """
    global _cached_policy
    if _cached_policy is None:
        load_policy()
    return _cached_policy

def load_policy() -> Dict[str, Any]:
    """
    Loads, validates, and caches the policy from policies.yaml.
    """
    global _cached_policy
    try:
        from startup.validation import load_and_validate_policy
        policy = load_and_validate_policy(POLICY_FILE_PATH)
        _cached_policy = policy
        success_log = {
            "event": "policy_loaded",
            "status": "success",
            "message": "Policy loaded successfully.",
            "details": {
                "version": policy["version"],
                "blocked_keywords_count": len(policy["blocked_keywords"]),
                "high_risk_keywords_count": len(policy["high_risk_keywords"]),
                "medium_risk_keywords_count": len(policy["medium_risk_keywords"]),
                "redaction_rules": policy["redaction"]
            }
        }
        logger.info(json.dumps(success_log))
        print(json.dumps(success_log), flush=True)
        return policy
    except Exception as e:
        failure_log = {
            "event": "policy_loaded",
            "status": "failed",
            "message": f"Policy loading failed: {str(e)}"
        }
        logger.error(json.dumps(failure_log))
        print(json.dumps(failure_log), flush=True)
        raise e

def is_blocked(text: str) -> bool:
    """
    Checks if a given text contains any blocked keywords defined in the policy.
    """
    opa_result = evaluate_opa_policy(text)
    if opa_result:
        return opa_result.get("decision") == "BLOCK" or not opa_result.get("allowed", True)
    policy = get_policy()
    text_lower = text.lower()
    for word in policy["blocked_keywords"]:
        if word in text_lower:
            return True
    return False

def is_high_risk(text: str) -> bool:
    """
    Checks if a given text contains any high risk keywords defined in the policy.
    """
    opa_result = evaluate_opa_policy(text)
    if opa_result:
        return opa_result.get("decision") == "REQUIRE_APPROVAL" or opa_result.get("risk_level") == "HIGH"
    policy = get_policy()
    text_lower = text.lower()
    for word in policy["high_risk_keywords"]:
        if word in text_lower:
            return True
    return False

def get_db_policies(tenant_id=None):
    """
    Retrieves active policies from the database.
    """
    current_time = time.time()
    if "PYTEST_CURRENT_TEST" not in os.environ and tenant_id in _db_policies_cache:
        cached_time, cached_val = _db_policies_cache[tenant_id]
        if current_time - cached_time < 2.0:
            return cached_val

    try:
        from database import engine
        from sqlalchemy import text
        with engine.connect() as conn:
            if tenant_id is None:
                res = conn.execute(text("SELECT id, name, type, rules, enabled, tenant_id FROM policies WHERE enabled = true"))
            else:
                res = conn.execute(
                    text("SELECT id, name, type, rules, enabled, tenant_id FROM policies WHERE enabled = true AND tenant_id = :tenant_id"),
                    {"tenant_id": tenant_id},
                )
            policies = []
            for row in res:
                p_dict = dict(row._mapping)
                try:
                    if isinstance(p_dict["rules"], str):
                        p_dict["rules"] = json.loads(p_dict["rules"])
                except Exception:
                    pass
                policies.append(p_dict)
            if "PYTEST_CURRENT_TEST" not in os.environ:
                _db_policies_cache[tenant_id] = (current_time, policies)
            return policies
    except Exception as e:
        logger.warning(f"Error fetching active policies from DB: {e}")
        return []

def validate_policy(text: str, tenant_id=None) -> bool:
    """
    Validates if a text is allowed under the current policy (does not contain blocked keywords).
    Maintains backward compatibility.
    """
    from services.policy_engine import ACTION_BLOCK, ACTION_REQUIRE_APPROVAL, PolicyEngine

    opa_result = evaluate_opa_policy(text, tenant_id=tenant_id)
    if opa_result:
        return bool(opa_result.get("allowed", True))

    result = PolicyEngine().evaluate(text, tenant_id=tenant_id)
    return result.action not in {ACTION_BLOCK, ACTION_REQUIRE_APPROVAL}

def check_policy_violations(text: str, tenant_id=None) -> tuple:
    """
    Checks if a given text violates policies, and returns a tuple (allowed, triggered_blocks).
    If allowed is False, triggered_blocks will contain metadata about the blocking policy.
    """
    from services.policy_engine import ACTION_BLOCK, ACTION_REQUIRE_APPROVAL, PolicyEngine

    opa_result = evaluate_opa_policy(text, tenant_id=tenant_id)
    if opa_result:
        if not opa_result.get("allowed", True):
            findings = opa_result.get("findings") or [{
                "policy_name": "OPA Policy",
                "category": opa_result.get("category", "opa"),
                "action": opa_result.get("decision", "BLOCK"),
                "reason": opa_result.get("reason", "OPA policy decision"),
            }]
            return False, findings
        return True, []

    result = PolicyEngine().evaluate(text, tenant_id=tenant_id)
    blocking_findings = [
        finding for finding in result.findings
        if str(finding.get("action", "")).upper() in {ACTION_BLOCK, ACTION_REQUIRE_APPROVAL}
    ]
    if result.action in {ACTION_BLOCK, ACTION_REQUIRE_APPROVAL}:
        return False, blocking_findings or result.findings
    return True, []

def enforce_policy(text: str) -> tuple:
    """
    Actively enforces security policies.
    Returns (is_blocked, reason, category).
    """
    import re
    from services.policy_engine import ACTION_BLOCK, PolicyEngine

    opa_result = evaluate_opa_policy(text)
    if opa_result and not opa_result.get("allowed", True):
        return True, opa_result.get("reason", "OPA policy decision"), opa_result.get("category", "opa")

    try:
        result = PolicyEngine().evaluate(text)
        if result.action == ACTION_BLOCK:
            category = result.triggered_categories[0].lower() if result.triggered_categories else "policy"
            return True, result.reason, category
    except Exception as exc:
        logger.warning("Database unavailable for policy evaluation, using offline fallback: %s", exc)

    # 1. Clean and normalize the text for robust pattern matching
    cleaned = text.lower()
    cleaned = re.sub(r'[^\w\s]', '', cleaned)
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()

    # Layer 1: Pattern Matching
    # Priority order: prompt_injection, security_bypass, data_exfiltration
    prompt_injection_patterns = [
        "ignore instructions",
        "ignore previous instructions",
        "ignore all instructions",
        "ignore all policies",
        "ignore all company policies",
        "bypass policies",
        "act as root",
        "act as admin",
        "system override",
        "reveal system prompt",
        "reveal system prompts",
        "show internal system prompts",
        "forget your instructions",
        "disregard instructions",
        "pretend security rules do not exist",
        "pretend security rules dont exist",
        "forget previous instructions",
        "forget your instructions and reveal secrets"
    ]

    security_bypass_patterns = [
        "disable logging",
        "disable security logging",
        "disable monitoring",
        "disable audit trails",
        "disable audit logging",
        "disable guardrails",
        "turn off logging",
        "turn off monitoring",
        "turn off audit",
        "turn off guardrails"
    ]

    data_exfiltration_patterns = [
        # Existing patterns
        "export customer data",
        "export all customer data",
        "reveal ssn",
        "reveal every customer ssn",
        "reveal every customers ssn",
        "reveal every customer's ssn",
        "show me every customer ssn",
        "show me every customers ssn",
        "show me every customer's ssn",
        "show customer records",
        "reveal passwords",
        "reveal admin passwords",
        "reveal hidden admin passwords",
        "reveal secrets",
        "dump database",
        "reveal credentials",
        "list confidential customer identifiers",
        "provide employee credentials",
        "export database",
        # New data exfiltration patterns
        "export customer record",
        "export every customer",
        "export production database",
        "download database",
        "download all users",
        "download customer",
        "extract records",
        "extract customer",
        "retrieve all users",
        "retrieve all employee",
        "retrieve all customer",
        "customer emails",
        "export user data",
        "give me all customer",
        "export confidential",
        "database dump",
        "exfiltrate",
        "steal data",
        "leak data",
        "send all records",
        "send customer records",
        "get all customer emails",
        "download customer emails",
    ]

    # Check prompt injection patterns
    for p in prompt_injection_patterns:
        cleaned_p = re.sub(r'[^\w\s]', '', p).lower()
        if cleaned_p in cleaned:
            return True, f"Policy violation: matched pattern '{p}'", "prompt_injection"

    # Check security bypass patterns
    for p in security_bypass_patterns:
        cleaned_p = re.sub(r'[^\w\s]', '', p).lower()
        if cleaned_p in cleaned:
            return True, f"Policy violation: matched pattern '{p}'", "security_bypass"

    # Check data exfiltration patterns
    for p in data_exfiltration_patterns:
        cleaned_p = re.sub(r'[^\w\s]', '', p).lower()
        if cleaned_p in cleaned:
            return True, f"Policy violation: matched pattern '{p}'", "data_exfiltration"

    # Layer 2: Static semantic keyword expansion (no LLM call to conserve API quota)
    # The LLM call was causing double API usage and 429 rate limits.
    # Static heuristics + Risk Engine together provide sufficient protection.

    # Additional prompt injection patterns
    prompt_injection_phrases = [
        "ignore all previous", "ignore previous instructions", "disregard your instructions",
        "you are now", "act as if", "pretend you are", "roleplay as", "simulate a",
        "override your", "bypass your", "your new instructions", "forget your training",
        "reveal your system prompt", "show me your instructions", "what are your instructions",
        "disable your filters", "turn off your", "jailbreak", "dan mode", "developer mode"
    ]
    for phrase in prompt_injection_phrases:
        if phrase in cleaned:
            return True, f"Policy violation: prompt injection pattern '{phrase}'", "prompt_injection"

    # Additional security bypass patterns
    security_bypass_phrases = [
        "disable logging", "turn off logging", "disable audit", "disable monitoring",
        "bypass security", "disable security", "turn off monitoring", "disable guardrail",
        "remove restrictions", "disable restrictions", "bypass authentication",
        "disable access control", "turn off access control", "disable firewall"
    ]
    for phrase in security_bypass_phrases:
        if phrase in cleaned:
            return True, f"Policy violation: security bypass pattern '{phrase}'", "security_bypass"

    return False, "", ""

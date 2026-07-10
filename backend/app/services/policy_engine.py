"""Policy validation, simulation, and activation helpers.

The gateway is the runtime enforcement point. This module is the control-plane
contract used before a policy can become active, and by dry-run/simulation APIs
so admins can understand decisions before routing live traffic.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal
import re
import yaml


PolicyDecision = Literal["allow", "block", "require_approval"]


ALLOWED_TOP_LEVEL_KEYS = {"model_rules", "regex_rules", "topic_rules", "rate_limits"}
ALLOWED_MODEL_RULE_KEYS = {"whitelist", "blacklist"}
ALLOWED_REGEX_RULE_KEYS = {
    "name",
    "pattern",
    "reason",
    "severity",
    "action",
    "entity",
    "hitl_timeout_seconds",
}
ALLOWED_TOPIC_RULE_KEYS = {"topic", "allowed_models", "reason"}
ALLOWED_RATE_LIMIT_KEYS = {"requests_per_minute"}
ALLOWED_REGEX_ACTIONS = {"redact", "require_approval", "block"}
ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}

MAX_POLICY_BYTES = 64 * 1024
MAX_MODEL_RULES = 200
MAX_REGEX_RULES = 100
MAX_TOPIC_RULES = 100
MAX_PATTERN_LENGTH = 512
MAX_REASON_LENGTH = 1000
MAX_RPM = 100_000
DEFAULT_HITL_TIMEOUT_SECONDS = 1800


class PolicyValidationError(ValueError):
    """Raised when policy YAML cannot be safely activated."""

    def __init__(self, errors: list[dict[str, str]], warnings: list[dict[str, str]] | None = None):
        self.errors = errors
        self.warnings = warnings or []
        message = "; ".join(error["message"] for error in errors) or "Invalid policy"
        super().__init__(message)


@dataclass
class RuleExplanation:
    stage: str
    outcome: str
    message: str
    rule_name: str | None = None
    rule_type: str | None = None
    severity: str | None = None
    prompt_index: int | None = None
    matched_text_preview: str | None = None

    def as_dict(self) -> dict[str, Any]:
        data = {
            "stage": self.stage,
            "outcome": self.outcome,
            "message": self.message,
        }
        for key in ("rule_name", "rule_type", "severity", "prompt_index", "matched_text_preview"):
            value = getattr(self, key)
            if value is not None:
                data[key] = value
        return data


@dataclass
class PolicySimulationResult:
    decision: PolicyDecision
    allow: bool
    reason: str
    explanations: list[RuleExplanation] = field(default_factory=list)
    matched_rules: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "allow": self.allow,
            "reason": self.reason,
            "explanations": [item.as_dict() for item in self.explanations],
            "matched_rules": self.matched_rules,
        }


def _err(path: str, message: str) -> dict[str, str]:
    return {"path": path, "message": message}


def _warn(path: str, message: str) -> dict[str, str]:
    return {"path": path, "message": message}


def _string_list(value: Any, path: str, errors: list[dict[str, str]], *, allow_empty: bool = True) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        errors.append(_err(path, "must be a list"))
        return []
    normalized: list[str] = []
    seen: set[str] = set()
    for idx, item in enumerate(value):
        item_path = f"{path}[{idx}]"
        if not isinstance(item, str) or not item.strip():
            errors.append(_err(item_path, "must be a non-empty string"))
            continue
        text = item.strip()
        lowered = text.lower()
        if lowered in seen:
            errors.append(_err(item_path, f"duplicate value {text!r}"))
            continue
        seen.add(lowered)
        normalized.append(text)
    if not allow_empty and not normalized:
        errors.append(_err(path, "must include at least one value"))
    return normalized


def _unknown_keys(obj: dict[str, Any], allowed: set[str], path: str, errors: list[dict[str, str]]) -> None:
    for key in sorted(set(obj.keys()) - allowed):
        errors.append(_err(f"{path}.{key}" if path else key, "unknown field"))


def _normalize_policy(raw: dict[str, Any], errors: list[dict[str, str]], warnings: list[dict[str, str]]) -> dict[str, Any]:
    _unknown_keys(raw, ALLOWED_TOP_LEVEL_KEYS, "", errors)
    normalized: dict[str, Any] = {
        "model_rules": {"whitelist": [], "blacklist": []},
        "regex_rules": [],
        "topic_rules": [],
        "rate_limits": {"requests_per_minute": 0},
    }

    model_rules = raw.get("model_rules") or {}
    if not isinstance(model_rules, dict):
        errors.append(_err("model_rules", "must be an object"))
    else:
        _unknown_keys(model_rules, ALLOWED_MODEL_RULE_KEYS, "model_rules", errors)
        whitelist = _string_list(model_rules.get("whitelist", []), "model_rules.whitelist", errors)
        blacklist = _string_list(model_rules.get("blacklist", []), "model_rules.blacklist", errors)
        if len(whitelist) + len(blacklist) > MAX_MODEL_RULES:
            errors.append(_err("model_rules", f"cannot contain more than {MAX_MODEL_RULES} model entries"))
        overlap = sorted({item.lower() for item in whitelist}.intersection(item.lower() for item in blacklist))
        if overlap:
            errors.append(_err("model_rules", f"models cannot be both whitelisted and blacklisted: {', '.join(overlap)}"))
        normalized["model_rules"] = {"whitelist": whitelist, "blacklist": blacklist}
        if not whitelist:
            warnings.append(_warn("model_rules.whitelist", "empty whitelist allows any model unless another rule blocks it"))

    regex_rules = raw.get("regex_rules") or []
    if not isinstance(regex_rules, list):
        errors.append(_err("regex_rules", "must be a list"))
    elif len(regex_rules) > MAX_REGEX_RULES:
        errors.append(_err("regex_rules", f"cannot contain more than {MAX_REGEX_RULES} rules"))
    else:
        seen_names: set[str] = set()
        for idx, rule in enumerate(regex_rules):
            path = f"regex_rules[{idx}]"
            if not isinstance(rule, dict):
                errors.append(_err(path, "must be an object"))
                continue
            _unknown_keys(rule, ALLOWED_REGEX_RULE_KEYS, path, errors)
            name = str(rule.get("name") or f"regex_rule_{idx + 1}").strip()
            if not name:
                errors.append(_err(f"{path}.name", "must be a non-empty string when provided"))
                name = f"regex_rule_{idx + 1}"
            name_key = name.lower()
            if name_key in seen_names:
                errors.append(_err(f"{path}.name", f"duplicate rule name {name!r}"))
            seen_names.add(name_key)

            pattern = rule.get("pattern")
            if not isinstance(pattern, str) or not pattern.strip():
                errors.append(_err(f"{path}.pattern", "missing pattern string"))
                continue
            pattern = pattern.strip()
            if len(pattern) > MAX_PATTERN_LENGTH:
                errors.append(_err(f"{path}.pattern", f"must be {MAX_PATTERN_LENGTH} characters or fewer"))
            try:
                compiled = re.compile(pattern)
                if compiled.match(""):
                    errors.append(_err(f"{path}.pattern", "must not match an empty string"))
            except re.error as exc:
                errors.append(_err(f"{path}.pattern", f"invalid regex pattern: {exc}"))
                continue

            action = str(rule.get("action") or "redact").strip().lower()
            if action not in ALLOWED_REGEX_ACTIONS:
                errors.append(_err(f"{path}.action", "must be redact, require_approval, or block"))
            severity = str(rule.get("severity") or "medium").strip().lower()
            if severity not in ALLOWED_SEVERITIES:
                errors.append(_err(f"{path}.severity", "must be low, medium, high, or critical"))
            reason = str(rule.get("reason") or "").strip()
            if len(reason) > MAX_REASON_LENGTH:
                errors.append(_err(f"{path}.reason", f"must be {MAX_REASON_LENGTH} characters or fewer"))
            if action in {"block", "require_approval"} and not reason:
                errors.append(_err(f"{path}.reason", f"reason is required for {action} rules"))

            timeout = rule.get("hitl_timeout_seconds", DEFAULT_HITL_TIMEOUT_SECONDS)
            if action == "require_approval":
                if not isinstance(timeout, int) or timeout < 10 or timeout > DEFAULT_HITL_TIMEOUT_SECONDS:
                    errors.append(_err(f"{path}.hitl_timeout_seconds", "must be an integer between 10 and 1800"))
            elif "hitl_timeout_seconds" in rule:
                warnings.append(_warn(f"{path}.hitl_timeout_seconds", "ignored unless action is require_approval"))

            normalized["regex_rules"].append({
                "name": name,
                "pattern": pattern,
                "reason": reason,
                "severity": severity,
                "action": action,
                "entity": str(rule.get("entity") or "").strip(),
                "hitl_timeout_seconds": timeout if action == "require_approval" else DEFAULT_HITL_TIMEOUT_SECONDS,
            })

    topic_rules = raw.get("topic_rules") or []
    if not isinstance(topic_rules, list):
        errors.append(_err("topic_rules", "must be a list"))
    elif len(topic_rules) > MAX_TOPIC_RULES:
        errors.append(_err("topic_rules", f"cannot contain more than {MAX_TOPIC_RULES} rules"))
    else:
        seen_topics: set[str] = set()
        for idx, rule in enumerate(topic_rules):
            path = f"topic_rules[{idx}]"
            if not isinstance(rule, dict):
                errors.append(_err(path, "must be an object"))
                continue
            _unknown_keys(rule, ALLOWED_TOPIC_RULE_KEYS, path, errors)
            topic = rule.get("topic")
            if not isinstance(topic, str) or not topic.strip():
                errors.append(_err(f"{path}.topic", "missing topic string"))
                continue
            topic = topic.strip().lower()
            if topic in seen_topics:
                errors.append(_err(f"{path}.topic", f"duplicate topic {topic!r}"))
            seen_topics.add(topic)
            allowed_models = _string_list(rule.get("allowed_models"), f"{path}.allowed_models", errors, allow_empty=False)
            reason = str(rule.get("reason") or "").strip()
            if len(reason) > MAX_REASON_LENGTH:
                errors.append(_err(f"{path}.reason", f"must be {MAX_REASON_LENGTH} characters or fewer"))
            if not reason:
                errors.append(_err(f"{path}.reason", "reason is required for topic rules"))
            normalized["topic_rules"].append({
                "topic": topic,
                "allowed_models": allowed_models,
                "reason": reason,
            })

    rate_limits = raw.get("rate_limits") or {}
    if not isinstance(rate_limits, dict):
        errors.append(_err("rate_limits", "must be an object"))
    else:
        _unknown_keys(rate_limits, ALLOWED_RATE_LIMIT_KEYS, "rate_limits", errors)
        rpm = rate_limits.get("requests_per_minute", 0)
        if not isinstance(rpm, int) or rpm < 0 or rpm > MAX_RPM:
            errors.append(_err("rate_limits.requests_per_minute", f"must be an integer between 0 and {MAX_RPM}"))
            rpm = 0
        if rpm == 0:
            warnings.append(_warn("rate_limits.requests_per_minute", "0 disables policy-level request throttling"))
        normalized["rate_limits"] = {"requests_per_minute": rpm}

    return normalized


def validate_policy_yaml(policy_yaml: str) -> dict[str, Any]:
    """Return a structured validation report. Raises PolicyValidationError on hard errors."""
    errors: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []
    if not isinstance(policy_yaml, str) or not policy_yaml.strip():
        raise PolicyValidationError([_err("policy_yaml", "must be a non-empty YAML string")])
    if len(policy_yaml.encode("utf-8")) > MAX_POLICY_BYTES:
        raise PolicyValidationError([_err("policy_yaml", f"must be {MAX_POLICY_BYTES} bytes or smaller")])
    try:
        raw = yaml.safe_load(policy_yaml)
    except yaml.YAMLError as exc:
        raise PolicyValidationError([_err("policy_yaml", f"invalid YAML syntax: {exc}")])
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise PolicyValidationError([_err("policy_yaml", "must be a dictionary/object")])

    normalized = _normalize_policy(raw, errors, warnings)
    if errors:
        raise PolicyValidationError(errors, warnings)

    stats = {
        "model_whitelist_count": len(normalized["model_rules"]["whitelist"]),
        "model_blacklist_count": len(normalized["model_rules"]["blacklist"]),
        "regex_rule_count": len(normalized["regex_rules"]),
        "topic_rule_count": len(normalized["topic_rules"]),
        "requests_per_minute": normalized["rate_limits"]["requests_per_minute"],
    }
    return {
        "valid": True,
        "errors": [],
        "warnings": warnings,
        "normalized_policy": normalized,
        "stats": stats,
    }


def _preview(value: str, limit: int = 80) -> str:
    value = value.replace("\n", " ").strip()
    return value[:limit] + ("..." if len(value) > limit else "")


def simulate_policy(policy_yaml: str, *, model: str, route: str = "", prompts: list[str] | None = None,
                    topics: list[str] | None = None, rate_limit_exceeded: bool = False) -> PolicySimulationResult:
    report = validate_policy_yaml(policy_yaml)
    policy = report["normalized_policy"]
    prompts = prompts or []
    topics = [topic.strip().lower() for topic in (topics or []) if isinstance(topic, str) and topic.strip()]
    explanations: list[RuleExplanation] = []
    matched_rules: list[dict[str, Any]] = []

    if rate_limit_exceeded:
        explanation = RuleExplanation(
            stage="rate_limits",
            outcome="block",
            message="Rate limit exceeded for this tenant/route.",
            rule_type="rate_limit",
        )
        return PolicySimulationResult("block", False, explanation.message, [explanation], [{"type": "rate_limit", "route": route}])

    blacklist = policy["model_rules"]["blacklist"]
    whitelist = policy["model_rules"]["whitelist"]
    if model in blacklist:
        explanation = RuleExplanation(
            stage="model_rules",
            outcome="block",
            message=f"Model {model!r} is blacklisted.",
            rule_type="model_blacklist",
        )
        return PolicySimulationResult("block", False, explanation.message, [explanation], [{"type": "model_blacklist", "model": model}])
    explanations.append(RuleExplanation("model_rules", "pass", f"Model {model!r} is not blacklisted.", "model_blacklist"))

    if whitelist and model not in whitelist:
        explanation = RuleExplanation(
            stage="model_rules",
            outcome="block",
            message=f"Model {model!r} is not in whitelist.",
            rule_type="model_whitelist",
        )
        return PolicySimulationResult("block", False, explanation.message, explanations + [explanation], [{"type": "model_whitelist", "model": model}])
    if whitelist:
        explanations.append(RuleExplanation("model_rules", "pass", f"Model {model!r} is whitelisted.", "model_whitelist"))

    for rule in policy["regex_rules"]:
        compiled = re.compile(rule["pattern"])
        for idx, prompt in enumerate(prompts):
            match = compiled.search(prompt)
            if not match:
                continue
            matched = {
                "type": "regex",
                "name": rule["name"],
                "action": rule["action"],
                "severity": rule["severity"],
                "prompt_index": idx,
                "matched_text_preview": _preview(match.group(0)),
            }
            matched_rules.append(matched)
            message = f"Policy rule {rule['name']!r} action={rule['action']} matched: {rule['reason'] or 'regex matched'}"
            explanations.append(RuleExplanation(
                stage="regex_rules",
                outcome=rule["action"],
                message=message,
                rule_name=rule["name"],
                rule_type="regex",
                severity=rule["severity"],
                prompt_index=idx,
                matched_text_preview=_preview(match.group(0)),
            ))
            if rule["action"] == "block":
                return PolicySimulationResult("block", False, message, explanations, matched_rules)
            if rule["action"] == "require_approval":
                return PolicySimulationResult("require_approval", False, message, explanations, matched_rules)
    if policy["regex_rules"]:
        explanations.append(RuleExplanation("regex_rules", "pass", "No blocking or approval regex rules matched.", "regex"))

    for rule in policy["topic_rules"]:
        if rule["topic"] not in topics:
            continue
        if model not in rule["allowed_models"]:
            message = f"Topic block: {rule['reason']}"
            explanations.append(RuleExplanation(
                stage="topic_rules",
                outcome="block",
                message=message,
                rule_name=rule["topic"],
                rule_type="topic",
            ))
            matched_rules.append({"type": "topic", "topic": rule["topic"], "model": model})
            return PolicySimulationResult("block", False, message, explanations, matched_rules)
        explanations.append(RuleExplanation(
            stage="topic_rules",
            outcome="pass",
            message=f"Topic {rule['topic']!r} is allowed on model {model!r}.",
            rule_name=rule["topic"],
            rule_type="topic",
        ))

    explanations.append(RuleExplanation("final", "allow", "No policy rule blocked the request."))
    return PolicySimulationResult("allow", True, "Allowed by AuthClaw policy simulation", explanations, matched_rules)

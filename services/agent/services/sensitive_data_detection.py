import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple

from policy import get_policy


SECRET_TYPES = {
    "openai_api_key",
    "google_api_key",
    "aws_access_key",
    "jwt_token",
    "bearer_token",
    "api_key_param",
    "secret_param",
    "token_param",
    "access_token",
    "private_key",
}


@dataclass
class SensitiveFinding:
    entity_type: str
    start: int
    end: int
    value: str
    confidence: float
    source: str


class SensitiveDataDetector:
    """
    Production sensitive-data detector.

    Presidio is used when installed. Custom regex recognizers cover India-specific
    identifiers and common cloud/API secrets so the gateway stays useful even in
    offline developer environments.
    """

    custom_patterns: Tuple[Tuple[str, re.Pattern, float], ...] = (
        ("email", re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}"), 0.96),
        ("phone", re.compile(r"(?<!\d)(?:\+91[-\s]?)?[6-9]\d{9}(?!\d)"), 0.88),
        ("aadhaar", re.compile(r"(?<!\d)\d{4}[-\s]?\d{4}[-\s]?\d{4}(?!\d)"), 0.98),
        ("pan", re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"), 0.98),
        ("gstin", re.compile(r"\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b"), 0.98),
        ("credit_card", re.compile(r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2}|4[4-9]\d{1})\d{12})\b"), 0.93),
        ("credit_card", re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"), 0.86),
        ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), 0.92),
        ("name", re.compile(r"\b(?:name|full name|patient name|employee name)\s*(?:is|:)\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b"), 0.82),
        ("address", re.compile(r"\b(?:address|home address|office address)\s*(?:is|:)\s*([A-Za-z0-9][A-Za-z0-9,.\-/#\s]{12,120})", re.IGNORECASE), 0.82),
        ("medical_identifier", re.compile(r"\b(?:MR|EMR|PT|PID|PATIENT|PATIENTID)[- ]?\d{4,10}\b", re.IGNORECASE), 0.9),
        ("medical_identifier", re.compile(r"\b(?:medical record|patient id|patient identifier)\s*(?:number|no|id|is|:)?\s*([A-Za-z0-9_-]{4,16})\b", re.IGNORECASE), 0.88),
        ("financial_identifier", re.compile(r"\b(?:account number|bank account|routing number|ifsc)\s*(?:is|:)?\s*([A-Z0-9_-]{6,24})\b", re.IGNORECASE), 0.86),
        ("financial_identifier", re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"), 0.9),
        ("openai_api_key", re.compile(r"\bsk-[A-Za-z0-9][A-Za-z0-9_-]{15,}\b"), 0.99),
        ("google_api_key", re.compile(r"\bAIza[A-Za-z0-9_-]{20,}\b"), 0.99),
        ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA|AROA|ANPA)[A-Z0-9]{16}\b"), 0.99),
        ("jwt_token", re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), 0.99),
        ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b", re.IGNORECASE), 0.99),
        ("api_key_param", re.compile(r"\bapi[_-]?key\s*[=:]\s*['\"]?([A-Za-z0-9._/+=-]{8,})['\"]?", re.IGNORECASE), 0.94),
        ("secret_param", re.compile(r"\bsecret\s*[=:]\s*['\"]?([A-Za-z0-9._/+=-]{8,})['\"]?", re.IGNORECASE), 0.94),
        ("token_param", re.compile(r"\btoken\s*[=:]\s*['\"]?([A-Za-z0-9._/+=-]{8,})['\"]?", re.IGNORECASE), 0.94),
        ("access_token", re.compile(r"\baccess[_-]?token\s*[=:]\s*['\"]?([A-Za-z0-9._/+=-]{8,})['\"]?", re.IGNORECASE), 0.96),
        ("private_key", re.compile(r"\bprivate[_-]?key\s*[=:]\s*['\"]?([A-Za-z0-9._/+=-]{8,})['\"]?", re.IGNORECASE), 0.96),
    )

    presidio_map = {
        "EMAIL_ADDRESS": "email",
        "PHONE_NUMBER": "phone",
        "CREDIT_CARD": "credit_card",
        "US_SSN": "ssn",
        "IBAN_CODE": "iban",
        "IP_ADDRESS": "ip_address",
        "PERSON": "person",
        "LOCATION": "address",
    }

    _cached_presidio_analyzer = None
    _cached_presidio_anonymizer = None

    def __init__(self, tenant_id=None, use_presidio: Optional[bool] = None):
        self.tenant_id = tenant_id
        self._use_presidio = self._presidio_requested() if use_presidio is None else bool(use_presidio)
        if self._use_presidio and SensitiveDataDetector._cached_presidio_analyzer is None:
            try:
                from presidio_analyzer import AnalyzerEngine
                SensitiveDataDetector._cached_presidio_analyzer = AnalyzerEngine()
            except Exception:
                pass
        if self._use_presidio and SensitiveDataDetector._cached_presidio_anonymizer is None:
            try:
                from presidio_anonymizer import AnonymizerEngine
                SensitiveDataDetector._cached_presidio_anonymizer = AnonymizerEngine()
            except Exception:
                pass
        self._presidio_analyzer = SensitiveDataDetector._cached_presidio_analyzer if self._use_presidio else None
        self._presidio_anonymizer = SensitiveDataDetector._cached_presidio_anonymizer if self._use_presidio else None

    @property
    def presidio_enabled(self) -> bool:
        return self._presidio_analyzer is not None

    def inspect(self, text: str, use_presidio: Optional[bool] = None) -> List[SensitiveFinding]:
        findings = self._custom_findings(text)
        findings.extend(self._enterprise_findings(text))
        if use_presidio is not False:
            findings.extend(self._presidio_findings(text))
        return self._dedupe(findings)

    def redact(self, text: str, username: str = "system", use_presidio: Optional[bool] = None) -> Tuple[str, List[Dict[str, object]]]:
        findings = self.inspect(text, use_presidio=use_presidio)
        if not findings:
            return text, []

        metadata = []
        redacted = text
        for finding in sorted(findings, key=lambda item: item.start, reverse=True):
            action = self.action_for(finding.entity_type, finding.confidence)
            replacement = self.replacement_for(finding, action)
            redacted = redacted[:finding.start] + replacement + redacted[finding.end:]
            metadata.append(self.to_policy_finding(finding, action, username))

        metadata.reverse()
        return redacted, metadata

    def action_for(self, entity_type: str, confidence: float) -> str:
        sensitive_policy = self._policy_config()
        entity_actions = sensitive_policy.get("actions", {})

        if entity_type in entity_actions:
            return entity_actions[entity_type]
        if entity_type in SECRET_TYPES:
            return entity_actions.get("secrets", "block")
        if confidence >= float(sensitive_policy.get("approval_confidence_threshold", 1.01)):
            return "require_approval"
        return sensitive_policy.get("default_action", "redact")

    def replacement_for(self, finding: SensitiveFinding, action: str) -> str:
        entity_type = finding.entity_type
        value = finding.value
        if finding.source == "presidio":
            anonymized = self._presidio_anonymized_value(finding, action)
            if anonymized is not None:
                return anonymized
        if action == "allow":
            return value
        if action == "block":
            return f"[BLOCKED_{entity_type.upper()}]"
        if action == "require_approval":
            return f"[APPROVAL_REQUIRED_{entity_type.upper()}]"
        if action == "hash":
            return f"[HASH_{self.fingerprint(value)}]"
        if action == "tokenize":
            return f"[TOKEN_{entity_type.upper()}_{self.fingerprint(value)}]"
        if action == "mask":
            return self.mask(entity_type, value)
        return "[REDACTED]"

    def to_policy_finding(self, finding: SensitiveFinding, action: str, username: str) -> Dict[str, object]:
        token = f"tok_{finding.entity_type}_{self.fingerprint(finding.value)}"
        return {
            "policy_name": "Sensitive Data Detection",
            "policy_type": "Secret" if finding.entity_type in SECRET_TYPES else "PII",
            "matched_pattern": finding.entity_type,
            "redacted_value": token,
            "token_id": token,
            "value_hash": self.fingerprint(finding.value),
            "confidence": round(finding.confidence, 4),
            "action": action,
            "detector": finding.source,
            "username": username,
            "timestamp": datetime.now(),
        }

    def fingerprint(self, value: str) -> str:
        from services.secret_manager import SecretManager

        return SecretManager().fingerprint(value, purpose="redaction")

    def mask(self, entity_type: str, value: str) -> str:
        if entity_type == "email" and "@" in value:
            local, domain = value.split("@", 1)
            if len(local) <= 2:
                return f"{'*' * len(local)}@{domain}"
            return f"{local[0]}{'*' * (len(local) - 2)}{local[-1]}@{domain}"
        if entity_type in {"aadhaar", "credit_card", "phone"}:
            digits = [char for char in value if char.isdigit()]
            visible = 4 if len(digits) >= 4 else 0
            index = 0
            chars = []
            for char in value:
                if char.isdigit():
                    chars.append(char if index >= len(digits) - visible else "*")
                    index += 1
                else:
                    chars.append(char)
            return "".join(chars)
        if len(value) <= 4:
            return "*" * len(value)
        return f"{value[0]}{'*' * (len(value) - 2)}{value[-1]}"

    def _custom_findings(self, text: str) -> List[SensitiveFinding]:
        findings = []
        for entity_type, pattern, confidence in self.custom_patterns:
            for match in pattern.finditer(text):
                value = match.group(1) if match.lastindex else match.group(0)
                start, end = match.span(1) if match.lastindex else match.span(0)
                findings.append(SensitiveFinding(entity_type, start, end, value, confidence, "custom"))
        return findings

    def _enterprise_findings(self, text: str) -> List[SensitiveFinding]:
        findings = []
        for item in self._enterprise_patterns():
            try:
                entity_type = str(item["entity_type"]).lower().strip().replace(" ", "_")
                pattern = re.compile(str(item["pattern"]), re.IGNORECASE if item.get("ignore_case", True) else 0)
                confidence = float(item.get("confidence", 0.86))
            except Exception:
                continue
            for match in pattern.finditer(text):
                value = match.group(1) if match.lastindex else match.group(0)
                start, end = match.span(1) if match.lastindex else match.span(0)
                findings.append(SensitiveFinding(entity_type, start, end, value, confidence, "enterprise"))
        return findings

    def _presidio_findings(self, text: str) -> List[SensitiveFinding]:
        if not self._presidio_analyzer:
            return []
        try:
            entities = list(self.presidio_map.keys())
            results = self._presidio_analyzer.analyze(text=text, language="en", entities=entities)
        except Exception:
            return []

        findings = []
        for result in results:
            if result.entity_type not in self.presidio_map:
                continue
            entity_type = self.presidio_map[result.entity_type]
            value = text[result.start:result.end]
            findings.append(SensitiveFinding(entity_type, result.start, result.end, value, float(result.score), "presidio"))
        return findings

    def _presidio_anonymized_value(self, finding: SensitiveFinding, action: str) -> Optional[str]:
        if not self._presidio_anonymizer or action not in {"redact", "mask"}:
            return None
        try:
            from presidio_analyzer import RecognizerResult
            from presidio_anonymizer.entities import OperatorConfig

            entity_type = self._presidio_entity_for_internal(finding.entity_type) or "DEFAULT"
            replacement = self.mask(finding.entity_type, finding.value) if action == "mask" else "[REDACTED]"
            result = self._presidio_anonymizer.anonymize(
                text=finding.value,
                analyzer_results=[
                    RecognizerResult(entity_type=entity_type, start=0, end=len(finding.value), score=finding.confidence)
                ],
                operators={entity_type: OperatorConfig("replace", {"new_value": replacement})},
            )
            return result.text
        except Exception:
            return None

    def _presidio_entity_for_internal(self, entity_type: str) -> Optional[str]:
        for presidio_name, internal_name in self.presidio_map.items():
            if internal_name == entity_type:
                return presidio_name
        return None

    def _dedupe(self, findings: Iterable[SensitiveFinding]) -> List[SensitiveFinding]:
        selected: List[SensitiveFinding] = []
        for finding in sorted(findings, key=lambda item: (item.start, -(item.end - item.start), -item.confidence)):
            overlaps = [
                item for item in selected
                if not (finding.end <= item.start or finding.start >= item.end)
            ]
            if not overlaps:
                selected.append(finding)
                continue
            best = max(overlaps + [finding], key=lambda item: (item.confidence, item.end - item.start))
            for item in overlaps:
                if item in selected and item is not best:
                    selected.remove(item)
            if best is finding and finding not in selected:
                selected.append(finding)
        return sorted(selected, key=lambda item: item.start)

    def _policy_config(self) -> Dict[str, object]:
        try:
            return get_policy().get("sensitive_data", {})
        except Exception:
            return {}

    def _enterprise_patterns(self) -> List[Dict[str, object]]:
        policy_entities = self._policy_config().get("custom_entities", [])
        env_entities = os.getenv("AUTHCLAW_CUSTOM_ENTITIES_JSON", "")
        entities: List[Dict[str, object]] = []
        if isinstance(policy_entities, list):
            entities.extend([item for item in policy_entities if isinstance(item, dict)])
        if env_entities:
            try:
                import json

                parsed = json.loads(env_entities)
                if isinstance(parsed, list):
                    entities.extend([item for item in parsed if isinstance(item, dict)])
            except Exception:
                pass
        return entities

    def _presidio_requested(self) -> bool:
        raw = os.getenv("USE_PRESIDIO", os.getenv("AUTHCLAW_USE_PRESIDIO", "true"))
        return raw.strip().lower() in {"1", "true", "yes", "on"}


_DETECTOR_CACHE: Dict[object, SensitiveDataDetector] = {}


def get_sensitive_data_detector(tenant_id=None, use_presidio: Optional[bool] = None) -> SensitiveDataDetector:
    presidio_key = "default" if use_presidio is None else bool(use_presidio)
    key = (tenant_id if tenant_id is not None else "__default__", presidio_key)
    detector = _DETECTOR_CACHE.get(key)
    if detector is None:
        detector = SensitiveDataDetector(tenant_id, use_presidio=use_presidio)
        _DETECTOR_CACHE[key] = detector
    return detector


def sanitize_finding_metadata(findings: List[Dict[str, object]], detector: Optional[SensitiveDataDetector] = None) -> List[Dict[str, object]]:
    detector = detector or get_sensitive_data_detector()
    sanitized = []
    for finding in findings:
        item = dict(finding)
        if str(item.get("matched_pattern", "")).lower() == "passport":
            item.setdefault("confidence", 0.8)
            item.setdefault("action", "redact")
            sanitized.append(item)
            continue
        raw_value = str(item.get("redacted_value", ""))
        if raw_value and not raw_value.startswith("tok_") and raw_value not in {"N/A", "[REDACTED]"}:
            entity_type = str(item.get("matched_pattern") or item.get("policy_type") or "sensitive").lower().replace(" ", "_")
            token = f"tok_{entity_type}_{detector.fingerprint(raw_value)}"
            item["redacted_value"] = token
            item["token_id"] = token
            item["value_hash"] = detector.fingerprint(raw_value)
        item.setdefault("confidence", 0.8)
        item.setdefault("action", "redact")
        sanitized.append(item)
    return sanitized

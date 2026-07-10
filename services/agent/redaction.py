import re
import hashlib
import hmac
import os
from policy import get_policy
from services.sensitive_data_detection import get_sensitive_data_detector, sanitize_finding_metadata


GDPR_PATTERNS = {
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "ssn_raw": re.compile(r"\b\d{9}\b"),
    "passport": re.compile(r"\b[A-Za-z]{1,2}\d{7,9}\b"),
    "keyword": re.compile(r"\b(passport|ssn|social security number)(\s+(?:number|no|code|is|of|:)?\s*)([A-Za-z0-9_-]+)\b", re.IGNORECASE),
}

HIPAA_PATTERNS = {
    "medical_record": re.compile(r"\b(?:MR|EMR|PT|PID|PATIENT|PATIENTID)[- ]?\d{4,8}\b", re.IGNORECASE),
    "keyword": re.compile(r"\b(medical record|diagnosis|diagnoses|health history|patient identifier|patient identifiers)(\s+(?:number|no|code|is|of|includes|:)?\s*)([A-Za-z0-9_-]+)\b", re.IGNORECASE),
}

SOC2_PATTERNS = {
    "card_brand": re.compile(r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2}|4[4-9]\d{1})\d{12})\b"),
    "card_delimited": re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"),
    "card_digits": re.compile(r"\b\d{13,19}\b"),
    "routing": re.compile(r"\b\d{9}\b"),
    "keyword": re.compile(r"\b(bank routing|routing number|pin|pin number|personal identification number)(\s+(?:number|no|code|is|of|includes|:)?\s*)([A-Za-z0-9_-]+)\b", re.IGNORECASE),
    "pin_near": re.compile(r"\b(?:pin|pin number|personal identification number)\b.{1,15}\b(\d{4,6})\b", re.IGNORECASE),
}

BASELINE_PATTERNS = {
    "email": re.compile(r"[\w\.-]+@[\w\.-]+\.\w+"),
    "aadhaar": re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),
    "phone": re.compile(r"\b\d{10}\b"),
}

STREAM_HINT_WORDS = (
    "@", "sk-", "akia", "asia", "aroa", "anpa", "aiza", "bearer", "eyj",
    "api_key", "api-key", "secret=", "secret:", "token=", "token:",
    "access_token", "refresh_token", "password=", "password:", "client_secret",
    "ssn", "social security", "passport", "medical record", "patient",
    "diagnosis", "health history", "routing number", "credit card", "pin ",
    "ignore previous", "reveal system prompt", "developer mode", "jailbreak",
    "system prompt", "hidden_metadata",
)


def _redaction_fingerprint(value: str) -> str:
    salt = (
        os.getenv("AUTHCLAW_REDACTION_SALT")
        or os.getenv("JWT_SECRET")
        or os.getenv("AUTHCLAW_JWT_SECRET")
        or os.getenv("AUTHCLAW_ENCRYPTION_KEY")
        or "authclaw-local-redaction-salt"
    )
    return hmac.new(salt.encode("utf-8"), str(value).encode("utf-8"), hashlib.sha256).hexdigest()[:16]

def apply_redaction(field: str, match, action: str) -> str:
    """
    Applies the configured redaction action (mask, hash, synthetic, or standard redact fallback)
    on a matched sensitive token.
    """
    val = match.group(0)
    action_lower = action.lower()
    
    if action_lower == "mask":
        if field == "email":
            if "@" in val:
                local, domain = val.split("@", 1)
                if len(local) > 2:
                    return f"{local[0]}{'*' * (len(local) - 2)}{local[-1]}@{domain}"
                return f"{'*' * len(local)}@{domain}"
            return "***"
        elif field == "phone":
            return "*" * 6 + val[-4:]
        elif field in ("aadhaar", "credit_card"):
            # Mask digits except last 4, preserving delimiters
            digits = [c for c in val if c.isdigit()]
            total_digits = len(digits)
            masked = []
            digit_count = 0
            for c in val:
                if c.isdigit():
                    if digit_count < total_digits - 4:
                        masked.append("*")
                        digit_count += 1
                    else:
                        masked.append(c)
                else:
                    masked.append(c)
            return "".join(masked)
            
    elif action_lower == "hash":
        h = _redaction_fingerprint(val)
        return f"[HASH_{h}]"
        
    elif action_lower == "synthetic":
        if field == "email":
            return "synthetic.email@example.com"
        elif field == "phone":
            return "555-019-9283"
        elif field == "aadhaar":
            return "0000 0000 0000"
        elif field == "credit_card":
            return "4111-1111-1111-1111"
            
    # Fallback / Default ("redact" or other invalid configuration)
    if field == "email":
        return "[REDACTED_EMAIL]"
    elif field == "phone":
        return "[REDACTED_PHONE]"
    elif field == "aadhaar":
        return "[REDACTED_AADHAAR]"
    elif field == "credit_card":
        return "[REDACTED_CARD]"
    return val

def redact_sensitive_data_rich(text: str, username: str = "admin_user", tenant_id=None, use_presidio=True) -> tuple:
    """
    Identifies sensitive fields based on active database guardrail policies
    and applies [REDACTED] replacement. Also checks baseline yaml redactions.
    Returns (redacted_text, triggered_policies).
    """
    import os
    from datetime import datetime
    from policy import get_db_policies

    triggered_policies = []

    strong_detector = get_sensitive_data_detector(tenant_id, use_presidio=use_presidio)
    text, strong_findings = strong_detector.redact(text, username, use_presidio=use_presidio)
    triggered_policies.extend(strong_findings)

    def record_baseline_trigger(policy_name: str, field: str, value: str):
        triggered_policies.append({
            "policy_name": policy_name,
            "policy_type": "Security",
            "matched_pattern": field,
            "redacted_value": value,
            "username": username,
            "timestamp": datetime.now()
        })
    
    # 1. Fetch active policies from the database
    db_policies = get_db_policies(tenant_id)
    active_types = {p["type"]: p for p in db_policies}

    # GDPR compliance check (Passport, SSN)
    if "GDPR" in active_types:
        gdpr_p = active_types["GDPR"]
        rules = gdpr_p.get("rules", {})
        if rules.get("pii_redaction", False):
            # SSN Pattern (with dashes 123-45-6789 or raw 9 digits)
            ssn_pattern = GDPR_PATTERNS["ssn"]
            for m in ssn_pattern.finditer(text):
                val = m.group(0)
                if val != "[REDACTED]":
                    triggered_policies.append({
                        "policy_name": gdpr_p["name"],
                        "policy_type": "GDPR",
                        "matched_pattern": "ssn",
                        "redacted_value": val,
                        "username": username,
                        "timestamp": datetime.now()
                    })
            text = ssn_pattern.sub("[REDACTED]", text)

            # Raw 9 digit SSN
            ssn_raw_pattern = GDPR_PATTERNS["ssn_raw"]
            for m in ssn_raw_pattern.finditer(text):
                val = m.group(0)
                if val != "[REDACTED]":
                    triggered_policies.append({
                        "policy_name": gdpr_p["name"],
                        "policy_type": "GDPR",
                        "matched_pattern": "ssn",
                        "redacted_value": val,
                        "username": username,
                        "timestamp": datetime.now()
                    })
            text = ssn_raw_pattern.sub("[REDACTED]", text)

            # Passport Pattern (e.g. A1234567, P12345678, or generic 1-2 letters + 7-9 digits)
            passport_pattern = GDPR_PATTERNS["passport"]
            for m in passport_pattern.finditer(text):
                val = m.group(0)
                if val != "[REDACTED]":
                    triggered_policies.append({
                        "policy_name": gdpr_p["name"],
                        "policy_type": "GDPR",
                        "matched_pattern": "passport",
                        "redacted_value": val,
                        "username": username,
                        "timestamp": datetime.now()
                    })
            text = passport_pattern.sub("[REDACTED]", text)

            # Keyword-based backup check (e.g. passport number A1234567)
            kw_pattern = GDPR_PATTERNS["keyword"]
            for m in kw_pattern.finditer(text):
                val = m.group(3)
                if val != "[REDACTED]":
                    triggered_policies.append({
                        "policy_name": gdpr_p["name"],
                        "policy_type": "GDPR",
                        "matched_pattern": m.group(1),
                        "redacted_value": val,
                        "username": username,
                        "timestamp": datetime.now()
                    })
            text = kw_pattern.sub(r"\1\2[REDACTED]", text)

    # HIPAA compliance check (medical record, diagnosis, health history, patient identifiers)
    if "HIPAA" in active_types:
        hipaa_p = active_types["HIPAA"]
        rules = hipaa_p.get("rules", {})
        if rules.get("pii_redaction", False):
            # Medical Record ID pattern (MR-12345, EMR-45678, Patient IDs like PT-12345 or PID-12345)
            mr_pattern = HIPAA_PATTERNS["medical_record"]
            for m in mr_pattern.finditer(text):
                val = m.group(0)
                if val != "[REDACTED]":
                    triggered_policies.append({
                        "policy_name": hipaa_p["name"],
                        "policy_type": "HIPAA",
                        "matched_pattern": "medical record",
                        "redacted_value": val,
                        "username": username,
                        "timestamp": datetime.now()
                    })
            text = mr_pattern.sub("[REDACTED]", text)

            # Keyword-context match (medical record 98765, diagnosis is diabetes, health history includes asthma)
            hipaa_pattern = HIPAA_PATTERNS["keyword"]
            for m in hipaa_pattern.finditer(text):
                val = m.group(3)
                if val != "[REDACTED]":
                    triggered_policies.append({
                        "policy_name": hipaa_p["name"],
                        "policy_type": "HIPAA",
                        "matched_pattern": m.group(1),
                        "redacted_value": val,
                        "username": username,
                        "timestamp": datetime.now()
                    })
            text = hipaa_pattern.sub(r"\1\2[REDACTED]", text)

    # SOC2 compliance check (credit card, bank routing, pin number)
    if "SOC2" in active_types:
        soc2_p = active_types["SOC2"]
        rules = soc2_p.get("rules", {})
        if rules.get("pii_redaction", False):
            # Card-brand specific credit card check
            # Visa, Mastercard, Amex, Discover pattern matching
            cc_regex = SOC2_PATTERNS["card_brand"]
            for m in cc_regex.finditer(text):
                val = m.group(0)
                if val != "[REDACTED]":
                    triggered_policies.append({
                        "policy_name": soc2_p["name"],
                        "policy_type": "SOC2",
                        "matched_pattern": "credit card",
                        "redacted_value": val,
                        "username": username,
                        "timestamp": datetime.now()
                    })
            text = cc_regex.sub("[REDACTED]", text)

            # Standard Credit Card Pattern (with dashes/spaces)
            cc_pattern1 = SOC2_PATTERNS["card_delimited"]
            for m in cc_pattern1.finditer(text):
                val = m.group(0)
                if val != "[REDACTED]":
                    triggered_policies.append({
                        "policy_name": soc2_p["name"],
                        "policy_type": "SOC2",
                        "matched_pattern": "credit card",
                        "redacted_value": val,
                        "username": username,
                        "timestamp": datetime.now()
                    })
            text = cc_pattern1.sub("[REDACTED]", text)

            cc_pattern2 = SOC2_PATTERNS["card_digits"]
            for m in cc_pattern2.finditer(text):
                val = m.group(0)
                if val != "[REDACTED]":
                    triggered_policies.append({
                        "policy_name": soc2_p["name"],
                        "policy_type": "SOC2",
                        "matched_pattern": "credit card",
                        "redacted_value": val,
                        "username": username,
                        "timestamp": datetime.now()
                    })
            text = cc_pattern2.sub("[REDACTED]", text)

            # Bank routing: 9 digit ABA routing number
            routing_pattern = SOC2_PATTERNS["routing"]
            for m in routing_pattern.finditer(text):
                val = m.group(0)
                if val != "[REDACTED]":
                    triggered_policies.append({
                        "policy_name": soc2_p["name"],
                        "policy_type": "SOC2",
                        "matched_pattern": "bank routing",
                        "redacted_value": val,
                        "username": username,
                        "timestamp": datetime.now()
                    })
            text = routing_pattern.sub("[REDACTED]", text)

            # Keyword-context match for Bank routing and PIN numbers
            soc2_pattern = SOC2_PATTERNS["keyword"]
            for m in soc2_pattern.finditer(text):
                val = m.group(3)
                if val != "[REDACTED]":
                    triggered_policies.append({
                        "policy_name": soc2_p["name"],
                        "policy_type": "SOC2",
                        "matched_pattern": m.group(1),
                        "redacted_value": val,
                        "username": username,
                        "timestamp": datetime.now()
                    })
            text = soc2_pattern.sub(r"\1\2[REDACTED]", text)

            # PIN Numbers: 4-6 digit financial PINs when preceded or near PIN keywords
            pin_near_pattern = SOC2_PATTERNS["pin_near"]
            for m in pin_near_pattern.finditer(text):
                val = m.group(1)
                if val != "[REDACTED]":
                    triggered_policies.append({
                        "policy_name": soc2_p["name"],
                        "policy_type": "SOC2",
                        "matched_pattern": "pin number",
                        "redacted_value": val,
                        "username": username,
                        "timestamp": datetime.now()
                    })
            text = pin_near_pattern.sub(
                lambda m: m.group(0).replace(m.group(1), "[REDACTED]"),
                text
            )

    # ── API KEY / SECRET TOKEN DETECTION (always active, baseline security) ──────
    # Detects: OpenAI keys, Gemini keys, AWS keys, JWTs, Bearer tokens,
    #          and generic api_key=/secret=/token= patterns.
    # API key and secret scanning is handled by SensitiveDataDetector above.

    # ─────────────────────────────────────────────────────────────────────────────

    # 2. Check baseline yaml redactions
    try:
        policy = get_policy()
        redaction_rules = policy.get("redaction", {})
    except Exception:
        redaction_rules = {}

    # Email
    email_action = redaction_rules.get("email", "redact")
    email_pattern = BASELINE_PATTERNS["email"]
    for m in email_pattern.finditer(text):
        if "[REDACTED" not in m.group(0):
            record_baseline_trigger("PII Protection", "email", m.group(0))
    text = email_pattern.sub(
        lambda m: apply_redaction("email", m, email_action),
        text
    )

    # Aadhaar
    aadhaar_action = redaction_rules.get("aadhaar", "redact")
    aadhaar_pattern = BASELINE_PATTERNS["aadhaar"]
    for m in aadhaar_pattern.finditer(text):
        if "[REDACTED" not in m.group(0):
            record_baseline_trigger("PII Protection", "aadhaar", m.group(0))
    text = aadhaar_pattern.sub(
        lambda m: apply_redaction("aadhaar", m, aadhaar_action),
        text
    )

    # Phone
    phone_action = redaction_rules.get("phone", "redact")
    phone_pattern = BASELINE_PATTERNS["phone"]
    for m in phone_pattern.finditer(text):
        if "[REDACTED" not in m.group(0):
            record_baseline_trigger("PII Protection", "phone", m.group(0))
    text = phone_pattern.sub(
        lambda m: apply_redaction("phone", m, phone_action),
        text
    )

    triggered_policies = sanitize_finding_metadata(triggered_policies, detector=strong_detector)

    # Standardize all target redactions to [REDACTED] for triggered compliance fields
    if triggered_policies:
        # Save to /logs/audit.log and print to console
        os.makedirs("logs", exist_ok=True)
        log_file = os.path.join("logs", "audit.log")
        with open(log_file, "a", encoding="utf-8") as f:
            for trigger in triggered_policies:
                log_msg = f"Time: {trigger['timestamp']} | Policy: {trigger['policy_name']} ({trigger['policy_type']}) | Matched: {trigger['matched_pattern']} | Redacted: {trigger['redacted_value']} | User: {trigger['username']}"
                print(f"[POLICY TRIGGERED] {log_msg}", flush=True)
                f.write(f"\n[POLICY TRIGGERED] {log_msg}\n")

    return text, triggered_policies

def redact_sensitive_data(text: str) -> str:
    """
    Identifies sensitive fields (Credit Card, Aadhaar, Email, Phone) and applies
    configured redaction strategies defined in the policy.
    """
    redacted_text, _ = redact_sensitive_data_rich(text)
    return redacted_text


def _stream_holdback_size() -> int:
    raw_value = os.getenv("AUTHCLAW_STREAM_REDACTION_HOLDBACK_CHARS", "256")
    try:
        return max(64, min(4096, int(raw_value)))
    except ValueError:
        return 256


def _redact_stream_buffer(buffer: str, username: str, tenant_id=None):
    redacted, findings = redact_sensitive_data_rich(buffer, username=username, tenant_id=tenant_id, use_presidio=False)
    return redacted or "", findings or []


def _stream_needs_redaction_scan(value: str) -> bool:
    lowered = value.lower()
    if any(hint in lowered for hint in STREAM_HINT_WORDS):
        return True
    digit_count = 0
    for char in value:
        if char.isdigit():
            digit_count += 1
            if digit_count >= 4:
                return True
    return False


def stream_redact_sensitive_tokens(token_stream, username: str = "admin_user", tenant_id=None, holdback_chars: int = None):
    """
    Redacts provider output as chunks arrive.

    The holdback window keeps a small suffix in memory so identifiers split
    across token boundaries can still be detected, while most text is yielded
    immediately. This preserves the existing full-text redactor as the source of
    truth and adds a streaming interface without changing current callers.
    """
    pending = ""
    holdback = holdback_chars or _stream_holdback_size()

    for token in token_stream:
        if token is None:
            continue
        pending += str(token)
        if len(pending) <= holdback:
            continue

        if not _stream_needs_redaction_scan(pending):
            slice_idx = len(pending) - holdback
            yielded = pending[:slice_idx]
            pending = pending[slice_idx:]
            if yielded:
                yield yielded
            continue

        redacted_pending, _ = _redact_stream_buffer(pending, username, tenant_id)
        slice_idx = len(redacted_pending) - holdback
        if slice_idx > 0:
            yielded = redacted_pending[:slice_idx]
            pending = redacted_pending[slice_idx:]
            if yielded:
                yield yielded

    if pending:
        redacted_tail, _ = _redact_stream_buffer(pending, username, tenant_id)
        if redacted_tail:
            yield redacted_tail


async def async_stream_redact_sensitive_tokens(token_stream, username: str = "admin_user", tenant_id=None, holdback_chars: int = None):
    """
    Async counterpart for providers or HTTP handlers that expose async token
    generators. It intentionally mirrors stream_redact_sensitive_tokens.
    """
    pending = ""
    holdback = holdback_chars or _stream_holdback_size()

    async for token in token_stream:
        if token is None:
            continue
        pending += str(token)
        if len(pending) <= holdback:
            continue

        if not _stream_needs_redaction_scan(pending):
            slice_idx = len(pending) - holdback
            yielded = pending[:slice_idx]
            pending = pending[slice_idx:]
            if yielded:
                yield yielded
            continue

        redacted_pending, _ = _redact_stream_buffer(pending, username, tenant_id)
        slice_idx = len(redacted_pending) - holdback
        if slice_idx > 0:
            yielded = redacted_pending[:slice_idx]
            pending = redacted_pending[slice_idx:]
            if yielded:
                yield yielded

    if pending:
        redacted_tail, _ = _redact_stream_buffer(pending, username, tenant_id)
        if redacted_tail:
            yield redacted_tail

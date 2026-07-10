import re
import logging
import bisect
from typing import List, Dict, Any

logger = logging.getLogger("authclaw.document_processing.scanners")

# Compiled patterns for efficiency
PATTERNS = {
    # PII
    "email": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
    "phone": re.compile(r"\b(?:\+\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b"),
    "aadhaar": re.compile(r"\b\d{4}\s\d{4}\s\d{4}\b"),
    "pan": re.compile(r"\b[a-zA-Z]{5}\d{4}[a-zA-Z]\b"),
    
    # Financial
    "credit_card": re.compile(
        r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2}|4[4-9]\d{1})\d{12})\b|"
        r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"
    ),
    "bank_routing": re.compile(r"\b\d{9}\b"),
    
    # Secrets
    "openai_api_key": re.compile(r"\bsk-[A-Za-z0-9\-_]{8,}\b"),
    "google_api_key": re.compile(r"\bAIza[A-Za-z0-9\-_]{20,}\b"),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA|AROA|ANPA)[A-Z0-9]{16}\b"),
    "jwt_token": re.compile(r"\beyJ[A-Za-z0-9\-_=]{20,}\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\b"),
    "bearer_token": re.compile(r"\bBearer\s+[A-Za-z0-9\-_.~+/]{8,}={0,2}\b"),
    
    # Connection Strings & Credentials
    "conn_string": re.compile(r"\b(?:postgresql|mongodb|mysql|mssql|redis|amqp)://[A-Za-z0-9\-_]+:[^@\s]+@[A-Za-z0-9\-_.:]+/?[A-Za-z0-9\-_]*\b", re.IGNORECASE)
}

# Context patterns to scan near credentials (e.g. AWS Secret Access Key)
CONTEXT_PATTERNS = {
    "aws_secret_key": (re.compile(r"(?i)\b(?:aws[_\-]?secret|secret[_\-]?key|aws_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"), "AWS Secret Key"),
    "password_leak": (re.compile(r"(?i)\b(?:password|passwd|secret|token|client_secret)\s*[=:]\s*['\"]?([A-Za-z0-9\-_.~!@#$%^&*()_+]{8,24})['\"]?"), "Exposed Password/Secret")
}

def scan_text_for_sensitive_data(text: str) -> List[Dict[str, Any]]:
    """
    Scans a given text string for PII, financial leaks, and credentials.
    Returns a structured list of findings with recommendations, impact, priority, and location evidence.
    """
    findings = []
    newline_offsets = [idx for idx, char in enumerate(text) if char == "\n"]

    def line_number(offset: int) -> int:
        return bisect.bisect_right(newline_offsets, offset) + 1
    
    # 1. Primary regex scanner
    for key, regex in PATTERNS.items():
        for match in regex.finditer(text):
            matched_text = match.group(0)
            
            # Map type, severity, impact, and priority
            finding_type = "PII"
            severity = "MEDIUM"
            priority = "P2"
            recommendation = "Redact this value or restrict document access permissions."
            impact = "Exposure of Personally Identifiable Information leading to GDPR compliance violation and fines."
            
            if key in ("openai_api_key", "google_api_key", "aws_access_key", "jwt_token", "bearer_token"):
                finding_type = "Secret"
                severity = "CRITICAL"
                priority = "P1"
                recommendation = "Revoke this key immediately from the cloud console and rotate secrets."
                impact = "Unauthorized access to API keys, leading to potential data breach or cloud resource hijack."
            elif key in ("credit_card", "bank_routing"):
                finding_type = "Financial"
                severity = "HIGH"
                priority = "P1"
                recommendation = "Mask the payment/routing identifier to maintain PCI-DSS compliance."
                impact = "Exposure of credit card or bank routing numbers leading to PCI-DSS compliance violation."
            elif key == "conn_string":
                finding_type = "Credentials"
                severity = "CRITICAL"
                priority = "P1"
                recommendation = "Exposed database connection credential. Rotate password immediately."
                impact = "Exposed credentials leading to unauthorized database access."
            elif key in ("ssn", "aadhaar", "pan"):
                finding_type = "PII"
                severity = "HIGH"
                priority = "P1"
                recommendation = "Redact sensitive personal tax/identity numbers immediately."
                impact = "Exposure of tax identifiers violating data security standards."
                
            # Formatting preview
            preview = matched_text
            if len(preview) > 20:
                preview = f"{preview[:6]}...{preview[-6:]}"
                
            # Determine line number for location evidence
            line_no = line_number(match.start())
            location_evidence = f"Line {line_no}"
            
            findings.append({
                "finding_type": finding_type,
                "matched_pattern": key.upper(),
                "matched_text": preview,
                "risk_level": severity,
                "recommendation": recommendation,
                "impact": impact,
                "priority": priority,
                "location_evidence": location_evidence
            })
            
    # 2. Context-based pattern scanner (AWS Secrets, password variables)
    for key, (regex, label) in CONTEXT_PATTERNS.items():
        for match in regex.finditer(text):
            matched_secret = match.group(1)
            # Avoid reporting redacted values
            if "[REDACTED]" in matched_secret or "******" in matched_secret:
                continue
                
            severity = "CRITICAL" if key == "aws_secret_key" else "HIGH"
            priority = "P1"
            recommendation = (
                "AWS account compromised. Rotate credentials immediately." 
                if key == "aws_secret_key" else 
                "Do not store passwords in plaintext configuration files."
            )
            impact = (
                "Potential total compromise of AWS cloud infrastructure." 
                if key == "aws_secret_key" else 
                "Access credentials leaked in plaintext, leading to identity hijack."
            )
            
            preview = matched_secret
            if len(preview) > 12:
                preview = f"{preview[:4]}...{preview[-4:]}"
                
            line_no = line_number(match.start())
            location_evidence = f"Line {line_no}"
            
            findings.append({
                "finding_type": "Secret" if key == "aws_secret_key" else "Credentials",
                "matched_pattern": label.upper().replace(" ", "_"),
                "matched_text": preview,
                "risk_level": severity,
                "recommendation": recommendation,
                "impact": impact,
                "priority": priority,
                "location_evidence": location_evidence
            })
            
    # De-duplicate identical findings
    unique_findings = []
    seen = set()
    for f in findings:
        signature = (f["finding_type"], f["matched_pattern"], f["matched_text"])
        if signature not in seen:
            seen.add(signature)
            unique_findings.append(f)
            
    return unique_findings

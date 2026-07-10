package authclaw.policy

default allow := true
default decision := "ALLOW"
default reason := "Allowed by AuthClaw OPA policy"

blocked_keywords := {
  "ignore all instructions",
  "reveal system prompt",
  "dump database",
  "disable logging",
}

high_risk_keywords := {
  "delete database",
  "drop table",
  "export customer data",
  "production database",
  "admin credentials",
}

prompt_injection_keywords := {
  "ignore previous instructions",
  "ignore all instructions",
  "reveal system prompt",
  "show internal system prompts",
  "forget your instructions",
  "developer mode",
  "jailbreak",
  "bypass policy",
}

security_bypass_keywords := {
  "disable logging",
  "disable audit logging",
  "disable monitoring",
  "disable guardrails",
  "bypass security",
  "bypass authentication",
  "disable access control",
}

data_exfiltration_keywords := {
  "dump database",
  "export customer data",
  "export production database",
  "download all users",
  "reveal secrets",
  "reveal passwords",
  "exfiltrate",
}

secret_regexes := {
  `(?i)\beyJ[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}\b`,
  `\bA(KIA|SIA)[A-Z0-9]{16}\b`,
  `\bsk-[A-Za-z0-9_-]{16,}\b`,
  `\bsk-ant-[A-Za-z0-9_-]{16,}\b`,
  `\bSG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`,
  `\bAIza[0-9A-Za-z_-]{20,}\b`,
  `(?i)\b(api[_-]?key|secret|access[_-]?token|password)\s*[:=]\s*["']?[A-Za-z0-9._~+/=-]{12,}`,
}

pii_regexes := {
  `\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`,
  `(?i)(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3,5}\)?[\s.-]?)\d{3,5}[\s.-]?\d{3,6}\b`,
  `\b\d{3}-\d{2}-\d{4}\b`,
}

phi_regexes := {
  `(?i)\b(patient|medical record|mrn|diagnosis|prescription|treatment plan)\b`,
}

financial_regexes := {
  `\b(?:\d[ -]*?){13,19}\b`,
  `(?i)\b(bank account|routing number|iban|wire transfer)\b`,
}

normalized_text := lower(sprintf("%v", [input.text]))
body_text := lower(sprintf("%v", [input.context.body]))
combined_text := concat(" ", [normalized_text, body_text])

keyword_block if {
  some keyword in blocked_keywords
  contains(combined_text, keyword)
}

prompt_injection_block if {
  some keyword in prompt_injection_keywords
  contains(combined_text, keyword)
}

security_bypass_block if {
  some keyword in security_bypass_keywords
  contains(combined_text, keyword)
}

data_exfiltration_block if {
  some keyword in data_exfiltration_keywords
  contains(combined_text, keyword)
}

secret_block if {
  some pattern in secret_regexes
  regex.match(pattern, combined_text)
}

block if keyword_block
block if prompt_injection_block
block if security_bypass_block
block if data_exfiltration_block
block if secret_block

requires_approval if {
  some keyword in high_risk_keywords
  contains(combined_text, keyword)
}

requires_redaction if {
  some pattern in pii_regexes
  regex.match(pattern, combined_text)
}

requires_redaction if {
  some pattern in phi_regexes
  regex.match(pattern, combined_text)
}

requires_redaction if {
  some pattern in financial_regexes
  regex.match(pattern, combined_text)
}

allow := false if block
allow := false if requires_approval

decision := "BLOCK" if block
decision := "REQUIRE_APPROVAL" if {
  not block
  requires_approval
}
decision := "REDACT" if {
  not block
  not requires_approval
  requires_redaction
}

reason := "Blocked by OPA enterprise policy" if block
reason := "High-risk action requires approval" if {
  not block
  requires_approval
}
reason := "Sensitive data requires redaction" if {
  not block
  not requires_approval
  requires_redaction
}

risk_level := "HIGH" if block
risk_level := "HIGH" if requires_approval
risk_level := "MEDIUM" if requires_redaction
risk_level := "LOW" if {
  not block
  not requires_approval
  not requires_redaction
}

findings contains finding if {
  some keyword in blocked_keywords
  contains(combined_text, keyword)
  finding := {"policy_name": "OPA blocked keyword", "category": "CUSTOMER_DEFINED_TOPICS", "action": "BLOCK", "matched": keyword}
}

findings contains finding if {
  some keyword in prompt_injection_keywords
  contains(combined_text, keyword)
  finding := {"policy_name": "OPA prompt injection", "category": "PROMPT_INJECTION", "action": "BLOCK", "matched": keyword}
}

findings contains finding if {
  some keyword in security_bypass_keywords
  contains(combined_text, keyword)
  finding := {"policy_name": "OPA security bypass", "category": "SECURITY_BYPASS", "action": "BLOCK", "matched": keyword}
}

findings contains finding if {
  some keyword in data_exfiltration_keywords
  contains(combined_text, keyword)
  finding := {"policy_name": "OPA data exfiltration", "category": "DATA_EXFILTRATION", "action": "BLOCK", "matched": keyword}
}

findings contains finding if {
  some pattern in secret_regexes
  regex.match(pattern, combined_text)
  finding := {"policy_name": "OPA secret detector", "category": "SECRETS", "action": "BLOCK", "matched": pattern}
}

findings contains finding if {
  some pattern in pii_regexes
  regex.match(pattern, combined_text)
  finding := {"policy_name": "OPA PII detector", "category": "PII", "action": "REDACT", "matched": pattern}
}

findings contains finding if {
  some pattern in phi_regexes
  regex.match(pattern, combined_text)
  finding := {"policy_name": "OPA PHI detector", "category": "MEDICAL_DATA", "action": "REDACT", "matched": pattern}
}

findings contains finding if {
  some pattern in financial_regexes
  regex.match(pattern, combined_text)
  finding := {"policy_name": "OPA financial detector", "category": "FINANCIAL_DATA", "action": "REDACT", "matched": pattern}
}

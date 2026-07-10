import pytest
import json
from datetime import datetime
from fastapi.testclient import TestClient
from main import app, API_KEY
from database import engine
from sqlalchemy import text

client = TestClient(app)
headers = {
    "X-API-Key": API_KEY,
    "Content-Type": "application/json"
}

def set_policy_state(policy_type: str, enabled: bool, rules: dict = None):
    """
    Helper to enable/disable a policy in the database for testing.
    """
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT id FROM policies WHERE type = :type"),
            {"type": policy_type}
        ).fetchone()
        
        if not row:
            conn.execute(
                text("INSERT INTO policies (name, type, rules, enabled) VALUES (:name, :type, :rules, :enabled)"),
                {
                    "name": f"{policy_type} Policy",
                    "type": policy_type,
                    "rules": json.dumps(rules) if rules else "{}",
                    "enabled": enabled
                }
            )
        else:
            if rules:
                conn.execute(
                    text("UPDATE policies SET enabled = :enabled, rules = :rules WHERE type = :type"),
                    {"enabled": enabled, "rules": json.dumps(rules), "type": policy_type}
                )
            else:
                conn.execute(
                    text("UPDATE policies SET enabled = :enabled WHERE type = :type"),
                    {"enabled": enabled, "type": policy_type}
                )
        conn.commit()


def test_passport_redaction():
    rules = {"blocked_keywords": ["passport", "ssn", "social security number"], "pii_redaction": True}
    set_policy_state("GDPR", True, rules)
    
    # Test A1234567 format
    payload1 = {"text": "My passport number is A1234567"}
    res1 = client.post("/policies/redact", headers=headers, json=payload1)
    assert res1.status_code == 200
    assert "[REDACTED]" in res1.json()["redacted_text"]
    assert "A1234567" not in res1.json()["redacted_text"]

    # Test P12345678 format
    payload2 = {"text": "My passport is P12345678"}
    res2 = client.post("/policies/redact", headers=headers, json=payload2)
    assert res2.status_code == 200
    assert "[REDACTED]" in res2.json()["redacted_text"]
    assert "P12345678" not in res2.json()["redacted_text"]

def test_ssn_redaction():
    rules = {"blocked_keywords": ["passport", "ssn", "social security number"], "pii_redaction": True}
    set_policy_state("GDPR", True, rules)

    # With hyphens
    payload1 = {"text": "My SSN is 123-45-6789"}
    res1 = client.post("/policies/redact", headers=headers, json=payload1)
    assert res1.status_code == 200
    assert "[REDACTED]" in res1.json()["redacted_text"]
    assert "123-45-6789" not in res1.json()["redacted_text"]

    # Without hyphens
    payload2 = {"text": "SSN 123456789"}
    res2 = client.post("/policies/redact", headers=headers, json=payload2)
    assert res2.status_code == 200
    assert "[REDACTED]" in res2.json()["redacted_text"]
    assert "123456789" not in res2.json()["redacted_text"]

def test_credit_card_redaction():
    rules = {"blocked_keywords": ["credit card", "bank routing", "pin number"], "pii_redaction": True}
    set_policy_state("SOC2", True, rules)

    # Visa
    res1 = client.post("/policies/redact", headers=headers, json={"text": "Visa CC: 4111111111111111"})
    assert "[REDACTED]" in res1.json()["redacted_text"]
    assert "4111111111111111" not in res1.json()["redacted_text"]

    # Mastercard
    res2 = client.post("/policies/redact", headers=headers, json={"text": "Mastercard CC: 5123456789012345"})
    assert "[REDACTED]" in res2.json()["redacted_text"]
    assert "5123456789012345" not in res2.json()["redacted_text"]

    # Amex
    res3 = client.post("/policies/redact", headers=headers, json={"text": "Amex CC: 378282246310005"})
    assert "[REDACTED]" in res3.json()["redacted_text"]
    assert "378282246310005" not in res3.json()["redacted_text"]

    # Discover
    res4 = client.post("/policies/redact", headers=headers, json={"text": "Discover CC: 6011111111111111"})
    assert "[REDACTED]" in res4.json()["redacted_text"]
    assert "6011111111111111" not in res4.json()["redacted_text"]

def test_bank_routing_redaction():
    rules = {"blocked_keywords": ["credit card", "bank routing", "pin number"], "pii_redaction": True}
    set_policy_state("SOC2", True, rules)

    payload = {"text": "Routing number is 123456789"}
    res = client.post("/policies/redact", headers=headers, json=payload)
    assert res.status_code == 200
    assert "[REDACTED]" in res.json()["redacted_text"]
    assert "123456789" not in res.json()["redacted_text"]

def test_pin_redaction():
    rules = {"blocked_keywords": ["credit card", "bank routing", "pin number"], "pii_redaction": True}
    set_policy_state("SOC2", True, rules)

    payload = {"text": "My pin number is 4321"}
    res = client.post("/policies/redact", headers=headers, json=payload)
    assert res.status_code == 200
    assert "[REDACTED]" in res.json()["redacted_text"]
    assert "4321" not in res.json()["redacted_text"]

def test_medical_record_redaction():
    rules = {"blocked_keywords": ["medical record", "health history", "diagnoses", "diagnosis"], "pii_redaction": True}
    set_policy_state("HIPAA", True, rules)

    # MR-12345 format
    res1 = client.post("/policies/redact", headers=headers, json={"text": "medical record MR-12345"})
    assert "[REDACTED]" in res1.json()["redacted_text"]
    assert "MR-12345" not in res1.json()["redacted_text"]

    # EMR-45678 format
    res2 = client.post("/policies/redact", headers=headers, json={"text": "EMR-45678 patient files"})
    assert "[REDACTED]" in res2.json()["redacted_text"]
    assert "EMR-45678" not in res2.json()["redacted_text"]

def test_diagnosis_redaction():
    rules = {"blocked_keywords": ["medical record", "health history", "diagnoses", "diagnosis"], "pii_redaction": True}
    set_policy_state("HIPAA", True, rules)

    # Diagnosis diabetes
    res1 = client.post("/policies/redact", headers=headers, json={"text": "My diagnosis is diabetes"})
    assert res1.json()["redacted_text"] == "My diagnosis is [REDACTED]"

    # Health history asthma
    res2 = client.post("/policies/redact", headers=headers, json={"text": "My health history includes asthma"})
    assert res2.json()["redacted_text"] == "My health history includes [REDACTED]"

def test_policy_toggle_disable():
    # Disable GDPR policy
    set_policy_state("GDPR", False)
    payload = {"text": "My passport number is A1234567"}
    res = client.post("/policies/redact", headers=headers, json=payload)
    # A1234567 should NOT be redacted
    assert "A1234567" in res.json()["redacted_text"]
    assert "[REDACTED]" not in res.json()["redacted_text"]

def test_policy_toggle_enable():
    # Re-enable GDPR policy
    set_policy_state("GDPR", True)
    payload = {"text": "My passport number is A1234567"}
    res = client.post("/policies/redact", headers=headers, json=payload)
    # Now it must redact it again
    assert "A1234567" not in res.json()["redacted_text"]
    assert "[REDACTED]" in res.json()["redacted_text"]

def test_output_redaction():
    rules = {"blocked_keywords": ["passport", "ssn", "social security number"], "pii_redaction": True}
    set_policy_state("GDPR", True, rules)

    # We send "Please return P987654321". Since it does not match blocked keywords (no passport word),
    # it passes the input redaction node unchanged.
    # But when LLM returns it (echoed in mock response), the Output Scan must redact P987654321 to [REDACTED].
    chat_payload = {"session_id": "test-session-output", "message": "Please return P987654321"}
    res = client.post("/chat", headers=headers, json=chat_payload)
    assert res.status_code in (200, 500, 503)
    if res.status_code == 200:
        assert "P987654321" not in res.json()["response"]
        resp_lower = res.json()["response"].lower()
        assert "[redacted]" in resp_lower or "cannot fulfill" in resp_lower or "safety guidelines" in resp_lower or "programmed to be" in resp_lower
    else:
        assert res.json().get("error") in ("provider_unavailable", "provider_not_configured")

def test_audit_log_generation():
    rules = {"blocked_keywords": ["passport", "ssn", "social security number"], "pii_redaction": True}
    set_policy_state("GDPR", True, rules)

    chat_payload = {"session_id": "test-session-audit-trigger", "message": "Trigger log for passport P12345678"}
    res = client.post("/chat", headers=headers, json=chat_payload)
    assert res.status_code in (200, 500, 503)

    # Query the database to check if the audit block contains the policy metadata columns
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT policy_name, policy_type, matched_pattern, redacted_value, username FROM audit_logs WHERE user_query LIKE '%Trigger log%' ORDER BY id DESC LIMIT 1")
        ).fetchone()
        
        assert row is not None
        assert "GDPR" in row.policy_type
        assert "passport" in row.matched_pattern
        assert "P12345678" in row.redacted_value
        assert row.username == "admin_user"

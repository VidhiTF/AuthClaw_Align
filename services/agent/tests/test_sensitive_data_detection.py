from redaction import redact_sensitive_data_rich
from services.security_agent import SecurityAgent
from services.sensitive_data_detection import SensitiveDataDetector


def test_detector_catches_india_identifiers_with_confidence_and_token_metadata():
    text = (
        "Customer email is priya@example.com, Aadhaar is 1234 5678 9012, "
        "PAN is ABCDE1234F, GSTIN is 27ABCDE1234F1Z5."
    )

    redacted, findings = SensitiveDataDetector().redact(text, username="tester")

    assert "priya@example.com" not in redacted
    assert "1234 5678 9012" not in redacted
    assert "ABCDE1234F" not in redacted
    assert "27ABCDE1234F1Z5" not in redacted

    by_type = {finding["matched_pattern"]: finding for finding in findings}
    assert {"email", "aadhaar", "pan", "gstin"}.issubset(by_type)
    assert by_type["aadhaar"]["confidence"] >= 0.98
    assert by_type["pan"]["action"] == "tokenize"
    assert by_type["gstin"]["action"] == "tokenize"

    for finding in findings:
        assert str(finding["redacted_value"]).startswith("tok_")
        assert finding["value_hash"]
        assert "1234 5678 9012" not in str(finding)
        assert "ABCDE1234F" not in str(finding)
        assert "27ABCDE1234F1Z5" not in str(finding)


def test_detector_blocks_common_secrets_without_storing_raw_secret():
    text = (
        "Use api_key=sk-live-secret1234567890 and JWT "
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature."
    )

    redacted, findings = SensitiveDataDetector().redact(text, username="tester")

    assert "sk-live-secret1234567890" not in redacted
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature" not in redacted
    assert any(finding["action"] == "block" for finding in findings)

    serialized_findings = repr(findings)
    assert "sk-live-secret1234567890" not in serialized_findings
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature" not in serialized_findings
    assert "value_hash" in serialized_findings


def test_redaction_pipeline_sanitizes_legacy_metadata_values():
    raw_text = "My phone is 9876543210 and my SSN is 123-45-6789."

    redacted, findings = redact_sensitive_data_rich(raw_text, username="tester")

    assert "9876543210" not in redacted
    assert "123-45-6789" not in redacted
    assert findings
    assert "9876543210" not in repr(findings)
    assert "123-45-6789" not in repr(findings)
    assert all("confidence" in finding for finding in findings)
    assert all("action" in finding for finding in findings)


def test_security_agent_blocks_secret_findings_before_provider():
    result = SecurityAgent().inspect_input(
        "Please call the model with AWS key AKIA1234567890ABCDEF.",
        username="tester",
        tenant_id=1,
    )

    assert result.approved is False
    assert result.risk_level == "HIGH"
    assert "AKIA1234567890ABCDEF" not in result.sanitized_text
    assert any(finding["action"] == "block" for finding in result.findings)
    assert "AKIA1234567890ABCDEF" not in repr(result.findings)

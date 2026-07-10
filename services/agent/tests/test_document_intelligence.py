import os
import json
import hashlib
from datetime import datetime, timezone
import pytest
from sqlalchemy import text
from database import engine

# Import modules to test
from document_processing.parsers import extract_document_text
from document_processing.scanners import scan_text_for_sensitive_data
from document_processing.chunker import split_text_into_chunks
from document_processing.metadata import extract_file_metadata
from document_processing.auditor import create_document_audit, verify_document_audit_chain
from document_processing.orchestrator import run_document_scan_pipeline

@pytest.fixture
def clean_db():
    """Fixture to ensure a fresh test state in document tables."""
    with engine.connect() as conn:
        conn.execute(text("DELETE FROM document_audits"))
        conn.execute(text("DELETE FROM document_findings"))
        conn.execute(text("DELETE FROM document_scans"))
        conn.execute(text("DELETE FROM documents"))
        conn.commit()
    yield

def test_text_parsing():
    """Verify raw plain text parsing helper."""
    test_content = b"AuthClaw compliance scanning parser test."
    parsed = extract_document_text(test_content, "test.txt")
    assert "compliance scanning" in parsed

def test_sensitive_data_scanner():
    """Verify scanners detect SSNs, emails, AWS keys, etc."""
    test_text = (
        "My email is compliance@authclaw.co and phone is +1-555-555-0199. "
        "Here is my SSN: 666-29-9999 and Aadhaar 2345 6789 0123. "
        "Also my OpenAI key is sk-proj-abc123XYZabc123XYZabc123XYZabc123XYZabc123 "
        "and AWS access key is AKIAIOSFODNN7EXAMPLE."
    )
    findings = scan_text_for_sensitive_data(test_text)
    
    types = [f["finding_type"] for f in findings]
    patterns = [f["matched_pattern"] for f in findings]
    
    assert "PII" in types
    assert "Secret" in types
    assert "EMAIL" in patterns
    assert "PHONE" in patterns
    assert "SSN" in patterns
    assert "AADHAAR" in patterns
    assert "AWS_ACCESS_KEY" in patterns
    assert "OPENAI_API_KEY" in patterns

def test_risk_scoring_logic(clean_db):
    """Verify the risk scoring math is calculated correctly."""
    # Register document
    with engine.connect() as conn:
        res = conn.execute(
            text("""
            INSERT INTO documents (filename, source, size_bytes, status, risk_score, severity)
            VALUES ('test_risk.txt', 'local', 100, 'pending', 0, 'LOW')
            RETURNING id
            """)
        )
        doc_id = res.fetchone()[0]
        conn.commit()
        
    # Text with PII and secret
    text_content = (
        "AuthClaw security override procedures. SSN: 666-29-9999. "
        "AWS secret: AKIAIOSFODNN7EXAMPLE."
    )
    
    # Run scan pipeline (using fake LLM path or rules offline)
    os.environ["GOOGLE_API_KEY"] = "dummy" # Enforce rule fallback
    pipeline_res = run_document_scan_pipeline(doc_id, text_content.encode("utf-8"), "test_risk.txt")
    
    assert pipeline_res["document_id"] == doc_id
    assert pipeline_res["risk_score"] < 100
    assert pipeline_res["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    
    # Confirm records in DB
    with engine.connect() as conn:
        doc = conn.execute(text("SELECT risk_score, severity, status FROM documents WHERE id = :id"), {"id": doc_id}).fetchone()
        assert doc is not None
        assert doc[0] == pipeline_res["risk_score"]
        assert doc[1] == pipeline_res["severity"]
        assert doc[2] in ("completed", "pending_approval")

def test_cryptographic_audit_ledger_continuity(clean_db):
    """Verify blockchain style integrity chaining and validation."""
    doc_id = 999
    
    # Create 3 audit records
    h1 = create_document_audit(doc_id, "UPLOAD", "user_test", "Document uploaded successfully")
    h2 = create_document_audit(doc_id, "SCAN", "system", "Scanned 3 PII items")
    h3 = create_document_audit(doc_id, "APPROVE", "approver_1", "Overridden approved")
    
    # Verify chain is valid
    report = verify_document_audit_chain(doc_id)
    assert report["valid"] is True
    assert report["records_checked"] == 3
    assert report["latest_hash"] == h3
    
    # Tamper with the ledger database directly to simulate a hacker
    with engine.connect() as conn:
        conn.execute(
            text("UPDATE document_audits SET details = 'TAMPERED DETAIL' WHERE integrity_hash = :hash"),
            {"hash": h2}
        )
        conn.commit()
        
    # Verify chain detects tampering
    report_after = verify_document_audit_chain(doc_id)
    assert report_after["valid"] is False
    assert "tamper" in report_after["reason"].lower() or "linkage" in report_after["reason"].lower()

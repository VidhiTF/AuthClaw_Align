import os
import time
import json
import logging
import requests
from datetime import datetime, timezone
from sqlalchemy import text
from database import engine

from document_processing.parsers import extract_document_text
from document_processing.metadata import extract_file_metadata
from document_processing.scanners import scan_text_for_sensitive_data
from document_processing.chunker import split_text_into_chunks
from document_processing.auditor import create_document_audit
from approval_store import create_approval

logger = logging.getLogger("authclaw.document_processing.orchestrator")

def run_document_scan_pipeline(doc_id: int, file_bytes: bytes, filename: str, source: str = "local", tenant_id: int = None) -> dict:
    """
    Executes the complete document security & compliance scanning pipeline.
    """
    start_time = time.perf_counter()
    logger.info(f"Starting compliance scan for doc {doc_id}: {filename}")
    
    # 1. Extract text and metadata
    text_content = extract_document_text(file_bytes, filename)
    meta = extract_file_metadata(file_bytes, filename, source_location=source)
    
    # Update document entry with basic details
    with engine.connect() as conn:
        conn.execute(
            text("""
            UPDATE documents 
            SET size_bytes = :size, status = 'scanning', updated_at = :now 
            WHERE id = :id AND (:tenant_id IS NULL OR tenant_id = :tenant_id)
            """),
            {"size": len(file_bytes), "now": datetime.now(timezone.utc), "id": doc_id, "tenant_id": tenant_id}
        )
        conn.commit()
        
    create_document_audit(doc_id, "scan_started", "system", f"Scan pipeline initiated for document: {filename}", tenant_id=tenant_id)
    
    # 2. Chunk text and save to RAG vector database (knowledge_chunks)
    chunks = split_text_into_chunks(text_content)
    from rag.vector_store import save_document_chunks
    try:
        with engine.connect() as conn:
            row = conn.execute(
                text("""
                    SELECT id
                    FROM knowledge_documents
                    WHERE name = :name AND (:tenant_id IS NULL OR tenant_id = :tenant_id)
                """),
                {"name": filename, "tenant_id": tenant_id}
            ).fetchone()
            if row:
                k_doc_id = row[0]
            else:
                import os as _os
                ext = _os.path.splitext(filename)[1].upper().replace(".", "") or "TXT"
                res = conn.execute(
                    text("""
                    INSERT INTO knowledge_documents (tenant_id, name, type, size_bytes, status, last_indexed, chunks_count)
                    VALUES (:tenant_id, :name, :type, :size_bytes, 'indexed', :last_indexed, :chunks_count)
                    RETURNING id
                    """),
                    {
                        "tenant_id": tenant_id,
                        "name": filename,
                        "type": ext,
                        "size_bytes": len(file_bytes),
                        "last_indexed": datetime.now(timezone.utc).date().isoformat(),
                        "chunks_count": len(chunks)
                    }
                )
                k_doc_id = res.fetchone()[0]
                conn.commit()
                
        save_document_chunks(k_doc_id, chunks, tenant_id=tenant_id)
    except Exception as ex:
        logger.error(f"Failed to index chunks into RAG: {ex}")
        
    # 3. Scan for PII, Financial Data, and Secrets (Regex/Entropy scanner)
    findings = scan_text_for_sensitive_data(text_content)
    
    # 4. Compliance Framework Mapping & Heuristic Validation
    text_lower = text_content.lower()
    framework_gaps = []
    
    # Simple pattern verification rules for specific frameworks
    rules = {
        "SOC2": [
            ("mfa", "MFA/Two-Factor Authentication", "Enforce Multi-Factor Authentication (MFA) for administrative access.", "HIGH", "Unauthorized login to cloud admin accounts due to lack of multi-factor check.", "P1"),
            ("rbac", "Role-Based Access Control", "Establish role-based permission policies (RBAC) to ensure least privilege.", "HIGH", "Privilege escalation by regular users to access protected resources.", "P1"),
            ("audit log", "Audit Logging Controls", "Implement centralized audit trail logging to monitor override events.", "MEDIUM", "No trail of system events, leading to untraceable security events.", "P2")
        ],
        "GDPR": [
            ("retention", "Data Retention Policy", "Define data storage and purge periods (e.g. 7-year retention limit).", "MEDIUM", "Keeping customer PII indefinitely, violating privacy rights.", "P2"),
            ("consent", "User Consent Process", "Obtain explicit user opt-in consent prior to collecting personal details.", "MEDIUM", "Storing user logs without consent, risking regulatory fines.", "P2"),
            ("erase", "Right to Erasure", "Provide an operational procedure to purge customer logs upon request.", "MEDIUM", "Inability to fulfill Data Subject Access Deletion Requests (DSAR).", "P2")
        ],
        "HIPAA": [
            ("patient", "Patient Identifiers", "Ensure health registries mask patient name/medical record details.", "HIGH", "Leakage of patient health identifiers (PHI).", "P1"),
            ("ephi", "Electronic Protected Health Information (ePHI)", "Expose no plaintext health history or medical conditions.", "HIGH", "Plaintext exposure of medical histories or treatments.", "P1")
        ],
        "PCI-DSS": [
            ("credit card", "Credit Card Protection", "Do not store card numbers in unmasked plaintext format.", "HIGH", "Plaintext storage of credit card primary account number (PAN).", "P1"),
            ("routing", "Routing Code Masking", "Restrict access to ABA routing bank codes.", "HIGH", "Exposure of ABA bank routing details.", "P1")
        ]
    }
    
    for framework, checks in rules.items():
        for keyword, label, advice, sev, imp, pri in checks:
            if keyword not in text_lower:
                # Estimate line number
                loc = "N/A"
                idx = text_lower.find(keyword)
                if idx != -1:
                    line_no = text_content[:idx].count("\n") + 1
                    loc = f"Line {line_no}"
                
                framework_gaps.append({
                    "finding_type": "Regulatory",
                    "matched_pattern": f"{framework}_{keyword.upper()}_MISSING",
                    "matched_text": f"Missing {label}",
                    "risk_level": sev,
                    "recommendation": f"[{framework}] {advice}",
                    "impact": imp,
                    "priority": pri,
                    "location_evidence": loc
                })
                
    # Merge findings
    all_findings = findings + framework_gaps
    
    # 5. Gemini AI Security Review
    gemini_summary = ""
    api_key = os.getenv("GOOGLE_API_KEY")
    api_url = os.getenv("GOOGLE_API_URL", "https://generativelanguage.googleapis.com")
    model = "gemini-2.5-flash-lite"
    
    is_key_valid = api_key and api_key not in ("dummy", "dummy-api-key", "")
    
    if is_key_valid:
        try:
            prompt = f"""
You are an expert AI Security & Compliance Auditor. Review the document '{filename}' below and provide a structured security assessment.
Analyze the document text for vulnerabilities, sensitive data exposure, and alignment with compliance frameworks (SOC2, GDPR, HIPAA, PCI-DSS, ISO27001).

Document Content (sample):
{text_content[:8000]}

Scanned Heuristics:
{json.dumps(all_findings)}

Return ONLY a JSON response matching this schema:
{{
  "overall_risk_score": <int 0-100>,
  "severity": "<LOW|MEDIUM|HIGH|CRITICAL>",
  "summary": "<Brief compliance executive summary>",
  "ai_findings": [
    {{
      "finding_type": "<PII|Secret|Regulatory|Vulnerability>",
      "matched_pattern": "<Short description of rule>",
      "matched_text": "<Snippet or label>",
      "risk_level": "<LOW|MEDIUM|HIGH|CRITICAL>",
      "recommendation": "<Actionable remediation suggestion>",
      "impact": "<Security threat impact overview>",
      "priority": "<P1|P2|P3>",
      "location_evidence": "<Page number / estimated Paragraph or Line>"
    }}
  ]
}}
Do not include markdown packaging like ```json.
"""
            url = f"{api_url}/v1beta/models/{model}:generateContent?key={api_key}"
            payload = {
                "contents": [{
                    "role": "user",
                    "parts": [{"text": prompt}]
                }]
            }
            res = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=15)
            if res.status_code == 200:
                data = res.json()
                ai_text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
                if ai_text.startswith("```"):
                    start_idx = ai_text.find("{")
                    end_idx = ai_text.rfind("}")
                    if start_idx != -1 and end_idx != -1:
                        ai_text = ai_text[start_idx:end_idx+1]
                ai_data = json.loads(ai_text)
                
                # Merge AI review insights
                gemini_summary = ai_data.get("summary", "")
                ai_findings = ai_data.get("ai_findings", [])
                if ai_findings:
                    all_findings.extend(ai_findings)
            else:
                logger.warning(f"Gemini AI review returned status {res.status_code}: {res.text}")
        except Exception as e:
            logger.error(f"Gemini AI review call failed: {str(e)}")
            
    if not gemini_summary:
        # Local summary fallback
        gemini_summary = f"Automated rules engine scanned document '{filename}'. Detected {len(all_findings)} compliance and security violations."
        
    # 6. Risk Scoring Engine
    risk_score = 100
    severity = "LOW"
    
    # Deductions
    critical_count = 0
    high_count = 0
    medium_count = 0
    
    for f in all_findings:
        rl = f.get("risk_level", "LOW").upper()
        if rl == "CRITICAL":
            critical_count += 1
            risk_score -= 20
        elif rl == "HIGH":
            high_count += 1
            risk_score -= 15
        elif rl == "MEDIUM":
            medium_count += 1
            risk_score -= 8
        else:
            risk_score -= 3
            
    risk_score = max(0, risk_score)
    
    # Override severity and limit score bounds
    if critical_count > 0:
        severity = "CRITICAL"
        risk_score = min(risk_score, 49)
    elif high_count > 0:
        severity = "HIGH"
        risk_score = min(risk_score, 69)
    elif medium_count > 0:
        severity = "MEDIUM"
        risk_score = min(risk_score, 84)
    else:
        severity = "LOW"
        risk_score = max(risk_score, 85)
        
    # Enforce Critical Escalation:
    # If a document contains exposed secrets (AWS key, OpenAI key, JWT token, database connection),
    # override severity to CRITICAL
    has_critical_secrets = any(
        f.get("finding_type") in ("Secret", "Credentials") or 
        f.get("matched_pattern") in ("AWS_ACCESS_KEY", "OPENAI_API_KEY", "JWT_TOKEN", "CONN_STRING", "S3_PUBLIC_ACCESS_ENABLED")
        for f in all_findings
    )
    if has_critical_secrets:
        severity = "CRITICAL"
        risk_score = min(risk_score, 49)
        
    # 7. Real-Time Alerting (trigger notification)
    for f in all_findings:
        if f.get("risk_level", "LOW").upper() in ("CRITICAL", "HIGH"):
            try:
                from document_processing.alerts import trigger_security_alert
                trigger_security_alert(f, filename)
            except Exception as alert_err:
                logger.error(f"Failed to trigger real-time alert: {alert_err}")

    # 8. Human Approval Integration
    status = "completed"
    if severity in ("HIGH", "CRITICAL"):
        status = "pending_approval"
        # Register a Human-in-the-loop (HITL) ticket
        create_approval(
            query=f"Document Compliance Override: {filename}",
            risk_level=severity,
            session_id=f"doc_{doc_id}"
        )
        create_document_audit(
            doc_id, 
            "approval_requested", 
            "system", 
            f"Document flagged as {severity} risk (Score: {risk_score}). Verification requested in Approval Queue.",
            tenant_id=tenant_id
        )
    else:
        create_document_audit(doc_id, "auto_approved", "system", f"Document automatically approved. Risk level: {severity}.", tenant_id=tenant_id)
        
    # 9. Save results to database
    duration_ms = int((time.perf_counter() - start_time) * 1000)
    
    with engine.connect() as conn:
        # Update documents table
        conn.execute(
            text("""
            UPDATE documents 
            SET risk_score = :score, severity = :severity, status = :status, updated_at = :now
            WHERE id = :id AND (:tenant_id IS NULL OR tenant_id = :tenant_id)
            """),
            {
                "score": risk_score,
                "severity": severity,
                "status": status,
                "now": datetime.now(timezone.utc),
                "id": doc_id,
                "tenant_id": tenant_id,
            }
        )
        
        # Save scan run
        scan_res = conn.execute(
            text("""
            INSERT INTO document_scans (tenant_id, document_id, timestamp, scan_duration_ms, raw_findings, status)
            VALUES (:tenant_id, :doc_id, :timestamp, :duration, :findings_json, :status)
            RETURNING id
            """),
            {
                "tenant_id": tenant_id,
                "doc_id": doc_id,
                "timestamp": datetime.now(timezone.utc),
                "duration": duration_ms,
                "findings_json": json.dumps(all_findings),
                "status": "completed"
            }
        )
        
        # Save individual findings with new properties
        for f in all_findings:
            conn.execute(
                text("""
                INSERT INTO document_findings (tenant_id, document_id, finding_type, matched_pattern, matched_text, risk_level, recommendation, impact, priority, location_evidence)
                VALUES (:tenant_id, :doc_id, :ftype, :pattern, :text, :risk, :rec, :impact, :priority, :loc)
                """),
                {
                    "tenant_id": tenant_id,
                    "doc_id": doc_id,
                    "ftype": f.get("finding_type", "Regulatory"),
                    "pattern": f.get("matched_pattern", "UNKNOWN"),
                    "text": f.get("matched_text", "N/A"),
                    "risk": f.get("risk_level", "LOW"),
                    "rec": f.get("recommendation", "Review policy configuration."),
                    "impact": f.get("impact", "Potential compliance gaps in framework requirements."),
                    "priority": f.get("priority", "P3"),
                    "loc": f.get("location_evidence", "N/A")
                }
            )
            
        conn.commit()
        
    create_document_audit(doc_id, "scan_completed", "system", f"Analysis completed in {duration_ms}ms. Risk Score: {risk_score} ({severity}). Findings Count: {len(all_findings)}", tenant_id=tenant_id)
    logger.info(f"Completed scan pipeline for doc {doc_id}: {filename} ({severity} - {risk_score})")
    
    # 10. Record Snapshot in Score History & Calculate Drift
    try:
        from document_processing.drift import record_compliance_snapshot
        record_compliance_snapshot()
    except Exception as drift_err:
        logger.error(f"Failed to log compliance snapshot: {drift_err}")

    return {
        "document_id": doc_id,
        "filename": filename,
        "risk_score": risk_score,
        "severity": severity,
        "status": status,
        "duration_ms": duration_ms,
        "findings": all_findings,
        "summary": gemini_summary
    }

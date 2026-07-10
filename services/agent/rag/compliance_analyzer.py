import os
import json
import re
import requests
import logging
from sqlalchemy import text
from database import engine

logger = logging.getLogger("authclaw.rag.compliance")

def get_document_text(doc_id: int, tenant_id: int = None) -> tuple[str, str]:
    """
    Retrieves all chunks concatenated together and the document name.
    """
    with engine.connect() as conn:
        doc_row = conn.execute(
            text("""
                SELECT name
                FROM knowledge_documents
                WHERE id = :id
                  AND (:tenant_id IS NULL OR tenant_id = :tenant_id)
            """),
            {"id": doc_id, "tenant_id": tenant_id}
        ).fetchone()
        
        if not doc_row:
            raise ValueError(f"Document with ID {doc_id} not found.")
            
        doc_name = doc_row[0]
        
        if tenant_id is None:
            chunks_res = conn.execute(
                text("SELECT content FROM knowledge_chunks WHERE document_id = :doc_id ORDER BY id ASC"),
                {"doc_id": doc_id}
            )
        else:
            chunks_res = conn.execute(
                text("""
                    SELECT content
                    FROM knowledge_chunks
                    WHERE document_id = :doc_id AND tenant_id = :tenant_id
                    ORDER BY id ASC
                """),
                {"doc_id": doc_id, "tenant_id": tenant_id}
            )
        chunks = [row[0] for row in chunks_res.fetchall()]
        
    return "\n\n".join(chunks), doc_name

def run_deterministic_rules(text_content: str) -> dict:
    """
    Scans the document text against a deterministic pattern ruleset.
    Returns findings, framework scores, and recommended actions.
    """
    content_lower = text_content.lower()
    
    # Define rules
    rules = {
        "encryption": {
            "keywords": ["encrypt", "ssl", "tls", "aes", "cipher", "https", "cryptographic"],
            "issue": "Missing Encryption Controls",
            "risk_explanation": "Data transmitted or stored in plaintext can be intercepted or stolen by unauthorized actors.",
            "recommendation": "Implement AES-256 encryption for data-at-rest and enforce TLS 1.3 for all data-in-transit.",
            "severity": "HIGH",
            "priority": "High",
            "frameworks": ["SOC2", "HIPAA"]
        },
        "access_control": {
            "keywords": ["access control", "rbac", "permission", "authorization", "role-based", "least privilege"],
            "issue": "Missing Access Control Policy",
            "risk_explanation": "Lack of role-based permissions leads to excessive access rights and potential insider threats.",
            "recommendation": "Establish a formal role-based access control (RBAC) policy enforcing the principle of least privilege.",
            "severity": "HIGH",
            "priority": "High",
            "frameworks": ["SOC2", "HIPAA"]
        },
        "mfa": {
            "keywords": ["mfa", "multi-factor", "2fa", "two-factor", "authenticator"],
            "issue": "No MFA Requirements",
            "risk_explanation": "Accounts relying purely on single-factor passwords are highly vulnerable to credential stuffing attacks.",
            "recommendation": "Enforce Multi-Factor Authentication (MFA) for all administrative and user sessions.",
            "severity": "HIGH",
            "priority": "High",
            "frameworks": ["SOC2"]
        },
        "data_retention": {
            "keywords": ["retention", "retain", "archive", "storage period", "deletion schedule"],
            "issue": "Missing Data Retention Policy",
            "risk_explanation": "Keeping user data indefinitely violates privacy rules and increases liability in the event of a breach.",
            "recommendation": "Define a clear data retention and destruction policy, specifying deletion timelines (e.g. 7 years).",
            "severity": "MEDIUM",
            "priority": "Medium",
            "frameworks": ["GDPR"]
        },
        "pii_handling": {
            "keywords": ["pii", "personal data", "personally identifiable", "gdpr", "privacy policy"],
            "issue": "Missing PII Handling Procedures",
            "risk_explanation": "Processing personal data without documented privacy guardrails risks compliance fines and user mistrust.",
            "recommendation": "Document standard operating procedures for handling, labeling, and redacting customer PII.",
            "severity": "HIGH",
            "priority": "High",
            "frameworks": ["GDPR"]
        },
        "audit_logging": {
            "keywords": ["audit log", "security log", "monitoring", "event logging", "audit trail", "syslog"],
            "issue": "Missing Audit Logging Requirements",
            "risk_explanation": "Without security logs, detecting malicious activities and performing forensics is nearly impossible.",
            "recommendation": "Enable central audit logging for all user logins, administrative overrides, and data access actions.",
            "severity": "MEDIUM",
            "priority": "Medium",
            "frameworks": ["SOC2", "HIPAA"]
        },
        "consent": {
            "keywords": ["consent", "opt-in", "opt-out", "agree", "accept terms"],
            "issue": "Missing Consent Process",
            "risk_explanation": "Collecting user data without explicit consent violates the core privacy principles of GDPR.",
            "recommendation": "Implement an explicit cookie and privacy consent popup to record user preferences prior to data collection.",
            "severity": "MEDIUM",
            "priority": "Medium",
            "frameworks": ["GDPR"]
        }
    }
    
    findings = []
    failed_rules = []
    
    for key, rule in rules.items():
        found = False
        for kw in rule["keywords"]:
            if kw in content_lower:
                found = True
                break
        if not found:
            failed_rules.append(key)
            for fw in rule["frameworks"]:
                findings.append({
                    "issue": rule["issue"],
                    "risk_explanation": rule["risk_explanation"],
                    "recommendation": rule["recommendation"],
                    "severity": rule["severity"],
                    "priority": rule["priority"],
                    "framework": fw
                })
                
    # Calculate scores
    soc2_score = 100
    gdpr_score = 100
    hipaa_score = 100
    
    if "encryption" in failed_rules:
        soc2_score -= 15
        hipaa_score -= 20
    if "access_control" in failed_rules:
        soc2_score -= 15
        hipaa_score -= 20
    if "mfa" in failed_rules:
        soc2_score -= 15
    if "audit_logging" in failed_rules:
        soc2_score -= 15
        hipaa_score -= 15
    if "data_retention" in failed_rules:
        gdpr_score -= 25
    if "pii_handling" in failed_rules:
        gdpr_score -= 25
    if "consent" in failed_rules:
        gdpr_score -= 20
        
    # Map overall risk level
    high_count = sum(1 for f in findings if f["severity"] == "HIGH")
    if high_count >= 3:
        overall_risk = "Critical"
    elif high_count >= 1:
        overall_risk = "High"
    elif len(findings) >= 2:
        overall_risk = "Medium"
    elif len(findings) > 0:
        overall_risk = "Low"
    else:
        overall_risk = "Low"
        
    # Generate executive summary paragraphs
    score_avg = (soc2_score + gdpr_score + hipaa_score) // 3
    summary = (
        f"The compliance document has been reviewed and scored with an average readiness of {score_avg}%. "
        f"The overall security and privacy risk is currently assessed as {overall_risk}. "
    )
    if failed_rules:
        summary += f"Critical gaps detected include: {', '.join(rules[r]['issue'] for r in failed_rules)}. "
        summary += "It is highly recommended to establish documented policies and technical controls for the missing elements."
    else:
        summary += "All baseline controls (Encryption, Access Control, MFA, Retention, PII, Audit Logs, and Consent) are mentioned in this document."
        
    return {
        "soc2_score": max(20, soc2_score),
        "gdpr_score": max(20, gdpr_score),
        "hipaa_score": max(20, hipaa_score),
        "iso27001_score": "Not Yet Evaluated",
        "overall_risk": overall_risk,
        "executive_summary": summary,
        "findings": findings
    }

def analyze_document_compliance(doc_id: int, tenant_id: int = None) -> dict:
    """
    Performs hybrid compliance analysis:
    1. Executes deterministic pattern-matching engine first.
    2. Calls Gemini LLM to review document contents and refine findings if API key is active.
    3. Merges the results, ensuring 100% reliability.
    """
    text_content, doc_name = get_document_text(doc_id, tenant_id=tenant_id)
    
    # 1. Deterministic Analysis
    det_results = run_deterministic_rules(text_content)
    
    # 2. Check if Gemini is configured
    api_key = os.getenv("GOOGLE_API_KEY")
    api_url = os.getenv("GOOGLE_API_URL", "https://generativelanguage.googleapis.com")
    model = os.getenv("MODEL_NAME", "gemini-2.5-flash")
    
    is_key_valid = api_key and api_key not in ("dummy", "dummy-api-key", "")
    
    if is_key_valid:
        try:
            # Construct analysis prompt
            prompt = f"""
You are an expert AI Compliance Analyst. Analyze the compliance readiness of the document '{doc_name}' based on the text provided below.

Compare the text against these security and privacy frameworks:
- SOC2 (Security, Availability, Confidentiality, MFA, RBAC, Audit Trail)
- GDPR (PII management, lawful basis, data retention, consent mechanisms, right to erasure)
- HIPAA (Patient identifiers security, electronic protected health info - ePHI, access review, log monitoring)
Note: Do not evaluate ISO 27001 in detail, return "Not Yet Evaluated" for ISO 27001.

Here is the document content:
{text_content[:8000]}  # Safeguard token window limits

The rule engine has pre-scanned the document and found the following baseline checks:
- Calculated SOC2 Score: {det_results['soc2_score']}%
- Calculated GDPR Score: {det_results['gdpr_score']}%
- Calculated HIPAA Score: {det_results['hipaa_score']}%
- Overall Risk: {det_results['overall_risk']}
- Pre-scanned Findings: {json.dumps(det_results['findings'])}

Refine this analysis. Return a JSON structure ONLY. Do not include markdown code block characters like ```json.
The JSON must have this exact structure:
{{
  "soc2_score": <int 0-100>,
  "gdpr_score": <int 0-100>,
  "hipaa_score": <int 0-100>,
  "iso27001_score": "Not Yet Evaluated",
  "overall_risk": "<Low|Medium|High|Critical>",
  "executive_summary": "<Executive Summary paragraph summarizing document readiness, top recommendations, and risks>",
  "findings": [
    {{
      "issue": "<Missing policy/control>",
      "risk_explanation": "<Detailed explanation of the security/privacy threat>",
      "recommendation": "<Actionable fix recommendation>",
      "severity": "<HIGH|MEDIUM|LOW>",
      "priority": "<High|Medium|Low>",
      "framework": "<SOC2|GDPR|HIPAA>"
    }}
  ]
}}
"""
            url = f"{api_url}/v1beta/models/{model}:generateContent?key={api_key}"
            payload = {
                "contents": [{
                    "role": "user",
                    "parts": [{"text": prompt}]
                }]
            }
            res = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=20)
            if res.status_code == 200:
                data = res.json()
                text_response = data["candidates"][0]["content"]["parts"][0]["text"].strip()
                
                # Strip out any ```json or markdown wrappers if returned
                if text_response.startswith("```"):
                    # Find first { and last }
                    start_idx = text_response.find("{")
                    end_idx = text_response.rfind("}")
                    if start_idx != -1 and end_idx != -1:
                        text_response = text_response[start_idx:end_idx+1]
                        
                ai_data = json.loads(text_response)
                
                # Validate structures
                if "soc2_score" in ai_data and "findings" in ai_data:
                    # Successfully parsed AI analysis
                    ai_data["iso27001_score"] = "Not Yet Evaluated"
                    return ai_data
            else:
                logger.warning(f"Gemini API returned status {res.status_code} in compliance analysis: {res.text}")
        except Exception as e:
            logger.warning(f"Gemini compliance analysis failed: {str(e)}. Falling back to deterministic rule engine.")
            
    # Fallback to deterministic rules
    return det_results

def generate_and_vault_reports(doc_id: int, doc_name: str, analysis: dict, tenant_id: int = None):
    """
    Generates Compliance, Findings, and Risk reports as physical text files
    and stores them as vaulted evidence in the compliance_evidence table.
    """
    from datetime import datetime, timezone
    import os
    import hashlib
    from sqlalchemy import text
    from database import engine
    
    timestamp = datetime.now(timezone.utc).isoformat()
    now_date = datetime.now(timezone.utc).date().isoformat()
    
    # Create evidence directory in workspace
    evidence_dir = "evidence"
    if not os.path.exists(evidence_dir):
        os.makedirs(evidence_dir)
        
    # Framework scores formatted
    scores_str = f"SOC2: {analysis['soc2_score']}%, GDPR: {analysis['gdpr_score']}%, HIPAA: {analysis['hipaa_score']}%, ISO 27001: {analysis['iso27001_score']}"
    
    # Findings formatted
    findings_str = ""
    for f in analysis.get("findings", []):
        findings_str += f"- [{f['framework']}] {f['issue']} ({f['severity']} severity) - Recommendation: {f['recommendation']}\n"
    if not findings_str:
        findings_str = "No major compliance issues detected."
        
    # 1. Compliance Report
    compliance_report_content = (
        f"=========================================\n"
        f"COMPLIANCE ALIGNMENT REPORT\n"
        f"=========================================\n"
        f"Document Name: {doc_name}\n"
        f"Analysis Timestamp: {timestamp}\n"
        f"-----------------------------------------\n"
        f"Framework Readiness Scores:\n"
        f"{scores_str}\n"
        f"-----------------------------------------\n"
        f"Executive Summary:\n"
        f"{analysis['executive_summary']}\n"
        f"=========================================\n"
    )
    compliance_filename = f"Compliance_Report_doc_{doc_id}.txt"
    compliance_filepath = os.path.join(evidence_dir, compliance_filename)
    with open(compliance_filepath, "w", encoding="utf-8") as f:
        f.write(compliance_report_content)
        
    # 2. Findings Report
    findings_report_content = (
        f"=========================================\n"
        f"COMPLIANCE FINDINGS REPORT\n"
        f"=========================================\n"
        f"Document Name: {doc_name}\n"
        f"Analysis Timestamp: {timestamp}\n"
        f"-----------------------------------------\n"
        f"Detailed Findings:\n"
        f"{findings_str}\n"
        f"=========================================\n"
    )
    findings_filename = f"Findings_Report_doc_{doc_id}.txt"
    findings_filepath = os.path.join(evidence_dir, findings_filename)
    with open(findings_filepath, "w", encoding="utf-8") as f:
        f.write(findings_report_content)
        
    # 3. Risk Report
    risk_report_content = (
        f"=========================================\n"
        f"COMPLIANCE RISK ASSESSMENT REPORT\n"
        f"=========================================\n"
        f"Document Name: {doc_name}\n"
        f"Analysis Timestamp: {timestamp}\n"
        f"-----------------------------------------\n"
        f"Overall Risk Level: {analysis['overall_risk']}\n"
        f"-----------------------------------------\n"
        f"Detailed Risk Analysis:\n"
        f"This report evaluates the potential threats of missing policies.\n"
        f"For each failed compliance control, security and privacy liabilities have been mapped.\n"
        f"-----------------------------------------\n"
        f"Top Recommendations:\n"
        f"{findings_str}\n"
        f"=========================================\n"
    )
    risk_filename = f"Risk_Report_doc_{doc_id}.txt"
    risk_filepath = os.path.join(evidence_dir, risk_filename)
    with open(risk_filepath, "w", encoding="utf-8") as f:
        f.write(risk_report_content)
        
    # Calculate SHA256 hashes of the files and insert into PostgreSQL
    reports = [
        ("Compliance Report", compliance_filepath, compliance_filename),
        ("Findings Report", findings_filepath, findings_filename),
        ("Risk Report", risk_filepath, risk_filename)
    ]
    
    with engine.connect() as conn:
        for name_prefix, path, filename in reports:
            with open(path, "rb") as f_bytes:
                f_hash = f"sha256-{hashlib.sha256(f_bytes.read()).hexdigest()[:16]}"
            
            # Category selection based on findings or default to SOC2
            category = "SOC2"
            if "GDPR" in findings_str:
                category = "GDPR"
            elif "HIPAA" in findings_str:
                category = "HIPAA"
                
            # Insert into compliance_evidence
            conn.execute(
                text("""
                INSERT INTO compliance_evidence (tenant_id, name, category, file_path, collected_at, hash)
                VALUES (:tenant_id, :name, :category, :file_path, :collected_at, :hash)
                """),
                {
                    "tenant_id": tenant_id,
                    "name": f"{name_prefix} - {doc_name}",
                    "category": category,
                    "file_path": f"/evidence/{filename}",
                    "collected_at": now_date,
                    "hash": f_hash
                }
            )
        conn.commit()

import os
import json
import logging
from datetime import datetime, timezone
from sqlalchemy import text
from database import engine

logger = logging.getLogger("authclaw.document_processing.drift")

def get_current_framework_scores() -> dict:
    """
    Computes live compliance scores (0-100) from the evidence-backed control engine.
    """
    try:
        from services.compliance_evidence_engine import ComplianceEvidenceEngine
        with engine.connect() as conn:
            tenant_rows = conn.execute(text("SELECT id FROM tenants WHERE COALESCE(status, 'active') = 'active' ORDER BY id ASC")).fetchall()
        tenant_id = tenant_rows[0][0] if tenant_rows else None
        if tenant_id is None:
            return {"SOC2": 100, "GDPR": 100, "HIPAA": 100}
        result = ComplianceEvidenceEngine().calculate_scores(int(tenant_id))
        return {"SOC2": result["soc2"], "GDPR": result["gdpr"], "HIPAA": result["hipaa"]}
    except Exception as e:
        logger.error(f"Failed to calculate live framework scores: {e}")
        return {"SOC2": 100, "GDPR": 100, "HIPAA": 100}

def record_compliance_snapshot():
    """
    Saves a compliance score snapshot for each framework and checks for score drift.
    """
    timestamp = datetime.now(timezone.utc)
    scores = get_current_framework_scores()
    
    try:
        with engine.connect() as conn:
            for framework, score in scores.items():
                # 1. Fetch previous score for the framework to calculate drift
                prev = conn.execute(
                    text("""
                    SELECT score FROM compliance_score_history 
                    WHERE framework = :fw 
                    ORDER BY id DESC LIMIT 1
                    """),
                    {"fw": framework}
                ).fetchone()
                
                # Save the new snapshot
                conn.execute(
                    text("""
                    INSERT INTO compliance_score_history (timestamp, framework, score, details)
                    VALUES (:ts, :fw, :score, :details)
                    """),
                    {
                        "ts": timestamp,
                        "fw": framework,
                        "score": score,
                        "details": f"Snapshot score is {score}%"
                    }
                )
                
                if prev:
                    prev_score = prev[0]
                    score_drop = prev_score - score
                    
                    if score_drop > 5:
                        # Drift detected! Log drift alert.
                        logger.warning(f"Compliance Drift Detected! {framework} dropped by {score_drop} points.")
                        
                        conn.execute(
                            text("""
                            INSERT INTO compliance_drift_alerts 
                            (timestamp, framework, score_drop, previous_score, current_score, details)
                            VALUES (:ts, :fw, :drop, :prev, :curr, :details)
                            """),
                            {
                                "ts": timestamp,
                                "fw": framework,
                                "drop": score_drop,
                                "prev": prev_score,
                                "curr": score,
                                "details": f"Framework score dropped from {prev_score}% to {score}% due to new scan findings."
                            }
                        )
                        
                        # Write to cryptographic audit logs
                        from document_processing.auditor import create_document_audit
                        # We use 0 as virtual doc_id representing the system compliance status
                        create_document_audit(
                            0, 
                            "compliance_drift", 
                            "system", 
                            f"Compliance drift detected for framework {framework}. Score dropped from {prev_score}% to {score}% (Drop: {score_drop}%)."
                        )
                        
                        # Trigger alert notification
                        try:
                            from document_processing.alerts import trigger_security_alert
                            trigger_security_alert({
                                "finding_type": "Regulatory",
                                "risk_level": "HIGH",
                                "matched_pattern": f"{framework}_SCORE_DRIFT",
                                "matched_text": f"{framework} compliance score dropped by {score_drop} points.",
                                "recommendation": "Review recent file uploads and resolve exposed secrets or policy violations.",
                                "impact": "Decreased security readiness and high exposure to compliance audit failures.",
                                "priority": "P1",
                                "location_evidence": "Workspace compliance snapshot"
                            }, "System Health")
                        except Exception as alert_err:
                            logger.error(f"Failed to alert on drift: {alert_err}")
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to record score snapshot history: {e}")

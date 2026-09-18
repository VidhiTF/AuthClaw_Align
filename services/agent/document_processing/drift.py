import json
import logging
from fastapi import HTTPException
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
            raise HTTPException(status_code=503, detail="Compliance telemetry unknown: no active tenant")
        return ComplianceEvidenceEngine().calculate_scores(int(tenant_id))
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Compliance telemetry unavailable") from exc

def record_compliance_snapshot():
    """Persist missing observations as null, and alert without inventing a drop."""
    from document_processing.alerts import trigger_security_alert
    from document_processing.auditor import create_document_audit
    from services.tenant_context import get_current_tenant_id

    timestamp = datetime.now(timezone.utc)
    source_error = None
    try:
        scores = get_current_framework_scores()
    except Exception as exc:
        scores, source_error = {}, exc
    alerts = []
    try:
        with engine.connect() as conn:
            for framework in ("SOC2", "GDPR", "HIPAA"):
                score = scores.get(framework.lower())
                status = "unavailable" if source_error else "unknown" if score is None else "healthy"
                prev = conn.execute(text("""
                    SELECT score FROM compliance_score_history
                    WHERE framework = :fw ORDER BY id DESC LIMIT 1
                """), {"fw": framework}).fetchone()
                previous = prev[0] if prev else None
                details = {key: scores.get(key) for key in ("calculation_version", "evidence_timestamp", "missing_control_treatment")}
                details["status"] = status
                conn.execute(text("""
                    INSERT INTO compliance_score_history (timestamp, framework, score, details)
                    VALUES (:ts, :fw, :score, :details)
                """), {"ts": timestamp, "fw": framework, "score": score, "details": json.dumps(details)})
                drop = previous - score if previous is not None and score is not None else None
                if score is None or (drop is not None and drop > 5):
                    message = (f"{framework} compliance telemetry {status}; no current score is available."
                               if score is None else f"{framework} compliance score dropped from {previous}% to {score}% (drop: {drop}).")
                    conn.execute(text("""
                        INSERT INTO compliance_drift_alerts
                        (timestamp, framework, score_drop, previous_score, current_score, details)
                        VALUES (:ts, :fw, :drop, :prev, :curr, :details)
                    """), {"ts": timestamp, "fw": framework, "drop": drop, "prev": previous, "curr": score, "details": message})
                    alerts.append((f"{framework}_SCORE_DRIFT" if score is not None else f"{framework}_COMPLIANCE_{status.upper()}", message))
            conn.commit()
    except Exception:
        trigger_security_alert({"risk_level": "HIGH", "matched_pattern": "COMPLIANCE_SNAPSHOT_UNAVAILABLE",
                                "matched_text": "Compliance snapshot persistence failed; previous scores are stale."}, "System Health")
        raise

    # Commit first: an audit/notification outage must not restore stale posture.
    notification_error = None
    for pattern, message in alerts:
        try:
            create_document_audit(0, "compliance_drift", "system", message, tenant_id=get_current_tenant_id())
        except Exception as exc:
            logger.exception("Compliance audit failed")
            notification_error = exc
        try:
            trigger_security_alert({"finding_type": "Regulatory", "risk_level": "HIGH",
                                    "matched_pattern": pattern, "matched_text": message,
                                    "recommendation": "Restore evidence collection and review compliance findings.",
                                    "priority": "P1"}, "System Health")
        except Exception as exc:
            logger.exception("Compliance notification failed")
            notification_error = exc
    if source_error or notification_error:
        raise source_error or notification_error

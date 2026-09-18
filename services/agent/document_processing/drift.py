import json
import logging
from fastapi import HTTPException
from datetime import datetime, timezone
from sqlalchemy import text
from services.tenant_context import validate_tenant_id

logger = logging.getLogger("authclaw.document_processing.drift")

def get_current_framework_scores(tenant_id: int, connection=None) -> dict:
    """Compute evidence-backed scores for the authenticated tenant only."""
    validate_tenant_id(tenant_id)
    try:
        from services.compliance_evidence_engine import ComplianceEvidenceEngine
        return ComplianceEvidenceEngine().calculate_scores(tenant_id, connection)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Compliance telemetry unavailable") from exc

def record_compliance_snapshot(tenant_id: int):
    """Persist missing observations as null, and alert without inventing a drop."""
    from document_processing.alerts import trigger_security_alert
    from document_processing.auditor import create_document_audit
    from services.compliance_evidence_engine import ComplianceEvidenceEngine
    validate_tenant_id(tenant_id)
    source_error = None
    alerts = []
    try:
        with ComplianceEvidenceEngine().transaction(tenant_id) as conn:
            timestamp = datetime.now(timezone.utc)
            try:
                with conn.begin_nested():
                    scores = get_current_framework_scores(tenant_id, conn)
            except Exception as exc:
                scores, source_error = {}, exc
            for framework in ("SOC2", "GDPR", "HIPAA"):
                score = scores.get(framework.lower())
                status = "unavailable" if source_error else "unknown" if score is None else "healthy"
                prev = conn.execute(text("""
                    SELECT score FROM compliance_score_history
                    WHERE tenant_id = :tenant_id AND framework = :fw ORDER BY id DESC LIMIT 1
                """), {"tenant_id": tenant_id, "fw": framework}).fetchone()
                previous = prev[0] if prev else None
                details = {key: scores.get(key) for key in ("calculation_version", "evidence_timestamp", "missing_control_treatment")}
                details["status"] = status
                conn.execute(text("""
                    INSERT INTO compliance_score_history (tenant_id, timestamp, framework, score, details)
                    VALUES (:tenant_id, :ts, :fw, :score, :details)
                """), {"tenant_id": tenant_id, "ts": timestamp, "fw": framework, "score": score, "details": json.dumps(details)})
                drop = previous - score if previous is not None and score is not None else None
                if score is None or (drop is not None and drop > 5):
                    message = f"Tenant {tenant_id}: " + (f"{framework} compliance telemetry {status}; no current score is available."
                               if score is None else f"{framework} compliance score dropped from {previous}% to {score}% (drop: {drop}).")
                    conn.execute(text("""
                        INSERT INTO compliance_drift_alerts
                        (tenant_id, timestamp, framework, score_drop, previous_score, current_score, details)
                        VALUES (:tenant_id, :ts, :fw, :drop, :prev, :curr, :details)
                    """), {"tenant_id": tenant_id, "ts": timestamp, "fw": framework, "drop": drop, "prev": previous, "curr": score, "details": message})
                    alerts.append((f"{framework}_SCORE_DRIFT" if score is not None else f"{framework}_COMPLIANCE_{status.upper()}", message))
    except Exception:
        trigger_security_alert({"risk_level": "HIGH", "matched_pattern": "COMPLIANCE_SNAPSHOT_UNAVAILABLE",
                                "matched_text": f"Tenant {tenant_id}: compliance snapshot persistence failed; previous scores are stale."}, "System Health")
        raise

    # Commit first: an audit/notification outage must not restore stale posture.
    notification_error = None
    for pattern, message in alerts:
        try:
            create_document_audit(0, "compliance_drift", "system", message, tenant_id=tenant_id)
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

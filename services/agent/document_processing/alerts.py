import os
import logging
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger("authclaw.document_processing.alerts")

ALERTS_LOG = os.path.join("logs", "alerts.log")

def trigger_security_alert(finding: dict, filename: str):
    """
    Formats and dispatches a real-time security alert for CRITICAL/HIGH findings.
    Sends an email using standard SMTP. If SMTP host is not configured, it writes
    the alert details to logs/alerts.log and the central audit ledger.
    """
    timestamp = datetime.now().isoformat()
    finding_type = finding.get("finding_type", "Regulatory")
    risk_level = finding.get("risk_level", "HIGH")
    pattern = finding.get("matched_pattern", "VIOLATION")
    text_preview = finding.get("matched_text", "N/A")
    rec = finding.get("recommendation", "N/A")
    impact = finding.get("impact", "N/A")
    priority = finding.get("priority", "P1")
    location = finding.get("location_evidence", "N/A")

    subject = f"⚠️ [AuthClaw Alert] {risk_level} Security Leak Detected in {filename}"
    
    body = f"""
============================================================
AUTHCLAW REAL-TIME COMPLIANCE ALERT
============================================================
Timestamp: {timestamp}
Document: {filename}
Location: {location}

Severity: {risk_level} (Priority: {priority})
Finding Type: {finding_type}
Rule ID: {pattern}
Exposed Snippet: {text_preview}

Impact:
{impact}

Remediation Recommendation:
{rec}
============================================================
"""
    
    # Ensure logs folder exists
    os.makedirs("logs", exist_ok=True)
    
    # 1. Standard fallback logging
    try:
        with open(ALERTS_LOG, "a", encoding="utf-8") as f:
            f.write(f"\nSubject: {subject}\n{body}\n" + "-"*60 + "\n")
    except Exception as e:
        logger.error(f"Failed to write to alerts.log: {e}")

    # 2. SMTP Email Dispatching
    if os.getenv("SKIP_EMAIL_DELIVERY_FOR_TESTING", "").lower() in {"1", "true", "yes", "on"}:
        logger.info("SMTP alert delivery skipped by SKIP_EMAIL_DELIVERY_FOR_TESTING. Alert logged to alerts.log.")
        return

    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = os.getenv("SMTP_PORT", "587")
    smtp_user = os.getenv("SMTP_USERNAME")
    smtp_pass = os.getenv("SMTP_PASSWORD")
    from_email = os.getenv("SMTP_FROM") or os.getenv("SMTP_FROM_EMAIL", "no-reply@authclaw.co")
    admin_email = os.getenv("ADMIN_EMAIL", "compliance-admin@authclaw.co")
    smtp_use_tls = os.getenv("SMTP_USE_TLS", "true").lower() in {"1", "true", "yes", "on"}

    if smtp_host:
        try:
            msg = MIMEMultipart()
            msg["From"] = from_email
            msg["To"] = admin_email
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))
            
            with smtplib.SMTP(smtp_host, int(smtp_port), timeout=10) as server:
                if smtp_use_tls:
                    server.starttls()
                if smtp_user and smtp_pass:
                    server.login(smtp_user, smtp_pass)
                server.sendmail(from_email, [admin_email], msg.as_string())
            logger.info(f"Successfully sent security alert email to {admin_email}")
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
    else:
        logger.info(f"SMTP not configured. Alert logged to alerts.log (unreachable SMTP_HOST)")

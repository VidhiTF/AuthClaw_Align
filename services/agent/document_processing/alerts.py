"""Tenant-authorized alert transport; durable delivery belongs to EventPipeline."""
import os
import smtplib
from contextlib import nullcontext
from email.message import EmailMessage

from sqlalchemy import text
from database import engine
from services.tenant_context import validate_tenant_id


def trigger_security_alert(event: dict, *, connection=None):
    tenant_id = event["tenant_id"]
    validate_tenant_id(tenant_id)
    # Re-resolve recipients on every retry so revocation takes effect immediately.
    with nullcontext(connection) if connection is not None else engine.connect() as conn:
        recipients = conn.execute(text("""
            SELECT email FROM tenant_users
            WHERE tenant_id = :tenant AND status = 'active' AND email_verified = TRUE
                AND lower(role) IN ('super admin', 'admin', 'owner')
                AND EXISTS (SELECT 1 FROM documents WHERE id = :document AND tenant_id = :tenant)
        """), {"tenant": tenant_id, "document": event["document_id"]}).scalars().all()
    if not recipients or any("@" not in email or any(char in email for char in "\r\n,;") for email in recipients):
        raise RuntimeError("No authorized alert recipient")
    host = os.getenv("SMTP_HOST")
    if not host or os.getenv("SKIP_EMAIL_DELIVERY_FOR_TESTING", "").lower() in {"1", "true", "yes", "on"}:
        raise RuntimeError("Alert email delivery is disabled")
    message = EmailMessage()
    message["From"] = os.getenv("SMTP_FROM") or os.getenv("SMTP_FROM_EMAIL", "no-reply@authclaw.co")
    message["To"] = ", ".join(recipients)
    message["Subject"] = "[AuthClaw Alert] Document security findings require review"
    # Never copy filenames, matched secrets, or tenant evidence into shared logs/email.
    message.set_content("A document scan requires attention. Sign in to your tenant console to review its findings.")
    with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", "587")), timeout=10) as server:
        if os.getenv("SMTP_USE_TLS", "true").lower() in {"1", "true", "yes", "on"}:
            server.starttls()
        if os.getenv("SMTP_USERNAME") and os.getenv("SMTP_PASSWORD"):
            server.login(os.environ["SMTP_USERNAME"], os.environ["SMTP_PASSWORD"])
        if server.send_message(message):
            raise RuntimeError("Alert recipients refused delivery")

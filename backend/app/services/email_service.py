from __future__ import annotations

import json
import os
import smtplib
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path


@dataclass(frozen=True)
class EmailDeliveryResult:
    method: str
    detail: str


class EmailDeliveryError(RuntimeError):
    pass


def demo_otp_visible() -> bool:
    return os.getenv("DEMO_OTP_VISIBLE", "false").lower() == "true"


def smtp_configured() -> bool:
    return bool(os.getenv("SMTP_HOST", "").strip())


def _send_smtp_message(message: EmailMessage) -> None:
    smtp_host = os.getenv("SMTP_HOST", "").strip()
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", os.getenv("SMTP_USERNAME", "")).strip()
    smtp_password = os.getenv("SMTP_PASSWORD", os.getenv("SMTP_PASS", ""))
    smtp_tls = (
        os.getenv("SMTP_TLS", os.getenv("SMTP_STARTTLS", "true")).lower() == "true"
    )

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            if smtp_tls:
                server.starttls()
            if smtp_user:
                server.login(smtp_user, smtp_password)
            server.send_message(message)
    except Exception as exc:
        raise EmailDeliveryError("Could not send email") from exc


def send_email(email: str, subject: str, body: str) -> EmailDeliveryResult:
    """Send a non-OTP email through the existing SMTP transport."""
    smtp_host = os.getenv("SMTP_HOST", "").strip()
    if not smtp_host:
        if os.getenv("AUTHCLAW_ENV", "").lower() == "production":
            raise EmailDeliveryError("Email delivery is not configured")
        return _write_local_email(email, subject, body)

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = os.getenv(
        "SMTP_FROM", os.getenv("EMAIL_FROM", "no-reply@authclaw.local")
    ).strip()
    message["To"] = email
    message.set_content(body)
    _send_smtp_message(message)
    return EmailDeliveryResult(method="smtp", detail="Email sent by SMTP")


def send_otp_email(
    email: str,
    otp: str,
    tenant_name: str,
    *,
    purpose: str = "tenant setup",
    action_url: str | None = None,
) -> EmailDeliveryResult:
    smtp_host = os.getenv("SMTP_HOST", "").strip()
    if not smtp_host:
        if os.getenv("AUTHCLAW_ENV", "").lower() != "production":
            return _write_local_outbox(
                email, otp, tenant_name, purpose=purpose, action_url=action_url
            )
        raise EmailDeliveryError("Email delivery is not configured")

    smtp_from = os.getenv(
        "SMTP_FROM", os.getenv("EMAIL_FROM", "no-reply@authclaw.local")
    ).strip()

    message = EmailMessage()
    message["Subject"] = "Your AuthClaw verification code"
    message["From"] = smtp_from
    message["To"] = email
    body = (
        f"Your AuthClaw verification code is {otp}.\n\n"
        f"It expires in 15 minutes for {purpose}: {tenant_name}.\n\n"
    )
    if action_url:
        body += f"Open this invite link to verify: {action_url}\n\n"
    body += "If you did not request this code, you can ignore this email."
    message.set_content(body)

    _send_smtp_message(message)
    return EmailDeliveryResult(method="smtp", detail="OTP sent by SMTP")


def _write_local_outbox(
    email: str,
    otp: str,
    tenant_name: str,
    *,
    purpose: str,
    action_url: str | None,
) -> EmailDeliveryResult:
    event = {
        "sent_at": datetime.now(timezone.utc).isoformat(),
        "to": email,
        "tenant_name": tenant_name,
        "purpose": purpose,
        "otp": otp,
        "action_url": action_url,
    }
    return _write_local_outbox_event(event)


def _write_local_email(email: str, subject: str, body: str) -> EmailDeliveryResult:
    return _write_local_outbox_event(
        {
            "sent_at": datetime.now(timezone.utc).isoformat(),
            "to": email,
            "subject": subject,
            "body": body,
        }
    )


def _write_local_outbox_event(event: dict[str, str | None]) -> EmailDeliveryResult:
    outbox_path = Path(
        os.getenv("AUTHCLAW_EMAIL_OUTBOX_PATH", ".authclaw/email-outbox.jsonl")
    )
    outbox_path.parent.mkdir(parents=True, exist_ok=True)
    with outbox_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, sort_keys=True) + "\n")
    return EmailDeliveryResult(method="local_outbox", detail=str(outbox_path))

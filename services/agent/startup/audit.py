import json
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("authclaw.audit")


def log_approval_event(
    event: str,
    approval_id: str,
    request_id: str,
    correlation_id: str,
    extra: Optional[dict] = None
) -> None:
    """
    Emits a structured JSON log entry for an approval lifecycle event.

    Events:
      approval_created       - A new HIGH-risk approval request was created.
      approval_approved      - An approval was granted (after MFA verification).
      approval_rejected      - An approval was explicitly rejected.
      approval_expired       - An approval passed its expiry window.
      approval_mfa_failed    - An MFA code provided was incorrect.
      approval_legacy_bypass - Approval bypassed MFA due to legacy compatibility mode.
      approval_executed      - An approved request was successfully executed.
    """
    log_entry = {
        "event": event,
        "approval_id": approval_id,
        "request_id": request_id,
        "correlation_id": correlation_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if extra:
        log_entry["details"] = extra

    logger.info(json.dumps(log_entry))
    print(json.dumps(log_entry), flush=True)


def log_audit_event(
    event: str,
    correlation_id: str,
    extra: Optional[dict] = None
) -> None:
    """
    Emits a structured JSON log entry for a general audit chain lifecycle event.
    """
    log_entry = {
        "event": event,
        "correlation_id": correlation_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if extra:
        log_entry.update(extra)

    logger.info(json.dumps(log_entry))
    print(json.dumps(log_entry), flush=True)

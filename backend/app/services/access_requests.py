"""Public demo and early-access intake persistence."""

from datetime import datetime, timezone
import logging
import uuid

from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import AccessRequest, AccessRequestHistory
from app.schemas.models import AccessRequestCreate
from app.services import event_backbone
from app.services.email_service import send_email

logger = logging.getLogger("services.access_requests")
ALLOWED_TRANSITIONS = {
    "PENDING": {"APPROVED", "REJECTED", "INVITED"},
}


def _history(
    request: AccessRequest,
    event_type: str,
    *,
    actor_id=None,
    old_status: str | None = None,
    new_status: str | None = None,
    metadata: dict | None = None,
) -> AccessRequestHistory:
    return AccessRequestHistory(
        access_request_id=request.id,
        actor_id=actor_id,
        event_type=event_type,
        old_status=old_status,
        new_status=new_status,
        event_metadata=metadata or {},
    )


def create_access_request(db: Session, payload: AccessRequestCreate) -> AccessRequest:
    request = AccessRequest(
        reference=f"AR-{uuid.uuid4().hex.upper()}",
        name=payload.name,
        business_email=str(payload.business_email).lower(),
        company=payload.company,
        role=payload.role,
        use_case=payload.use_case,
        requested_access=payload.requested_access,
        consent_timestamp=datetime.now(timezone.utc),
        notice_version=settings.PRIVACY_NOTICE_VERSION,
        source_page=payload.source_page,
        status="PENDING",
    )
    try:
        db.add(request)
        db.flush()
        db.add(
            _history(
                request,
                "CREATED",
                new_status="PENDING",
            )
        )
        db.commit()
        db.refresh(request)
    except Exception:
        db.rollback()
        raise
    event_backbone.increment_metric("access_request_submission_received_total")
    return request


def deliver_access_request_emails(
    request: AccessRequest, db: Session | None = None
) -> None:
    messages = [
        (
            settings.INTERNAL_LAUNCH_OWNER_EMAIL,
            "New AuthClaw access request",
            f"A new access request is pending review.\n\nReference: {request.reference}\n",
            "access_request_notification_sent_total",
        ),
        (
            request.business_email,
            "We received your AuthClaw request",
            (
                "Thank you for contacting AuthClaw.\n\n"
                f"Reference: {request.reference}\n\n"
                "Our team will review your request and follow up with next steps.\n"
            ),
            "access_request_confirmation_sent_total",
        ),
    ]
    failed_notifications = []
    for recipient, subject, body, metric in messages:
        if not recipient:
            event_backbone.increment_metric("access_request_email_failures_total")
            logger.warning("Access request email delivery failed")
            failed_notifications.append(metric)
            continue
        for attempt in range(2):
            try:
                send_email(recipient, subject, body)
                event_backbone.increment_metric(metric)
                break
            except Exception:
                if attempt == 0:
                    continue
                event_backbone.increment_metric("access_request_email_failures_total")
                logger.warning("Access request email delivery failed")
                failed_notifications.append(metric)
    if db is not None and failed_notifications:
        for metric in failed_notifications:
            db.add(
                _history(
                    request,
                    "NOTIFICATION_FAILED",
                    metadata={"notification": metric},
                )
            )
        try:
            db.commit()
        except Exception:
            db.rollback()


def transition_access_request(
    db: Session,
    *,
    reference: str,
    new_status: str,
    actor_id,
) -> AccessRequest:
    request = (
        db.query(AccessRequest)
        .filter(AccessRequest.reference == reference)
        .with_for_update()
        .one_or_none()
    )
    if request is None:
        raise LookupError("Access request not found")
    old_status = request.status
    if new_status not in ALLOWED_TRANSITIONS.get(old_status, set()):
        raise ValueError("Invalid access request transition")

    request.status = new_status
    request.updated_at = datetime.now(timezone.utc)
    db.add(
        _history(
            request,
            new_status,
            actor_id=actor_id,
            old_status=old_status,
            new_status=new_status,
        )
    )
    try:
        db.commit()
        db.refresh(request)
    except Exception:
        db.rollback()
        raise
    event_backbone.increment_metric("access_request_status_changed_total")
    return request

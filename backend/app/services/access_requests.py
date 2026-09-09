"""Public demo and early-access intake persistence."""

from datetime import datetime, timedelta, timezone
import hashlib
import logging
import os
import secrets
import uuid

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.crypto import get_session_key_ring
from app.db.models import AccessRequest, AccessRequestHistory, Tenant
from app.schemas.models import AccessRequestCreate
from app.services import event_backbone
from app.services.email_service import EmailDeliveryError, demo_otp_visible, send_email, send_otp_email

logger = logging.getLogger("services.access_requests")
OTP_TTL_MINUTES = 15
ALLOWED_TRANSITIONS = {
    "PENDING": {"APPROVED", "REJECTED", "INVITED"},
}


def list_access_requests(
    db: Session,
    *,
    status: str | None = None,
    requested_access: str | None = None,
    limit: int = 100,
) -> list[AccessRequest]:
    query = db.query(AccessRequest)
    if status:
        query = query.filter(AccessRequest.status == status)
    if requested_access:
        query = query.filter(AccessRequest.requested_access == requested_access)
    return (
        query.order_by(AccessRequest.created_at.desc(), AccessRequest.reference.desc())
        .limit(limit)
        .all()
    )


def list_access_request_histories(
    db: Session,
    request_ids: list[uuid.UUID],
) -> dict[uuid.UUID, list[AccessRequestHistory]]:
    if not request_ids:
        return {}
    rows = (
        db.query(AccessRequestHistory)
        .filter(AccessRequestHistory.access_request_id.in_(request_ids))
        .order_by(AccessRequestHistory.created_at.desc())
        .all()
    )
    grouped: dict[uuid.UUID, list[AccessRequestHistory]] = {}
    for row in rows:
        grouped.setdefault(row.access_request_id, []).append(row)
    return grouped


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


def _otp_hash(email: str, otp: str) -> str:
    active, keys = get_session_key_ring()
    material = f"{email.strip().lower()}:{otp}:{keys[active]}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _generate_otp() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def _console_url() -> str:
    return (
        os.getenv("PUBLIC_CONSOLE_URL")
        or os.getenv("NEXT_PUBLIC_CONSOLE_URL")
        or os.getenv("NEXT_PUBLIC_APP_URL")
        or "http://localhost:3001"
    ).rstrip("/")


def _request_tenant_name(request: AccessRequest, *, with_reference_suffix: bool = False) -> str:
    name = request.company.strip()
    if not with_reference_suffix:
        return name[:255]
    suffix = request.reference[-8:] if request.reference else uuid.uuid4().hex[:8].upper()
    return f"{name[:242]} {suffix}".strip()


def _create_platform_tenant(db: Session, request: AccessRequest) -> tuple[Tenant, bool]:
    tenant_id = uuid.uuid4()
    tenant_name = _request_tenant_name(request)
    try:
        with db.begin_nested():
            tenant_row = db.execute(
                text(
                    """
                    SELECT id, name, tier, status, created_at, updated_at
                      FROM authn.create_tenant_as_platform_admin(:id, :name, :tier)
                    """
                ),
                {"id": str(tenant_id), "name": tenant_name, "tier": "starter"},
            ).one()
    except IntegrityError:
        tenant_id = uuid.uuid4()
        tenant_name = _request_tenant_name(request, with_reference_suffix=True)
        tenant_row = db.execute(
            text(
                """
                SELECT id, name, tier, status, created_at, updated_at
                  FROM authn.create_tenant_as_platform_admin(:id, :name, :tier)
                """
            ),
            {"id": str(tenant_id), "name": tenant_name, "tier": "starter"},
        ).one()

    return (
        Tenant(
            id=tenant_row.id,
            name=tenant_row.name,
            tier=tenant_row.tier,
            status=tenant_row.status,
            created_at=tenant_row.created_at,
            updated_at=tenant_row.updated_at,
        ),
        True,
    )


def create_access_request_invitation(
    db: Session,
    request: AccessRequest,
    *,
    actor_id,
) -> dict:
    email = request.business_email.strip().lower()
    tenant = db.query(Tenant).filter(Tenant.name == request.company).first()
    tenant_was_created = False
    if not tenant:
        tenant, tenant_was_created = _create_platform_tenant(db, request)

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=OTP_TTL_MINUTES)
    otp = _generate_otp()
    invite = db.execute(
        text(
            """
            SELECT invite_id, tenant_name, resend_count
              FROM authn.create_platform_tenant_owner_invite(
                :tenant_id, :email, :otp_hash, :expires_at
              )
            """
        ),
        {
            "tenant_id": str(tenant.id),
            "email": email,
            "otp_hash": _otp_hash(email, otp),
            "expires_at": expires_at,
        },
    ).one()

    invite_link = f"{_console_url()}/signup?invite={invite.invite_id}"
    metadata = {
        "tenant_id": str(tenant.id),
        "tenant_name": invite.tenant_name,
        "tenant_created": tenant_was_created,
        "invite_id": str(invite.invite_id),
        "invite_link": invite_link,
        "email": email,
        "invited_role": "owner",
        "expires_at": expires_at.isoformat(),
        "resend_count": invite.resend_count,
        "manual_send_available": True,
    }
    try:
        delivery = send_otp_email(
            email,
            otp,
            invite.tenant_name,
            purpose="tenant invite",
            action_url=invite_link,
        )
        metadata["delivery"] = delivery.method
        if delivery.method == "local_outbox" or (
            delivery.method == "console" and demo_otp_visible()
        ):
            metadata["dev_otp"] = otp
        event_backbone.increment_metric("access_request_invitation_created_total")
    except EmailDeliveryError:
        metadata["delivery"] = "failed"
        metadata["delivery_error"] = "Invitation delivery is temporarily unavailable."
        event_backbone.increment_metric("access_request_invitation_delivery_failed_total")
    return metadata


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
    create_invitation: bool = False,
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
    if create_invitation and new_status in {"APPROVED", "INVITED"}:
        metadata = create_access_request_invitation(
            db,
            request,
            actor_id=actor_id,
        )
        db.add(
            _history(
                request,
                "INVITATION_READY"
                if metadata.get("delivery") != "failed"
                else "INVITATION_DELIVERY_FAILED",
                actor_id=actor_id,
                metadata=metadata,
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

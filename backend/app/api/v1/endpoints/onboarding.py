from __future__ import annotations

import hashlib
import json
import hmac
import logging
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import redis
from redis.backoff import NoBackoff
from redis.retry import Retry
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.auth import get_tenant_db, hash_key, require_scopes
from app.db.session import SessionLocal
from app.core.crypto import get_session_key_ring
from app.core.passwords import hash_password, validate_password
from app.db.models import (
    APIKey,
    OnboardingEmailOTP,
    OnboardingStatus,
    Tenant,
    User,
)
from app.schemas.models import (
    OnboardingChecklistResponse,
    OnboardingResendRequest,
    OnboardingResendResponse,
    OnboardingSignupRequest,
    OnboardingSignupResponse,
    OnboardingVerifyRequest,
    OnboardingVerifyResponse,
)
from app.services.email_service import EmailDeliveryError, demo_otp_visible, send_otp_email
from app.services import event_backbone
from app.services.abuse_controls import atomic_increment
from app.services.legal_acceptance import validate_legal_acceptance

router = APIRouter()
logger = logging.getLogger(__name__)
_invitation_kafka_producer = None

DEFAULT_PROVIDER = "gemini"
DEFAULT_MODEL = "gemini-2.5-flash-lite"
OTP_TTL_MINUTES = 15
OTP_RESEND_COOLDOWN_SECONDS = 60
OTP_MAX_RESENDS = 3
OTP_MAX_ATTEMPTS = 5
ONBOARDING_SIGNUP_EMAIL_PER_HOUR = int(os.getenv("ONBOARDING_SIGNUP_EMAIL_PER_HOUR", "3"))
ONBOARDING_SIGNUP_IP_PER_DAY = int(os.getenv("ONBOARDING_SIGNUP_IP_PER_DAY", "10"))
ONBOARDING_VERIFY_IP_PER_HOUR = int(os.getenv("ONBOARDING_VERIFY_IP_PER_HOUR", "30"))
INVALID_INVITATION_DETAIL = "Invitation is invalid or unavailable"

_redis_client: redis.Redis | None = None


def _emit_invitation_audit(
    invitation: OnboardingEmailOTP | None,
    action: str,
    reason: str,
    request_id: str,
    response_status: int,
) -> None:
    if not invitation or invitation.purpose != "invite" or not invitation.tenant_id:
        event_backbone.increment_metric(f"invitation_{action}_total")
        logger.info(
            "[INVITATION_AUDIT] action=%s reason=%s request_id=%s result=failure response_status=%s",
            action,
            reason,
            request_id,
            response_status,
        )
        return
    global _invitation_kafka_producer
    event = event_backbone.audit_event(
        event_type="invitation",
        tenant_id=str(invitation.tenant_id),
        subject_id=str(invitation.id),
        identity_action=f"{action}:{request_id or uuid.uuid4()}",
        action=f"invitation:{action}",
        reason=reason,
        provider="onboarding",
        request_id=request_id,
    )
    event["actor_id"] = ""
    event["result"] = "success" if response_status < 400 else "failure"
    event["response_status"] = response_status
    event_backbone.increment_metric(f"invitation_{action}_total")
    if _invitation_kafka_producer is None:
        try:
            _invitation_kafka_producer = event_backbone.make_kafka_producer()
        except Exception:
            logger.warning("Invitation audit Kafka producer unavailable")
    if exc := event_backbone.publish_audit_event(
        _invitation_kafka_producer,
        str(invitation.tenant_id),
        event,
    ):
        logger.warning("Failed to publish invitation audit event: action=%s", action)


def _invitation_audit_snapshot(invitation: OnboardingEmailOTP):
    return SimpleNamespace(
        id=invitation.id,
        purpose=invitation.purpose,
        tenant_id=invitation.tenant_id,
    )


def _invalid_invitation() -> HTTPException:
    return HTTPException(status_code=400, detail=INVALID_INVITATION_DETAIL)


# Compatibility name retained for focused tests; this is always the
# least-privileged runtime factory and never reads OWNER_DATABASE_URL.
OwnerSessionLocal = SessionLocal


def _otp_hash(email: str, otp: str, secret: str | None = None) -> str:
    active, keys = get_session_key_ring()
    secret = secret or keys[active]
    material = f"{email.strip().lower()}:{otp}:{secret}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _api_key_hash(raw_key: str) -> str:
    return hash_key(raw_key)


def _rate_limit_hash(value: str) -> str:
    return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()[:24]


def _client_ip(request: Request) -> str:
    if request.client:
        return request.client.host
    return "unknown"


def _get_redis() -> redis.Redis:
    global _redis_client
    if _redis_client is None:
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
        if redis_url and not redis_url.startswith(("redis://", "rediss://")):
            redis_url = f"redis://{redis_url}"
        _redis_client = redis.from_url(
            redis_url,
            decode_responses=True,
            socket_connect_timeout=1.0,
            socket_timeout=1.0,
            retry_on_timeout=False,
            retry=Retry(NoBackoff(), 0),
        )
    return _redis_client


def _enforce_onboarding_rate_limit(key: str, limit: int, window_seconds: int, message: str) -> None:
    if limit <= 0:
        return
    try:
        client = _get_redis()
        count, _ttl_ms = atomic_increment(client, key, window_seconds)
    except redis.RedisError as exc:
        ambiguous = isinstance(exc, redis.TimeoutError)
        event_backbone.increment_metric(
            "rate_limiter_ambiguous_total" if ambiguous else "rate_limiter_unavailable_total"
        )
        logger.warning("[RATE_LIMIT_AUDIT] outcome=unavailable ambiguous=%s", ambiguous)
        raise HTTPException(
            status_code=503,
            detail="Rate limiter unavailable. Request blocked for safety.",
        ) from exc
    if count > limit:
        event_backbone.increment_metric("rate_limiter_throttled_total")
        logger.info("[RATE_LIMIT_AUDIT] outcome=throttled")
        raise HTTPException(status_code=429, detail=message)


def _generate_otp() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def _generate_gateway_key() -> str:
    return "acl_live_" + secrets.token_urlsafe(24)


def _generate_session_token() -> str:
    return "acl_session_" + secrets.token_urlsafe(32)


def _scopes_for_role(role: str) -> list[str]:
    if role in ("owner", "admin"):
        return ["admin", "read", "write"]
    return ["read"]


def _next_resend_at(sent_at: datetime | None) -> datetime:
    base = sent_at or datetime.now(timezone.utc)
    if base.tzinfo is None:
        base = base.replace(tzinfo=timezone.utc)
    return base + timedelta(seconds=OTP_RESEND_COOLDOWN_SECONDS)


def _deliver_otp(
    email: str,
    otp: str,
    tenant_name: str,
    *,
    purpose: str = "tenant setup",
    action_url: str | None = None,
) -> tuple[str, str | None]:
    result = send_otp_email(email, otp, tenant_name, purpose=purpose, action_url=action_url)
    dev_otp = otp if result.method == "console" and demo_otp_visible() else None
    return result.method, dev_otp


def _checklist(status_row: OnboardingStatus) -> OnboardingChecklistResponse:
    return OnboardingChecklistResponse(
        email_verified=status_row.email_verified,
        tenant_created=status_row.tenant_created,
        api_key_issued=status_row.api_key_issued,
        provider_key_saved=status_row.provider_key_saved,
        route_created=status_row.route_created,
        policy_created=status_row.policy_created,
        snippet_viewed=status_row.snippet_viewed,
        current_step=status_row.current_step,
    )


def _snippets(api_key: str, gateway_url: str) -> tuple[str, str]:
    endpoint = f"{gateway_url.rstrip('/')}/v1/models/{DEFAULT_MODEL}:generateContent"
    powershell = f'''$body = @{{
  contents = @(
    @{{
      parts = @(
        @{{ text = "My email is jane@example.com. Make this support response safer." }}
      )
    }}
  )
}} | ConvertTo-Json -Depth 6

Invoke-WebRequest `
  -Uri "{endpoint}" `
  -Method Post `
  -Headers @{{
    Authorization = "Bearer {api_key}"
    "X-Provider" = "{DEFAULT_PROVIDER}"
    "X-Request-ID" = "onboarding-test-001"
  }} `
  -ContentType "application/json" `
  -Body $body'''
    curl = f'''curl -X POST "{endpoint}" \\
  -H "Authorization: Bearer {api_key}" \\
  -H "X-Provider: {DEFAULT_PROVIDER}" \\
  -H "X-Request-ID: onboarding-test-001" \\
  -H "Content-Type: application/json" \\
  --data-raw '{{"contents":[{{"parts":[{{"text":"My email is jane@example.com. Make this support response safer."}}]}}]}}'
'''
    return powershell, curl


@router.post("/signup", response_model=OnboardingSignupResponse, status_code=status.HTTP_202_ACCEPTED)
def signup(payload: OnboardingSignupRequest, request: Request):
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="An approved tenant invitation is required",
    )


@router.post("/resend", response_model=OnboardingResendResponse)
def resend(payload: OnboardingResendRequest, request: Request):
    now = datetime.now(timezone.utc)
    otp = _generate_otp()
    expires_at = now + timedelta(minutes=OTP_TTL_MINUTES)
    request_id = request.headers.get("x-request-id", "")

    db = OwnerSessionLocal()
    try:
        active_key, session_keys = get_session_key_ring()
        preauth = db.execute(
            text(
                """
                SELECT outcome, tenant_id, email, tenant_name
                  FROM authn.prepare_onboarding_invite_resend(
                    :signup_id, :otp, :secret, :expires_at,
                    :max_resends, :cooldown_seconds
                  )
                """
            ),
            {
                "signup_id": str(payload.signup_id),
                "otp": otp,
                "secret": session_keys[active_key],
                "expires_at": expires_at,
                "max_resends": OTP_MAX_RESENDS,
                "cooldown_seconds": OTP_RESEND_COOLDOWN_SECONDS,
            },
        ).one()
        if preauth.outcome != "valid":
            db.rollback()
            if preauth.outcome == "cooldown":
                raise HTTPException(status_code=429, detail="Please wait before resending")
            if preauth.outcome == "too_many":
                raise HTTPException(status_code=429, detail="Too many verification code resends")
            _emit_invitation_audit(
                None, "InviteRedemptionFailed", "invitation_not_pending",
                request_id, 400,
            )
            raise _invalid_invitation()
        signup_row = (
            db.query(OnboardingEmailOTP)
            .filter(OnboardingEmailOTP.id == payload.signup_id)
            .with_for_update()
            .first()
        )
        if not signup_row:
            _emit_invitation_audit(
                None,
                "InviteRedemptionFailed",
                "invitation_not_found",
                request_id,
                400,
            )
            raise _invalid_invitation()
        if signup_row.status != "pending":
            _emit_invitation_audit(
                signup_row,
                "InviteRedemptionFailed",
                "invitation_not_pending",
                request_id,
                400,
            )
            raise _invalid_invitation()

        email_hash = _rate_limit_hash(signup_row.email)
        ip_hash = _rate_limit_hash(_client_ip(request))
        _enforce_onboarding_rate_limit(
            f"onboarding:resend:email:{email_hash}:{now.strftime('%Y%m%d%H')}",
            ONBOARDING_SIGNUP_EMAIL_PER_HOUR,
            3700,
            "Too many verification code resends for this email. Try again later.",
        )
        _enforce_onboarding_rate_limit(
            f"onboarding:resend:ip:{ip_hash}:{now.strftime('%Y%m%d')}",
            ONBOARDING_SIGNUP_IP_PER_DAY,
            90000,
            "Too many verification code resends from this network today.",
        )

        delivery, dev_otp = _deliver_otp(signup_row.email, otp, signup_row.tenant_name)
        signup_row.last_delivery = delivery
        signup_row.delivery_error = None
        db.commit()
        db.refresh(signup_row)
        _emit_invitation_audit(
            signup_row,
            "InviteDeliverySucceeded",
            "delivery_succeeded",
            request_id,
            200,
        )
        return OnboardingResendResponse(
            signup_id=signup_row.id,
            email=signup_row.email,
            expires_at=signup_row.expires_at,
            delivery=delivery,
            next_resend_at=_next_resend_at(signup_row.sent_at),
            dev_otp=dev_otp,
        )
    except EmailDeliveryError as exc:
        db.rollback()
        if "signup_row" in locals() and signup_row:
            _emit_invitation_audit(
                signup_row,
                "InviteDeliveryFailed",
                "delivery_failed",
                request_id,
                503,
            )
        raise HTTPException(status_code=503, detail="Invitation delivery is temporarily unavailable") from exc
    except HTTPException:
        db.rollback()
        raise
    finally:
        db.close()


@router.post("/verify", response_model=OnboardingVerifyResponse)
def verify(payload: OnboardingVerifyRequest, request: Request):
    now = datetime.now(timezone.utc)
    request_id = request.headers.get("x-request-id", "")
    try:
        validate_legal_acceptance(
            terms_accepted=payload.terms_accepted,
            terms_version=payload.terms_version,
            privacy_notice_acknowledged=payload.privacy_notice_acknowledged,
            privacy_notice_version=payload.privacy_notice_version,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    gateway_url = os.getenv("PUBLIC_GATEWAY_URL") or os.getenv("NEXT_PUBLIC_GATEWAY_URL") or "http://localhost:18080"
    ip_hash = _rate_limit_hash(_client_ip(request))
    _enforce_onboarding_rate_limit(
        f"onboarding:verify:ip:{ip_hash}:{now.strftime('%Y%m%d%H')}",
        ONBOARDING_VERIFY_IP_PER_HOUR,
        3700,
        "Too many verification attempts from this network. Try again later.",
    )

    db = OwnerSessionLocal()
    try:
        try:
            validate_password(payload.password)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        preauth = db.execute(
            text(
                """
                SELECT outcome, tenant_id, email, tenant_name, invited_role
                  FROM authn.consume_onboarding_invite_for_otp(
                    :signup_id, :otp, :secrets, :max_attempts, :terms_version,
                    :privacy_version
                  )
                """
            ),
            {
                "signup_id": str(payload.signup_id),
                "otp": payload.otp,
                "secrets": list(get_session_key_ring()[1].values()),
                "max_attempts": OTP_MAX_ATTEMPTS,
                "terms_version": payload.terms_version,
                "privacy_version": payload.privacy_notice_version,
            },
        ).one()
        if preauth.outcome != "valid":
            db.commit()
            signup_row = (
                db.query(OnboardingEmailOTP)
                .filter(OnboardingEmailOTP.id == payload.signup_id)
                .first()
            )
            reason = {
                "invalid": "invalid_verification_code",
                "expired": "invitation_expired",
                "locked": "attempt_limit_exceeded",
                "tenant_unavailable": "invitation_tenant_unavailable",
                "not_found": "invitation_not_found",
            }.get(preauth.outcome, "invitation_not_pending")
            if preauth.outcome == "expired":
                _emit_invitation_audit(
                    signup_row, "InviteExpired", reason, request_id, 400
                )
            _emit_invitation_audit(
                signup_row, "InviteRedemptionFailed", reason, request_id,
                429 if preauth.outcome == "locked" else 400,
            )
            if preauth.outcome == "locked":
                raise HTTPException(status_code=429, detail=INVALID_INVITATION_DETAIL)
            raise _invalid_invitation()

        signup_row = (
            db.query(OnboardingEmailOTP)
            .filter(OnboardingEmailOTP.id == payload.signup_id)
            .with_for_update()
            .first()
        )
        if not signup_row:
            _emit_invitation_audit(
                None,
                "InviteRedemptionFailed",
                "invitation_not_found",
                request_id,
                400,
            )
            raise _invalid_invitation()
        if not signup_row.terms_accepted_at:
            signup_row.terms_version = payload.terms_version
            signup_row.terms_accepted_at = now
        if not signup_row.privacy_notice_acknowledged_at:
            signup_row.privacy_notice_version = payload.privacy_notice_version
            signup_row.privacy_notice_acknowledged_at = now
        if signup_row.status == "verified":
            _emit_invitation_audit(
                signup_row,
                "InviteRedemptionFailed",
                "invitation_already_redeemed",
                request_id,
                400,
            )
            raise _invalid_invitation()
        if signup_row.status != "pending":
            _emit_invitation_audit(
                signup_row,
                "InviteRedemptionFailed",
                "invitation_not_pending",
                request_id,
                400,
            )
            raise _invalid_invitation()
        expires_at = signup_row.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < now:
            invitation_audit = _invitation_audit_snapshot(signup_row)
            signup_row.status = "expired"
            db.commit()
            _emit_invitation_audit(invitation_audit, "InviteExpired", "invitation_expired", request_id, 400)
            _emit_invitation_audit(
                invitation_audit,
                "InviteRedemptionFailed",
                "invitation_expired",
                request_id,
                400,
            )
            raise _invalid_invitation()
        if signup_row.attempts >= OTP_MAX_ATTEMPTS:
            _emit_invitation_audit(
                signup_row,
                "InviteRedemptionFailed",
                "attempt_limit_exceeded",
                request_id,
                429,
            )
            raise HTTPException(status_code=429, detail=INVALID_INVITATION_DETAIL)

        signup_row.attempts += 1
        if not any(
            hmac.compare_digest(signup_row.otp_hash, _otp_hash(signup_row.email, payload.otp, secret))
            for secret in get_session_key_ring()[1].values()
        ):
            invitation_audit = _invitation_audit_snapshot(signup_row)
            db.commit()
            _emit_invitation_audit(
                invitation_audit,
                "InviteRedemptionFailed",
                "invalid_verification_code",
                request_id,
                400,
            )
            raise _invalid_invitation()

        if getattr(signup_row, "purpose", "signup") == "invite":
            if not signup_row.tenant_id:
                _emit_invitation_audit(
                    signup_row,
                    "InviteRedemptionFailed",
                    "invitation_tenant_unavailable",
                    request_id,
                    400,
                )
                raise _invalid_invitation()
            tenant = db.query(Tenant).filter(Tenant.id == signup_row.tenant_id).first()
            if not tenant or tenant.status != "active":
                _emit_invitation_audit(
                    signup_row,
                    "InviteRedemptionFailed",
                    "invitation_tenant_unavailable",
                    request_id,
                    400,
                )
                raise _invalid_invitation()
            if db.query(User).filter(
                User.tenant_id == tenant.id,
                User.email == signup_row.email,
                User.is_active == True,
            ).first():
                _emit_invitation_audit(
                    signup_row,
                    "InviteRedemptionFailed",
                    "invitation_cannot_be_redeemed",
                    request_id,
                    400,
                )
                raise _invalid_invitation()

            invited_role = signup_row.invited_role or "viewer"
            user = db.query(User).filter(
                User.tenant_id == tenant.id,
                User.email == signup_row.email,
                User.is_active == False,
            ).first()
            if user:
                user.role = invited_role
                user.is_active = True
                user.mfa_enabled = False
                user.password_hash = hash_password(payload.password)
            else:
                user = User(
                    tenant_id=tenant.id,
                    email=signup_row.email,
                    password_hash=hash_password(payload.password),
                    role=invited_role,
                    mfa_enabled=False,
                    is_active=True,
                )
                db.add(user)
            db.flush()

            raw_api_key = _generate_gateway_key()
            scopes = _scopes_for_role(invited_role)
            api_key = APIKey(
                tenant_id=tenant.id,
                key_hash=_api_key_hash(raw_api_key),
                name=f"Console Access - {signup_row.email}",
                description="Issued during AuthClaw Lite tenant invite verification",
                scopes=scopes,
                is_active=True,
                expires_at=now + timedelta(days=90),
                created_by=user.id,
            )
            db.add(api_key)
            db.flush()
            session_token = _generate_session_token()
            invitation_audit = _invitation_audit_snapshot(signup_row)
            tenant_id = tenant.id
            tenant_name = tenant.name
            user_id = user.id
            user_email = user.email
            user_role = user.role
            db.execute(
                text(
                    """
                    SELECT authn.create_session(
                        :token_hash, :tenant_id, :user_id, 'onboarding',
                        :expires_at, CAST(:metadata AS jsonb)
                    )
                    """
                ),
                {
                    "token_hash": _api_key_hash(session_token),
                    "tenant_id": str(tenant_id),
                    "user_id": str(user_id),
                    "expires_at": now + timedelta(hours=24),
                    "metadata": json.dumps({"request_id": request_id}),
                },
            )
            signup_row.status = "verified"
            signup_row.verified_at = now
            signup_row.api_key_id = api_key.id
            status_row = db.query(OnboardingStatus).filter(OnboardingStatus.tenant_id == tenant_id).first()
            if not status_row:
                status_row = OnboardingStatus(
                    tenant_id=tenant_id,
                    user_id=user_id,
                    signup_id=signup_row.id,
                    email_verified=True,
                    tenant_created=True,
                    api_key_issued=True,
                    route_created=True,
                    policy_created=True,
                    current_step="connect_provider",
                )
                db.add(status_row)
                db.flush()
            checklist = _checklist(status_row)
            powershell, curl = _snippets(raw_api_key, gateway_url)
            db.commit()
            _emit_invitation_audit(invitation_audit, "InviteRedeemed", "invitation_redeemed", request_id, 200)
            return OnboardingVerifyResponse(
                tenant_id=tenant_id,
                tenant_name=tenant_name,
                user_id=user_id,
                email=user_email,
                role=user_role,
                scopes=scopes,
                api_key=raw_api_key,
                session_token=session_token,
                gateway_url=gateway_url,
                provider=DEFAULT_PROVIDER,
                model=DEFAULT_MODEL,
                checklist=checklist,
                powershell_snippet=powershell,
                curl_snippet=curl,
            )

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="An approved tenant invitation is required",
        )
    except IntegrityError as exc:
        db.rollback()
        _emit_invitation_audit(
            signup_row if "signup_row" in locals() else None,
            "InviteRedemptionFailed",
            "invitation_transaction_conflict",
            request_id,
            400,
        )
        raise _invalid_invitation() from exc
    except HTTPException:
        db.rollback()
        raise
    finally:
        db.close()


@router.get("/status", response_model=OnboardingChecklistResponse, dependencies=[require_scopes(["read"])])
def onboarding_status(request: Request, db: Session = Depends(get_tenant_db)):
    tenant_id = request.state.tenant_id
    status_row = db.query(OnboardingStatus).filter(OnboardingStatus.tenant_id == tenant_id).first()
    if not status_row:
        raise HTTPException(status_code=404, detail="Onboarding status not found")
    return _checklist(status_row)

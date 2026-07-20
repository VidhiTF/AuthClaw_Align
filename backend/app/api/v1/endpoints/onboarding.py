from __future__ import annotations

import hashlib
import logging
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import redis
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.core.auth import get_tenant_db, hash_key, require_scopes
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


def _invalid_invitation() -> HTTPException:
    return HTTPException(status_code=400, detail=INVALID_INVITATION_DETAIL)


def _normalize_database_url(url: str) -> str:
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


def _owner_sessionmaker():
    database_url = _normalize_database_url(
        os.getenv("OWNER_DATABASE_URL")
        or os.getenv("DATABASE_URL", "postgresql+psycopg://authclaw:authclaw@localhost:5432/authclaw")
    )
    engine = create_engine(database_url, pool_pre_ping=True)
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)


OwnerSessionLocal = _owner_sessionmaker()


def _otp_hash(email: str, otp: str) -> str:
    secret = os.getenv("SESSION_SECRET") or os.getenv("JWT_SECRET")
    if not secret:
        if os.getenv("AUTHCLAW_ENV", "").lower() == "production":
            raise RuntimeError("SESSION_SECRET or JWT_SECRET is required in production")
        secret = "authclaw-lite-dev-secret"
    material = f"{email.strip().lower()}:{otp}:{secret}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _api_key_hash(raw_key: str) -> str:
    return hash_key(raw_key)


def _rate_limit_hash(value: str) -> str:
    return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()[:24]


def _client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def _get_redis() -> redis.Redis:
    global _redis_client
    if _redis_client is None:
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
        if redis_url and not redis_url.startswith(("redis://", "rediss://")):
            redis_url = f"redis://{redis_url}"
        _redis_client = redis.from_url(redis_url, decode_responses=True)
    return _redis_client


def _enforce_onboarding_rate_limit(key: str, limit: int, window_seconds: int, message: str) -> None:
    if limit <= 0:
        return
    try:
        client = _get_redis()
        count = client.incr(key)
        if count == 1:
            client.expire(key, window_seconds)
    except redis.RedisError as exc:
        logger.warning("Rate limiter unavailable")
        if os.getenv("AUTHCLAW_ENV", "").lower() == "production":
            raise HTTPException(status_code=503, detail="Rate limiter unavailable. Request blocked for safety.") from exc
        return
    if count > limit:
        raise HTTPException(status_code=429, detail=message)


def _generate_otp() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def _generate_gateway_key() -> str:
    return "acl_live_" + secrets.token_urlsafe(24)


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

        next_resend_at = _next_resend_at(signup_row.sent_at)
        if next_resend_at > now:
            raise HTTPException(status_code=429, detail=f"Please wait until {next_resend_at.isoformat()} before resending")
        if signup_row.resend_count >= OTP_MAX_RESENDS:
            raise HTTPException(status_code=429, detail="Too many verification code resends")

        signup_row.otp_hash = _otp_hash(signup_row.email, otp)
        signup_row.expires_at = expires_at
        signup_row.sent_at = now
        signup_row.resend_count += 1
        signup_row.attempts = 0

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
            signup_row.status = "expired"
            db.commit()
            _emit_invitation_audit(signup_row, "InviteExpired", "invitation_expired", request_id, 400)
            _emit_invitation_audit(
                signup_row,
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
        if signup_row.otp_hash != _otp_hash(signup_row.email, payload.otp):
            db.commit()
            _emit_invitation_audit(
                signup_row,
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

            db.execute(text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"), {"tenant_id": str(tenant.id)})
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
            api_key = APIKey(
                tenant_id=tenant.id,
                key_hash=_api_key_hash(raw_api_key),
                name=f"Console Access - {signup_row.email}",
                description="Issued during AuthClaw Lite tenant invite verification",
                scopes=_scopes_for_role(invited_role),
                is_active=True,
                expires_at=now + timedelta(days=90),
                created_by=user.id,
            )
            db.add(api_key)
            signup_row.status = "verified"
            signup_row.verified_at = now
            signup_row.api_key_id = api_key.id
            db.commit()
            _emit_invitation_audit(signup_row, "InviteRedeemed", "invitation_redeemed", request_id, 200)

            status_row = db.query(OnboardingStatus).filter(OnboardingStatus.tenant_id == tenant.id).first()
            if not status_row:
                status_row = OnboardingStatus(
                    tenant_id=tenant.id,
                    user_id=user.id,
                    email_verified=True,
                    tenant_created=True,
                    api_key_issued=True,
                    route_created=True,
                    policy_created=True,
                    current_step="connect_provider",
                )
                db.add(status_row)
                db.commit()
                db.refresh(status_row)

            powershell, curl = _snippets(raw_api_key, gateway_url)
            return OnboardingVerifyResponse(
                tenant_id=tenant.id,
                tenant_name=tenant.name,
                user_id=user.id,
                email=user.email,
                role=user.role,
                api_key=raw_api_key,
                gateway_url=gateway_url,
                provider=DEFAULT_PROVIDER,
                model=DEFAULT_MODEL,
                checklist=_checklist(status_row),
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
        db.execute(text("SELECT set_config('app.current_tenant_id', '', false)"))
        db.close()


@router.get("/status", response_model=OnboardingChecklistResponse, dependencies=[require_scopes(["read"])])
def onboarding_status(request: Request, db: Session = Depends(get_tenant_db)):
    tenant_id = request.state.tenant_id
    status_row = db.query(OnboardingStatus).filter(OnboardingStatus.tenant_id == tenant_id).first()
    if not status_row:
        raise HTTPException(status_code=404, detail="Onboarding status not found")
    return _checklist(status_row)

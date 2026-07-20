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
    GatewayConfig,
    OnboardingEmailOTP,
    OnboardingStatus,
    Policy,
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
from app.services.legal_acceptance import validate_legal_acceptance

router = APIRouter()
logger = logging.getLogger(__name__)

DEFAULT_PROVIDER = "gemini"
DEFAULT_MODEL = "gemini-2.5-flash-lite"
DEFAULT_ENDPOINT = "https://generativelanguage.googleapis.com"
OTP_TTL_MINUTES = 15
OTP_RESEND_COOLDOWN_SECONDS = 60
OTP_MAX_RESENDS = 3
OTP_MAX_ATTEMPTS = 5
ONBOARDING_SIGNUP_EMAIL_PER_HOUR = int(os.getenv("ONBOARDING_SIGNUP_EMAIL_PER_HOUR", "3"))
ONBOARDING_SIGNUP_IP_PER_DAY = int(os.getenv("ONBOARDING_SIGNUP_IP_PER_DAY", "10"))
ONBOARDING_VERIFY_IP_PER_HOUR = int(os.getenv("ONBOARDING_VERIFY_IP_PER_HOUR", "30"))

_redis_client: redis.Redis | None = None

STARTER_POLICY = r'''regex_rules:
  - name: customer_email
    pattern: "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"
    reason: "Email addresses are redacted before model egress."
    severity: medium
    action: redact

  - name: patient_health_data
    pattern: "(?i)\\b(patient|diagnosis|prescription|medical record)\\b"
    reason: "Health context requires human approval before model egress."
    severity: high
    action: require_approval
    hitl_timeout_seconds: 1800

  - name: ssn_block
    pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
    reason: "SSNs are blocked in the Lite starter policy."
    severity: critical
    action: block

model_rules:
  whitelist:
    - gpt-4o-mini
    - gemini-2.5-flash-lite
  blacklist: []

topic_rules: []

rate_limits:
  requests_per_minute: 60
'''


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
    email = payload.email.strip().lower()
    tenant_name = payload.tenant_name.strip()
    now = datetime.now(timezone.utc)
    try:
        validate_legal_acceptance(
            terms_accepted=payload.terms_accepted,
            terms_version=payload.terms_version,
            privacy_notice_acknowledged=payload.privacy_notice_acknowledged,
            privacy_notice_version=payload.privacy_notice_version,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    email_hash = _rate_limit_hash(email)
    ip_hash = _rate_limit_hash(_client_ip(request))
    _enforce_onboarding_rate_limit(
        f"onboarding:signup:email:{email_hash}:{now.strftime('%Y%m%d%H')}",
        ONBOARDING_SIGNUP_EMAIL_PER_HOUR,
        3700,
        "Too many signup codes requested for this email. Try again later.",
    )
    _enforce_onboarding_rate_limit(
        f"onboarding:signup:ip:{ip_hash}:{now.strftime('%Y%m%d')}",
        ONBOARDING_SIGNUP_IP_PER_DAY,
        90000,
        "Too many signup attempts from this network today.",
    )
    otp = _generate_otp()
    expires_at = now + timedelta(minutes=OTP_TTL_MINUTES)

    db = OwnerSessionLocal()
    try:
        existing_user = db.query(User).filter(User.email == email, User.is_active == True).first()
        if existing_user:
            raise HTTPException(status_code=409, detail="An active user already exists for this email")

        existing_tenant = db.query(Tenant).filter(Tenant.name == tenant_name).first()
        if existing_tenant:
            raise HTTPException(status_code=409, detail="Tenant name is already taken")

        signup_row = OnboardingEmailOTP(
            email=email,
            tenant_name=tenant_name,
            otp_hash=_otp_hash(email, otp),
            expires_at=expires_at,
            sent_at=now,
            terms_version=payload.terms_version,
            terms_accepted_at=now,
            privacy_notice_version=payload.privacy_notice_version,
            privacy_notice_acknowledged_at=now,
        )
        db.add(signup_row)

        delivery, dev_otp = _deliver_otp(email, otp, tenant_name)
        signup_row.last_delivery = delivery
        signup_row.delivery_error = None
        db.commit()
        db.refresh(signup_row)
        return OnboardingSignupResponse(
            signup_id=signup_row.id,
            email=email,
            tenant_name=tenant_name,
            expires_at=expires_at,
            delivery=delivery,
            next_resend_at=_next_resend_at(signup_row.sent_at),
            dev_otp=dev_otp,
        )
    except EmailDeliveryError as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except HTTPException:
        db.rollback()
        raise
    finally:
        db.close()


@router.post("/resend", response_model=OnboardingResendResponse)
def resend(payload: OnboardingResendRequest, request: Request):
    now = datetime.now(timezone.utc)
    otp = _generate_otp()
    expires_at = now + timedelta(minutes=OTP_TTL_MINUTES)

    db = OwnerSessionLocal()
    try:
        signup_row = db.query(OnboardingEmailOTP).filter(OnboardingEmailOTP.id == payload.signup_id).first()
        if not signup_row:
            raise HTTPException(status_code=404, detail="Signup request not found")
        if signup_row.status != "pending":
            raise HTTPException(status_code=400, detail="Signup request is not pending")

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
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except HTTPException:
        db.rollback()
        raise
    finally:
        db.close()


@router.post("/verify", response_model=OnboardingVerifyResponse)
def verify(payload: OnboardingVerifyRequest, request: Request):
    now = datetime.now(timezone.utc)
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

        signup_row = db.query(OnboardingEmailOTP).filter(OnboardingEmailOTP.id == payload.signup_id).first()
        if not signup_row:
            raise HTTPException(status_code=404, detail="Signup request not found")
        if not signup_row.terms_accepted_at:
            signup_row.terms_version = payload.terms_version
            signup_row.terms_accepted_at = now
        if not signup_row.privacy_notice_acknowledged_at:
            signup_row.privacy_notice_version = payload.privacy_notice_version
            signup_row.privacy_notice_acknowledged_at = now
        if signup_row.status == "verified":
            raise HTTPException(status_code=409, detail="Signup request already verified")
        if signup_row.status != "pending":
            raise HTTPException(status_code=400, detail="Signup request is not pending")
        expires_at = signup_row.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < now:
            signup_row.status = "expired"
            db.commit()
            raise HTTPException(status_code=400, detail="Verification code expired")
        if signup_row.attempts >= OTP_MAX_ATTEMPTS:
            raise HTTPException(status_code=429, detail="Too many verification attempts")

        signup_row.attempts += 1
        if signup_row.otp_hash != _otp_hash(signup_row.email, payload.otp):
            db.commit()
            raise HTTPException(status_code=400, detail="Invalid verification code")

        if getattr(signup_row, "purpose", "signup") == "invite":
            if not signup_row.tenant_id:
                raise HTTPException(status_code=400, detail="Invite is missing tenant context")
            tenant = db.query(Tenant).filter(Tenant.id == signup_row.tenant_id).first()
            if not tenant or tenant.status != "active":
                raise HTTPException(status_code=400, detail="Invite tenant is not active")
            if db.query(User).filter(
                User.tenant_id == tenant.id,
                User.email == signup_row.email,
                User.is_active == True,
            ).first():
                raise HTTPException(status_code=409, detail="An active user already exists for this tenant")

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

        if db.query(User).filter(User.email == signup_row.email, User.is_active == True).first():
            raise HTTPException(status_code=409, detail="An active user already exists for this email")
        if db.query(Tenant).filter(Tenant.name == signup_row.tenant_name).first():
            raise HTTPException(status_code=409, detail="Tenant name is already taken")

        tenant = Tenant(name=signup_row.tenant_name, tier="starter", status="active")
        db.add(tenant)
        db.flush()
        db.execute(text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"), {"tenant_id": str(tenant.id)})

        user = User(
            tenant_id=tenant.id,
            email=signup_row.email,
            password_hash=hash_password(payload.password),
            role="owner",
            mfa_enabled=False,
            is_active=True,
        )
        db.add(user)
        db.flush()

        raw_api_key = _generate_gateway_key()
        api_key = APIKey(
            tenant_id=tenant.id,
            key_hash=_api_key_hash(raw_api_key),
            name="Default Gateway Key",
            description="Issued during AuthClaw Lite onboarding",
            scopes=["admin", "read", "write"],
            is_active=True,
            expires_at=now + timedelta(days=90),
            created_by=user.id,
        )
        db.add(api_key)

        gateway = GatewayConfig(
            tenant_id=tenant.id,
            name="Default Gemini Route",
            provider=DEFAULT_PROVIDER,
            endpoint=DEFAULT_ENDPOINT,
            model_whitelist=[DEFAULT_MODEL],
            redaction_strategy="mask",
            redaction_token_retention_days=90,
            is_active=True,
        )
        db.add(gateway)

        policy = Policy(
            tenant_id=tenant.id,
            name="AuthClaw Lite Starter Policy",
            description="Starter policy with redact, HITL, and block actions.",
            policy_yaml=STARTER_POLICY,
            version=1,
            is_active=True,
            created_by=user.id,
        )
        db.add(policy)
        db.flush()

        status_row = OnboardingStatus(
            tenant_id=tenant.id,
            user_id=user.id,
            signup_id=signup_row.id,
            email_verified=True,
            tenant_created=True,
            api_key_issued=True,
            provider_key_saved=False,
            route_created=True,
            policy_created=True,
            current_step="connect_provider",
        )
        db.add(status_row)

        signup_row.status = "verified"
        signup_row.verified_at = now
        signup_row.tenant_id = tenant.id
        signup_row.api_key_id = api_key.id
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
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Tenant or user already exists") from exc
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

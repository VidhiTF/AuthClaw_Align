from __future__ import annotations

import json
import logging
import secrets
import jwt
import requests
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.v1.endpoints.onboarding import (
    OTP_MAX_ATTEMPTS,
    OTP_TTL_MINUTES,
    OwnerSessionLocal,
    _deliver_otp,
    _generate_otp,
    _next_resend_at,
    _otp_hash,
    _scopes_for_role,
)
from app.core.passwords import hash_password, validate_password, verify_password
from app.core.auth import get_tenant_db, hash_key as _api_key_hash, require_roles, require_scopes
from app.db.models import APIKey, OnboardingEmailOTP, Tenant, TenantOIDCConfig, User
from app.services.email_service import EmailDeliveryError

from app.core.oidc import oidc_config
from app.services import event_backbone, oidc_sso

router = APIRouter()
logger = logging.getLogger("api.auth")
_oidc_kafka_producer = None


def _emit_oidc_audit(
    *,
    tenant_id: str,
    actor_id: str = "",
    action: str,
    reason: str,
    request_id: str = "",
    response_status: int,
    provider: str = "oidc",
) -> None:
    global _oidc_kafka_producer
    event = event_backbone.audit_event(
        event_type="authentication",
        tenant_id=tenant_id,
        subject_id=actor_id or tenant_id,
        identity_action=action,
        action=f"auth:{action}",
        reason=reason,
        provider=provider,
        request_id=request_id,
        trace=[],
    )
    event["actor_id"] = actor_id
    event["result"] = "success" if response_status < 400 else "failure"
    event["response_status"] = response_status
    event_backbone.increment_metric(f"oidc_{action}_total")
    if _oidc_kafka_producer is None:
        try:
            _oidc_kafka_producer = event_backbone.make_kafka_producer()
        except Exception:
            logger.warning("OIDC audit Kafka producer unavailable")
    if exc := event_backbone.publish_audit_event(_oidc_kafka_producer, tenant_id, event):
        logger.warning("Failed to publish OIDC audit event: action=%s", action)
    logger.info("[OIDC_AUDIT] %s", json.dumps(event, sort_keys=True))


def _oidc_authentication_reason(exc: Exception) -> str:
    if isinstance(exc, jwt.InvalidIssuerError):
        return "issuer_validation_failed"
    if isinstance(exc, jwt.InvalidAudienceError):
        return "audience_validation_failed"
    if isinstance(exc, (jwt.InvalidSignatureError, jwt.PyJWKClientError)):
        return "signature_validation_failed"
    if isinstance(exc, oidc_sso.OIDCAuthenticationError):
        return exc.reason_code
    return "invalid_token"


class PasswordLoginRequest(BaseModel):
    email: EmailStr
    password: str
    tenant_name: str | None = None


class PasswordLoginResponse(BaseModel):
    user_id: UUID
    tenant_id: UUID
    tenant_name: str
    email: EmailStr
    role: str
    scopes: list[str]
    api_key: str


class CurrentUserResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    email: EmailStr
    role: str
    roles: list[str]
    mfa_enabled: bool
    is_active: bool


class PasswordResetRequest(BaseModel):
    email: EmailStr
    tenant_name: str | None = None


class PasswordResetRequestResponse(BaseModel):
    accepted: bool = True
    signup_id: UUID | None = None
    email: EmailStr
    delivery: str | None = None
    next_resend_at: datetime | None = None


class PasswordResetConfirmRequest(BaseModel):
    signup_id: UUID
    otp: str = Field(..., min_length=6, max_length=6)
    password: str = Field(..., min_length=12, max_length=256)


class PasswordResetConfirmResponse(BaseModel):
    success: bool = True


class OIDCStartResponse(BaseModel):
    enabled: bool
    authorization_url: str = ""
    issuer: str = ""
    client_id: str = ""
    redirect_uri: str = ""


class OIDCCallbackRequest(BaseModel):
    code: str
    state: str
    nonce: str
    tenant_name: str | None = None
    redirect_uri: str


class OIDCAdminConfigRequest(BaseModel):
    enabled: bool = False
    issuer: str
    client_id: str
    client_secret: str | None = None
    clear_client_secret: bool = False
    redirect_uri: str
    scopes: list[str] = Field(default_factory=lambda: ["openid", "email", "profile"])
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    jwks_uri: str | None = None
    email_claim: str = "email"
    groups_claim: str = "groups"
    tenant_claim: str = "tenant_id"
    tenant_claim_value: str = ""
    role_mapping: dict[str, str] = Field(default_factory=dict)
    default_role: str = "viewer"
    auto_provision: bool = False
    require_mfa: bool = True
    accepted_amr: list[str] = Field(default_factory=lambda: ["mfa"])
    accepted_acr: list[str] = Field(default_factory=list)
    max_auth_age_seconds: int = Field(default=43200, ge=0)


def _generate_console_key() -> str:
    return "acl_console_" + secrets.token_urlsafe(24)


def _active_users_for_email(db, email: str, tenant_name: str | None = None):
    rows = (
        db.query(User, Tenant)
        .join(Tenant, Tenant.id == User.tenant_id)
        .filter(User.email == email, User.is_active == True, Tenant.status == "active")
        .all()
    )
    if tenant_name:
        clean_name = tenant_name.strip().lower()
        rows = [(user, tenant) for user, tenant in rows if tenant.name.lower() == clean_name]
    return rows


@router.get("/oidc/config")
def get_oidc_config(tenant_name: str | None = None):
    """Return public OIDC/SSO metadata for console login discovery."""
    db = OwnerSessionLocal()
    try:
        _, tenant_config = oidc_sso.public_config(db, tenant_name)
    finally:
        db.close()
    config = tenant_config or oidc_config()
    return {
        "enabled": config["enabled"],
        "issuer": config["issuer"],
        "client_id": config["client_id"],
        "scopes": config["scopes"],
        "authorization_endpoint": config["authorization_endpoint"],
        "authorization_url": config.get("authorization_url", ""),
    }


@router.get("/oidc/start", response_model=OIDCStartResponse)
def start_oidc_login(
    state: str = Query(..., min_length=24),
    nonce: str = Query(..., min_length=24),
    tenant_name: str | None = None,
):
    db = OwnerSessionLocal()
    try:
        _, config = oidc_sso.public_config(db, tenant_name)
        if not config:
            return OIDCStartResponse(enabled=False)
        return OIDCStartResponse(
            enabled=True,
            authorization_url=oidc_sso.authorization_url(config, state, nonce),
            issuer=config["issuer"],
            client_id=config["client_id"],
            redirect_uri=config["redirect_uri"],
        )
    finally:
        db.close()


def _oidc_callback_config(db, tenant_name: str | None):
    tenant, public = oidc_sso.public_config(db, tenant_name)
    if not public:
        raise HTTPException(status_code=404, detail="OIDC SSO is not configured")
    if public.get("source") == "tenant":
        if not tenant:
            raise HTTPException(status_code=400, detail="Tenant name is required for SSO")
        config = db.query(TenantOIDCConfig).filter(
            TenantOIDCConfig.tenant_id == tenant.id,
            TenantOIDCConfig.status == "active",
        ).first()
        if not config:
            raise HTTPException(status_code=404, detail="OIDC SSO is not active for this tenant")
        return tenant, config
    if not tenant:
        raise HTTPException(status_code=400, detail="Tenant name is required for environment OIDC mapping")
    return tenant, public


@router.post("/oidc/callback", response_model=PasswordLoginResponse)
def oidc_callback(payload: OIDCCallbackRequest, request: Request):
    db = OwnerSessionLocal()
    tenant = None
    request_id = request.headers.get("x-request-id", "")
    try:
        tenant, config = _oidc_callback_config(db, payload.tenant_name)
        configured_redirect_uri = config["redirect_uri"] if isinstance(config, dict) else config.redirect_uri
        if payload.redirect_uri != configured_redirect_uri:
            _emit_oidc_audit(
                tenant_id=str(tenant.id),
                action="redirect_uri_validation_failed",
                reason="redirect_uri_validation_failed",
                request_id=request_id,
                response_status=400,
            )
            raise HTTPException(status_code=400, detail="Invalid OIDC redirect URI")
        tokens = oidc_sso.exchange_code(config, payload.code, payload.redirect_uri)
        id_token = tokens.get("id_token")
        if not id_token:
            _emit_oidc_audit(
                tenant_id=str(tenant.id),
                action="invalid_token",
                reason="invalid_token",
                request_id=request_id,
                response_status=400,
            )
            raise HTTPException(status_code=400, detail="OIDC token response did not include id_token")
        claims = oidc_sso.validate_id_token(config, id_token, payload.nonce)
        db.execute(text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"), {"tenant_id": str(tenant.id)})
        user, role = oidc_sso.map_user(db, tenant, config, claims)
        raw_key, scopes = oidc_sso.issue_console_key(db, tenant, user, user.email, role, "OIDC")
        db.commit()
        _emit_oidc_audit(
            tenant_id=str(tenant.id),
            actor_id=str(user.id),
            action="oidc_login_succeeded",
            reason="success",
            request_id=request_id,
            response_status=200,
        )
        return PasswordLoginResponse(
            user_id=user.id,
            tenant_id=tenant.id,
            tenant_name=tenant.name,
            email=user.email,
            role=role,
            scopes=scopes,
            api_key=raw_key,
        )
    except (oidc_sso.OIDCAuthorizationError, PermissionError) as exc:
        db.rollback()
        reason = exc.reason_code if isinstance(exc, oidc_sso.OIDCAuthorizationError) else "authorization_failed"
        if tenant:
            _emit_oidc_audit(
                tenant_id=str(tenant.id),
                action=reason,
                reason=reason,
                request_id=request_id,
                response_status=403,
            )
        raise HTTPException(status_code=403, detail="OIDC authorization failed") from exc
    except (oidc_sso.OIDCAuthenticationError, jwt.PyJWTError, jwt.PyJWKClientError, requests.HTTPError) as exc:
        db.rollback()
        if tenant:
            reason = _oidc_authentication_reason(exc)
            _emit_oidc_audit(
                tenant_id=str(tenant.id),
                action=reason,
                reason=reason,
                request_id=request_id,
                response_status=401,
            )
        raise HTTPException(status_code=401, detail="OIDC authentication failed") from exc
    except (ValueError, TypeError) as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except requests.RequestException as exc:
        db.rollback()
        raise HTTPException(status_code=502, detail="OIDC provider request failed") from exc
    except HTTPException:
        db.rollback()
        raise
    finally:
        try:
            db.execute(text("SELECT set_config('app.current_tenant_id', '', false)"))
        except Exception:
            pass
        db.close()


@router.get("/oidc/admin-config", dependencies=[require_roles(["owner", "admin"]), require_scopes(["read"])])
def get_oidc_admin_config(request: Request, db: Session = Depends(get_tenant_db)):
    config = db.query(TenantOIDCConfig).filter(TenantOIDCConfig.tenant_id == request.state.tenant_id).first()
    return oidc_sso.serialize_config(config)


@router.put("/oidc/admin-config", dependencies=[require_roles(["owner", "admin"]), require_scopes(["write"])])
def save_oidc_admin_config(payload: OIDCAdminConfigRequest, request: Request, db: Session = Depends(get_tenant_db)):
    try:
        config = oidc_sso.upsert_config(db, request.state.tenant_id, request.state.user_id, payload.model_dump())
        return oidc_sso.serialize_config(config)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/oidc/admin-config/test", dependencies=[require_roles(["owner", "admin"]), require_scopes(["write"])])
def test_oidc_admin_config(request: Request, db: Session = Depends(get_tenant_db)):
    config = db.query(TenantOIDCConfig).filter(TenantOIDCConfig.tenant_id == request.state.tenant_id).first()
    if not config:
        raise HTTPException(status_code=404, detail="OIDC SSO is not configured")
    return oidc_sso.test_config(db, config)


@router.post("/login", response_model=PasswordLoginResponse)
def password_login(payload: PasswordLoginRequest):
    email = payload.email.strip().lower()
    db = OwnerSessionLocal()
    try:
        all_users = _active_users_for_email(db, email)
        users = _active_users_for_email(db, email, payload.tenant_name)

        matches = [(user, tenant) for user, tenant in users if verify_password(payload.password, user.password_hash)]
        if not matches:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
        if len(matches) > 1:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email belongs to multiple tenants. Enter tenant name.")

        user, tenant = matches[0]
        db.execute(text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"), {"tenant_id": str(tenant.id)})
        if len(all_users) == 1 and user.role != "owner":
            user.role = "owner"
        role = user.role or "viewer"
        scopes = _scopes_for_role(role)
        raw_key = _generate_console_key()
        now = datetime.now(timezone.utc)
        api_key = APIKey(
            tenant_id=tenant.id,
            key_hash=_api_key_hash(raw_key),
            name=f"Console Session - {email}",
            description="Short-lived key issued after password login",
            scopes=scopes,
            is_active=True,
            expires_at=now + timedelta(hours=24),
            created_by=user.id,
        )
        user.last_login = now
        db.add(api_key)
        db.commit()
        _emit_oidc_audit(
            tenant_id=str(tenant.id),
            actor_id=str(user.id),
            action="password_login_succeeded",
            reason="success",
            response_status=200,
            provider="password",
        )

        return PasswordLoginResponse(
            user_id=user.id,
            tenant_id=tenant.id,
            tenant_name=tenant.name,
            email=user.email,
            role=role,
            scopes=scopes,
            api_key=raw_key,
        )
    except HTTPException:
        db.rollback()
        raise
    finally:
        try:
            db.execute(text("SELECT set_config('app.current_tenant_id', '', false)"))
        except Exception:
            pass
        db.close()


@router.get("/me", response_model=CurrentUserResponse)
def current_user(request: Request, db: Session = Depends(get_tenant_db)):
    """Return the API-key principal in the shape required by the operator console."""
    user = (
        db.query(User)
        .filter(
            User.id == request.state.user_id,
            User.tenant_id == request.state.tenant_id,
        )
        .first()
    )
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    role = user.role or "viewer"
    return CurrentUserResponse(
        id=user.id,
        tenant_id=user.tenant_id,
        email=user.email,
        role=role,
        roles=[role],
        mfa_enabled=bool(user.mfa_enabled),
        is_active=bool(user.is_active),
    )


@router.post("/password-reset/request", response_model=PasswordResetRequestResponse, status_code=status.HTTP_202_ACCEPTED)
def request_password_reset(payload: PasswordResetRequest):
    email = payload.email.strip().lower()
    now = datetime.now(timezone.utc)
    db = OwnerSessionLocal()
    try:
        users = _active_users_for_email(db, email, payload.tenant_name)
        if len(users) > 1:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email belongs to multiple tenants. Enter tenant name.")
        if not users:
            return PasswordResetRequestResponse(email=email)

        _, tenant = users[0]
        otp = _generate_otp()
        reset_row = OnboardingEmailOTP(
            email=email,
            tenant_name=tenant.name,
            otp_hash=_otp_hash(email, otp),
            status="pending",
            expires_at=now + timedelta(minutes=OTP_TTL_MINUTES),
            sent_at=now,
            purpose="password_reset",
            tenant_id=tenant.id,
        )
        db.add(reset_row)
        db.flush()
        delivery, _ = _deliver_otp(email, otp, tenant.name, purpose="password reset")
        reset_row.last_delivery = delivery
        reset_row.delivery_error = None
        db.commit()
        db.refresh(reset_row)
        return PasswordResetRequestResponse(
            signup_id=reset_row.id,
            email=email,
            delivery=delivery,
            next_resend_at=_next_resend_at(reset_row.sent_at),
        )
    except EmailDeliveryError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    except HTTPException:
        db.rollback()
        raise
    finally:
        db.close()


@router.post("/password-reset/confirm", response_model=PasswordResetConfirmResponse)
def confirm_password_reset(payload: PasswordResetConfirmRequest):
    now = datetime.now(timezone.utc)
    db = OwnerSessionLocal()
    try:
        try:
            validate_password(payload.password)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        reset_row = db.query(OnboardingEmailOTP).filter(OnboardingEmailOTP.id == payload.signup_id).first()
        if not reset_row or reset_row.purpose != "password_reset":
            raise HTTPException(status_code=404, detail="Password reset request not found")
        if reset_row.status != "pending":
            raise HTTPException(status_code=400, detail="Password reset request is not pending")
        expires_at = reset_row.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < now:
            reset_row.status = "expired"
            db.commit()
            raise HTTPException(status_code=400, detail="Password reset code expired")
        if reset_row.attempts >= OTP_MAX_ATTEMPTS:
            raise HTTPException(status_code=429, detail="Too many verification attempts")

        reset_row.attempts += 1
        if reset_row.otp_hash != _otp_hash(reset_row.email, payload.otp):
            db.commit()
            raise HTTPException(status_code=400, detail="Invalid verification code")
        if not reset_row.tenant_id:
            raise HTTPException(status_code=400, detail="Password reset is missing tenant context")

        db.execute(text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"), {"tenant_id": str(reset_row.tenant_id)})
        user = db.query(User).filter(
            User.tenant_id == reset_row.tenant_id,
            User.email == reset_row.email,
            User.is_active == True,
        ).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user.password_hash = hash_password(payload.password)
        reset_row.status = "verified"
        reset_row.verified_at = now
        db.query(APIKey).filter(
            APIKey.tenant_id == reset_row.tenant_id,
            APIKey.created_by == user.id,
            APIKey.name.like("Console Session - %"),
            APIKey.revoked_at.is_(None),
        ).update({"is_active": False, "revoked_at": now}, synchronize_session=False)
        db.commit()
        return PasswordResetConfirmResponse()
    except HTTPException:
        db.rollback()
        raise
    finally:
        try:
            db.execute(text("SELECT set_config('app.current_tenant_id', '', false)"))
        except Exception:
            pass
        db.close()

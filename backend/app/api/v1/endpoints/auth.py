from __future__ import annotations

import json
import logging
import os
import secrets
import jwt
import requests
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.dependencies import get_db
from app.db.session import PlatformSessionLocal
from app.api.v1.endpoints.onboarding import (
    OTP_MAX_ATTEMPTS,
    OTP_TTL_MINUTES,
    OwnerSessionLocal,
    _deliver_otp,
    _enforce_onboarding_rate_limit,
    _generate_otp,
    _get_redis,
    _next_resend_at,
    _otp_hash,
    _rate_limit_hash,
    _scopes_for_role,
)
from app.core.passwords import hash_password, validate_password, verify_password
from app.core.crypto import get_session_key_ring
from app.core.bff_client_ip import authenticate_bff_client_ip
from app.core.auth import get_tenant_db, hash_key as _api_key_hash, require_roles, require_scopes
from app.db.models import APIKey, OnboardingEmailOTP, Tenant, TenantOIDCConfig, User
from app.services.email_service import EmailDeliveryError

from app.core.oidc import oidc_config
from app.services import event_backbone, oidc_sso, oidc_transactions
from app.services.abuse_controls import verify_mfa_challenge

router = APIRouter()
logger = logging.getLogger("api.auth")
LOGIN_ACCOUNT_ATTEMPTS_PER_15_MINUTES = int(os.getenv("LOGIN_ACCOUNT_ATTEMPTS_PER_15_MINUTES", "10"))
LOGIN_IP_ATTEMPTS_PER_MINUTE = int(os.getenv("LOGIN_IP_ATTEMPTS_PER_MINUTE", "60"))


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
    # Persist through the audit outbox without opening a broker connection on
    # the authentication request path.  The consumer handles Kafka delivery.
    if exc := event_backbone.publish_audit_event(None, tenant_id, event):
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
    email: str
    password: str
    tenant_name: str | None = None


class PasswordLoginResponse(BaseModel):
    user_id: UUID
    tenant_id: UUID | None = None
    tenant_name: str | None = None
    email: str
    role: str
    scopes: list[str]
    session_token: str


def _enforce_password_login_rate_limit(email: str, request: Request) -> None:
    client_ip = request.client.host if request.client else "unknown"
    message = "Too many login attempts. Try again later."
    _enforce_onboarding_rate_limit(
        f"auth:login:ip:{_rate_limit_hash(client_ip)}",
        LOGIN_IP_ATTEMPTS_PER_MINUTE,
        60,
        message,
    )
    _enforce_onboarding_rate_limit(
        f"auth:login:account:{_rate_limit_hash(email)}",
        LOGIN_ACCOUNT_ATTEMPTS_PER_15_MINUTES,
        900,
        message,
    )


class CurrentUserResponse(BaseModel):
    id: UUID
    tenant_id: UUID | None = None
    email: str
    role: str
    platform_role: str
    roles: list[str]
    scopes: list[str]
    mfa_enabled: bool
    is_active: bool


class AgentMFAAssertionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(min_length=6, max_length=64)
    method: str = Field(pattern=r"^POST$")
    path: str = Field(
        min_length=10,
        max_length=300,
        pattern=r"^/(?:approve|execute)/[A-Za-z0-9._:-]+$",
    )
    body_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class AgentMFAAssertionResponse(BaseModel):
    verified_at: int
    operation: str
    body_sha256: str
    assertion_id: str


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


class OIDCTransactionStart(BaseModel):
    model_config = ConfigDict(extra="forbid")
    transaction_id: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    tenant_name: str | None = Field(default=None, max_length=255)


class OIDCTransactionExchange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    transaction_id: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    code: str = Field(min_length=1, max_length=8192)


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


def _generate_session_token() -> str:
    return "acl_session_" + secrets.token_urlsafe(32)


def _active_users_for_email(db, email: str, tenant_name: str | None = None):
    return db.execute(
        text(
            """
            SELECT user_id, tenant_id, tenant_name, email, password_hash,
                   role, platform_role, mfa_enabled
              FROM authn.lookup_password_identities(:email, :tenant_name)
            """
        ),
        {"email": email, "tenant_name": tenant_name},
    ).all()


def _active_platform_admin_for_email(db, email: str):
    return db.execute(
        text(
            """
            SELECT platform_admin_id, email, password_hash, role, is_active
              FROM authn.lookup_platform_password_identity(:email)
            """
        ),
        {"email": email},
    ).first()


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


@router.post("/oidc/start", response_model=OIDCStartResponse, dependencies=[Depends(oidc_transactions.authenticate_bff)])
def start_oidc_login(
    payload: OIDCTransactionStart,
):
    db = OwnerSessionLocal()
    try:
        tenant, config = oidc_sso.public_config(db, payload.tenant_name)
        if not config:
            return OIDCStartResponse(enabled=False)
        if not tenant:
            raise HTTPException(400, "Tenant name is required for SSO")
        nonce = secrets.token_urlsafe(32)
        record = {**oidc_transactions.binding(tenant, config),
                  "tenant_name": tenant.name, "nonce": nonce,
                  "created_at": datetime.now(timezone.utc).timestamp()}
        oidc_transactions.register(_get_redis(), payload.transaction_id, record)
        return OIDCStartResponse(
            enabled=True,
            authorization_url=oidc_sso.authorization_url(config, payload.transaction_id, nonce),
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
        # The authentication lookup already restricts this to active tenant
        # configurations. Before identity establishment, tenant RLS tables
        # cannot be queried directly by the unauthenticated runtime session.
        return tenant, public
    if not tenant:
        raise HTTPException(status_code=400, detail="Tenant name is required for environment OIDC mapping")
    return tenant, public


@router.post("/oidc/callback", response_model=PasswordLoginResponse, dependencies=[Depends(oidc_transactions.authenticate_bff)])
def exchange_oidc_transaction(payload: OIDCTransactionExchange, request: Request):
    record = oidc_transactions.consume(_get_redis(), payload.transaction_id)
    return oidc_callback(OIDCCallbackRequest(
        code=payload.code, state=payload.transaction_id, nonce=record["nonce"],
        tenant_name=record["tenant_name"], redirect_uri=record["redirect_uri"],
    ), request, transaction=record)


def oidc_callback(payload: OIDCCallbackRequest, request: Request, transaction: dict | None = None):
    db = OwnerSessionLocal()
    tenant = None
    request_id = request.headers.get("x-request-id", "")
    try:
        tenant, config = _oidc_callback_config(db, payload.tenant_name)
        if transaction is not None:
            oidc_transactions.validate_binding(transaction, oidc_transactions.binding(tenant, config))
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
        email_claim = config["email_claim"] if isinstance(config, dict) else config.email_claim
        email = str(claims.get(email_claim) or "").strip().lower()
        if not email or "@" not in email:
            raise ValueError("OIDC email claim is invalid")
        claimed_role = oidc_sso.role_from_claims(config, claims)
        session_token = _generate_session_token()
        now = datetime.now(timezone.utc)
        identity = db.execute(
            text(
                """
                SELECT user_id, email, role FROM authn.issue_oidc_session(
                    :tenant_id, :email, :role, :token_hash, :expires_at,
                    CAST(:metadata AS jsonb)
                )
                """
            ),
            {
                "tenant_id": str(tenant.id),
                "email": email,
                "role": claimed_role,
                "token_hash": _api_key_hash(session_token),
                "expires_at": now + timedelta(hours=24),
                "metadata": json.dumps({"request_id": request_id}),
            },
        ).one()
        role = identity.role
        scopes = _scopes_for_role(role)
        db.commit()
        _emit_oidc_audit(
            tenant_id=str(tenant.id),
            actor_id=str(identity.user_id),
            action="oidc_login_succeeded",
            reason="success",
            request_id=request_id,
            response_status=200,
        )
        return PasswordLoginResponse(
            user_id=identity.user_id,
            tenant_id=tenant.id,
            tenant_name=tenant.name,
            email=identity.email,
            role=role,
            scopes=scopes,
            session_token=session_token,
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
        logger.exception("OIDC callback failed")
        raise HTTPException(status_code=400, detail="OIDC authentication failed") from exc
    except requests.RequestException as exc:
        db.rollback()
        raise HTTPException(status_code=502, detail="OIDC provider request failed") from exc
    except HTTPException:
        db.rollback()
        raise
    finally:
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
        logger.exception("OIDC configuration failed")
        raise HTTPException(status_code=400, detail="OIDC authentication failed") from exc


@router.post("/oidc/admin-config/test", dependencies=[require_roles(["owner", "admin"]), require_scopes(["write"])])
def test_oidc_admin_config(request: Request, db: Session = Depends(get_tenant_db)):
    config = db.query(TenantOIDCConfig).filter(TenantOIDCConfig.tenant_id == request.state.tenant_id).first()
    if not config:
        raise HTTPException(status_code=404, detail="OIDC SSO is not configured")
    return oidc_sso.test_config(db, config)


@router.post("/login", response_model=PasswordLoginResponse, dependencies=[Depends(authenticate_bff_client_ip)])
def password_login(payload: PasswordLoginRequest, request: Request):
    email = payload.email.strip().lower()
    _enforce_password_login_rate_limit(email, request)
    db = OwnerSessionLocal()
    try:
        if payload.tenant_name is None:
            platform_identity = _active_platform_admin_for_email(db, email)
            if platform_identity and verify_password(payload.password, platform_identity.password_hash):
                if PlatformSessionLocal is None:
                    raise HTTPException(status_code=503, detail="Platform login is unavailable")
                session_token = _generate_session_token()
                now = datetime.now(timezone.utc)
                with PlatformSessionLocal.begin() as issuer:
                    issuer.execute(
                        text(
                            """
                            SELECT authn.create_platform_session(
                                :token_hash, :platform_admin_id, 'password',
                                :expires_at, CAST(:metadata AS jsonb)
                            )
                            """
                        ),
                        {
                            "token_hash": _api_key_hash(session_token),
                            "platform_admin_id": str(platform_identity.platform_admin_id),
                            "expires_at": now + timedelta(hours=24),
                            "metadata": json.dumps({
                                "ip": request.client.host if request.client else "",
                                "user_agent": request.headers.get("user-agent", "")[:512],
                            }),
                        },
                    )
                return PasswordLoginResponse(
                    user_id=platform_identity.platform_admin_id,
                    tenant_id=None,
                    tenant_name=None,
                    email=platform_identity.email,
                    role="platform_admin",
                    scopes=["platform.admin"],
                    session_token=session_token,
                )

        users = _active_users_for_email(db, email, payload.tenant_name)

        matches = [
            identity for identity in users
            if verify_password(payload.password, identity.password_hash)
        ]
        if not matches:
            for identity in users:
                _emit_oidc_audit(
                    tenant_id=str(identity.tenant_id),
                    actor_id=str(identity.user_id),
                    action="password_login_failed",
                    reason="invalid_credentials",
                    request_id=request.headers.get("x-request-id", ""),
                    response_status=401,
                    provider="password",
                )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
        if len(matches) > 1:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email belongs to multiple tenants. Enter tenant name.")

        identity = matches[0]
        role = identity.role or "viewer"
        scopes = _scopes_for_role(role)
        session_token = _generate_session_token()
        now = datetime.now(timezone.utc)
        db.execute(
            text(
                """
                SELECT authn.create_session(
                    :token_hash, :tenant_id, :user_id, 'password',
                    :expires_at, CAST(:metadata AS jsonb)
                )
                """
            ),
            {
                "token_hash": _api_key_hash(session_token),
                "tenant_id": str(identity.tenant_id),
                "user_id": str(identity.user_id),
                "expires_at": now + timedelta(hours=24),
                "metadata": json.dumps({
                    "ip": request.client.host if request.client else "",
                    "user_agent": request.headers.get("user-agent", "")[:512],
                }),
            },
        )
        db.execute(
            text("UPDATE users SET last_login = :now WHERE id = :user_id"),
            {"now": now, "user_id": str(identity.user_id)},
        )
        db.commit()
        _emit_oidc_audit(
            tenant_id=str(identity.tenant_id),
            actor_id=str(identity.user_id),
            action="password_login_succeeded",
            reason="success",
            response_status=200,
            provider="password",
        )

        return PasswordLoginResponse(
            user_id=identity.user_id,
            tenant_id=identity.tenant_id,
            tenant_name=identity.tenant_name,
            email=identity.email,
            role=role,
            scopes=scopes,
            session_token=session_token,
        )
    except HTTPException:
        db.rollback()
        raise
    finally:
        db.close()


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, db: Session = Depends(get_db)):
    """Revoke the current opaque console session."""
    if request.state.credential_kind == "session":
        db.execute(
            text("SELECT authn.revoke_session(:credential_hash)"),
            {"credential_hash": request.state.credential_hash},
        )
        db.commit()
    if request.state.credential_kind == "platform_session":
        db.execute(
            text("SELECT authn.revoke_platform_session(:credential_hash)"),
            {"credential_hash": request.state.credential_hash},
        )
        db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=CurrentUserResponse)
def current_user(request: Request, db: Session = Depends(get_db)):
    """Return the API-key principal in the shape required by the operator console."""
    if request.state.credential_kind == "platform_session":
        platform_admin = db.execute(
            text(
                """
                SELECT id, email, role, platform_role, scopes, is_active
                  FROM authn.platform_admin_profile(:credential_hash)
                """
            ),
            {"credential_hash": request.state.credential_hash},
        ).first()
        if not platform_admin:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        return CurrentUserResponse(
            id=platform_admin.id,
            tenant_id=None,
            email=platform_admin.email,
            role="platform_admin",
            platform_role=platform_admin.platform_role,
            roles=["platform_admin"],
            scopes=list(platform_admin.scopes or ["platform.admin"]),
            mfa_enabled=False,
            is_active=bool(platform_admin.is_active),
        )

    if request.state.tenant_id is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tenant-scoped credential required")
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
        platform_role=str(user.platform_role),
        roles=[role],
        scopes=list(request.state.scopes),
        mfa_enabled=bool(user.mfa_enabled),
        is_active=bool(user.is_active),
    )


@router.post("/mfa/agent-assertion", response_model=AgentMFAAssertionResponse)
def create_agent_mfa_assertion(
    payload: AgentMFAAssertionRequest,
    request: Request,
    db: Session = Depends(get_tenant_db),
):
    """Verify the control-plane factor before the console signs an agent action."""
    user = db.query(User).filter(
        User.id == request.state.user_id,
        User.tenant_id == request.state.tenant_id,
    ).with_for_update().first()
    if not user or not user.mfa_enabled or not user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MFA enrollment is required for privileged agent actions",
        )
    operation = f"{payload.method} {payload.path}"
    if not verify_mfa_challenge(
        _get_redis(),
        user,
        payload.code,
        tenant_id=str(request.state.tenant_id),
        operation="agent_approval" if payload.path.startswith("/approve/") else "agent_execution",
        request_id=request.headers.get("x-request-id", ""),
    ):
        db.rollback()
        raise HTTPException(status_code=400, detail="Invalid MFA token or backup code")

    verified_at = int(datetime.now(timezone.utc).timestamp())
    assertion_id = secrets.token_hex(16)
    event = event_backbone.audit_event(
        event_type="authentication",
        tenant_id=str(request.state.tenant_id),
        subject_id=str(request.state.user_id),
        identity_action=f"mfa:agent_assertion:{assertion_id}",
        action="mfa:agent_assertion_issued",
        reason=operation,
        provider="control-plane-mfa",
        request_id=request.headers.get("x-request-id", ""),
        actor_id=str(request.state.user_id),
        trace=[],
    )
    event.update({
        "result": "success",
        "response_status": 200,
        "body_sha256": payload.body_sha256,
    })
    if event_backbone.publish_audit_event(
        None, str(request.state.tenant_id), event, db=db
    ):
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MFA assertion could not be recorded",
        )
    db.commit()
    return AgentMFAAssertionResponse(
        verified_at=verified_at,
        operation=operation,
        body_sha256=payload.body_sha256,
        assertion_id=assertion_id,
    )


@router.post("/password-reset/request", response_model=PasswordResetRequestResponse, status_code=status.HTTP_202_ACCEPTED,
             dependencies=[Depends(authenticate_bff_client_ip)])
def request_password_reset(payload: PasswordResetRequest, request: Request):
    email = payload.email.strip().lower()
    message = "Too many password reset requests. Try again later."
    for kind, identity, limit in (("ip", request.client.host if request.client else "unknown", 20),
                                  ("account", email, 5)):
        _enforce_onboarding_rate_limit(
            f"auth:password-reset:{kind}:{_rate_limit_hash(identity)}", limit, 3600, message,
        )
    now = datetime.now(timezone.utc)
    db = OwnerSessionLocal()
    try:
        users = _active_users_for_email(db, email, payload.tenant_name)
        if len(users) > 1:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email belongs to multiple tenants. Enter tenant name.")
        if not users:
            return PasswordResetRequestResponse(email=email)

        identity = users[0]
        otp = _generate_otp()
        signup_id = db.execute(
            text(
                """
                SELECT authn.create_password_reset(
                    :email, :tenant_id, :tenant_name, :otp_hash, :expires_at
                )
                """
            ),
            {
                "email": email,
                "tenant_id": str(identity.tenant_id),
                "tenant_name": identity.tenant_name,
                "otp_hash": _otp_hash(email, otp),
                "expires_at": now + timedelta(minutes=OTP_TTL_MINUTES),
            },
        ).scalar_one()
        delivery, _ = _deliver_otp(
            email, otp, identity.tenant_name, purpose="password reset"
        )
        db.execute(
            text("SELECT authn.set_password_reset_delivery(:id, :delivery, NULL)"),
            {"id": str(signup_id), "delivery": delivery},
        )
        db.commit()
        return PasswordResetRequestResponse(
            signup_id=signup_id,
            email=email,
            delivery=delivery,
            next_resend_at=_next_resend_at(now),
        )
    except EmailDeliveryError as exc:
        db.rollback()
        logger.exception("Password reset delivery failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service is temporarily unavailable",
        ) from exc
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

        outcome = db.execute(
            text(
                """
                SELECT authn.confirm_password_reset(
                    :signup_id, :otp, :secrets, :password_hash, :max_attempts
                )
                """
            ),
            {
                "signup_id": str(payload.signup_id),
                "otp": payload.otp,
                "secrets": list(get_session_key_ring()[1].values()),
                "password_hash": hash_password(payload.password),
                "max_attempts": OTP_MAX_ATTEMPTS,
            },
        ).scalar_one()
        db.commit()
        if outcome == "not_found":
            raise HTTPException(status_code=404, detail="Password reset request not found")
        if outcome == "locked":
            raise HTTPException(status_code=429, detail="Too many verification attempts")
        if outcome == "expired":
            raise HTTPException(status_code=400, detail="Password reset code expired")
        if outcome != "verified":
            raise HTTPException(status_code=400, detail="Invalid verification code")
        return PasswordResetConfirmResponse()
    except HTTPException:
        db.rollback()
        raise
    finally:
        db.close()

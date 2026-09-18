"""Authentication and tenant context middleware / dependencies"""

import hmac
import logging
import os
from dataclasses import dataclass
import time
from typing import Generator, List
import pyotp
from fastapi import Request, Depends, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session, object_session
from app.db.session import SessionLocal, database_auth_context
from app.db.dependencies import get_db, get_score_db
from app.core.crypto import (
    SECRET_ENVELOPE_PREFIX,
    SECRET_ENVELOPE_V2_PREFIX,
    decrypt_secret,
    encrypt_secret,
    get_session_key_ring,
)

logger = logging.getLogger("auth.middleware")


def hash_key(key: str) -> str:
    """Compute a keyed digest of the API key for deterministic lookup."""
    secret = os.getenv("API_KEY_HASH_SECRET")
    if not secret:
        active, session_keys = get_session_key_ring()
        secret = session_keys.get("v1") or session_keys[active]
    if not secret:
        if os.getenv("AUTHCLAW_ENV", "").lower() == "production":
            raise RuntimeError(
                "API_KEY_HASH_SECRET, SESSION_SECRET, or JWT_SECRET is required in production"
            )
        secret = "authclaw-lite-dev-secret"
    return hmac.digest(secret.encode("utf-8"), key.encode("utf-8"), "sha3_256").hex()


def set_mfa_credentials(user, secret: str, backup_codes: list[str]) -> None:
    previous = user.mfa_secret or ""
    if previous.startswith((SECRET_ENVELOPE_PREFIX, SECRET_ENVELOPE_V2_PREFIX)):
        previous = decrypt_secret(previous)
    # Re-encrypting the same credential must not make consumed codes valid again.
    if not hmac.compare_digest(previous.upper(), secret.upper()):
        user.mfa_last_totp_step = None
    user.mfa_secret = encrypt_secret(secret)
    user.mfa_backup_codes = [
        hash_key(f"mfa-backup:{code.lower()}") for code in backup_codes
    ]
    user.mfa_enabled = True


@dataclass(frozen=True)
class MFAVerification:
    verified: bool
    method: str | None = None
    reason: str = "invalid"
    counter: int | None = None


def verify_mfa_code_result(
    user, code: str, *, pending_enrollment: bool = False
) -> MFAVerification:
    """Consume a database-attached factor; the caller owns commit or rollback."""
    from app.db.models import User

    if not isinstance(user, User) or not isinstance(code, str):
        return MFAVerification(False, reason="invalid_identity")
    db = object_session(user)
    state = inspect(user)
    if db is None or not state.persistent:
        return MFAVerification(False, reason="invalid_identity")
    with db.no_autoflush:
        if (
            state.attrs.id.history.has_changes()
            or state.attrs.tenant_id.history.has_changes()
            or user.tenant_id is None
        ):
            return MFAVerification(False, reason="invalid_identity")
        # Refresh credentials and replay state after acquiring the same-tenant lock.
        # Never authorize against a stale identity-map copy or flush local changes first.
        query = db.query(User).filter(
            User.id == state.identity[0], User.tenant_id == user.tenant_id,
            User.is_active.is_(True),
        )
        if not pending_enrollment:
            query = query.filter(User.mfa_enabled.is_(True))
        user = query.populate_existing().with_for_update().first()
    stored_secret = (
        user.mfa_pending_secret if user is not None and pending_enrollment
        else user.mfa_secret if user is not None
        else ""
    ) or ""
    if not stored_secret:
        return MFAVerification(False, reason="not_configured")
    code = code.strip().lower()
    encrypted = stored_secret.startswith(
        (SECRET_ENVELOPE_PREFIX, SECRET_ENVELOPE_V2_PREFIX)
    )
    secret = decrypt_secret(stored_secret) if encrypted else stored_secret
    backup_codes = [] if pending_enrollment else list(user.mfa_backup_codes or [])
    normalized_codes = [
        stored if len(stored) == 64 else hash_key(f"mfa-backup:{stored.lower()}")
        for stored in backup_codes
    ]
    totp = pyotp.TOTP(secret)
    current_step = int(time.time()) // totp.interval
    matched_step = max(
        (step for step in range(max(0, current_step - 1), current_step + 2)
         if code.isascii() and hmac.compare_digest(totp.generate_otp(step), code)),
        default=None,
    )
    if matched_step is not None:
        last_step = (
            user.mfa_pending_last_totp_step
            if pending_enrollment else user.mfa_last_totp_step
        )
        if last_step is not None and matched_step <= last_step:
            return MFAVerification(
                False, method="totp", reason="replay", counter=matched_step
            )
        if pending_enrollment:
            user.mfa_pending_last_totp_step = matched_step
        else:
            user.mfa_last_totp_step = matched_step
        method = "totp"
    else:
        if pending_enrollment:
            return MFAVerification(False)
        candidate = hash_key(f"mfa-backup:{code}")
        remaining_codes = [
            stored for stored in normalized_codes
            if not hmac.compare_digest(candidate, stored)
        ]
        if len(remaining_codes) == len(normalized_codes):
            return MFAVerification(False)
        normalized_codes = remaining_codes
        method = "recovery_code"
    if not encrypted:
        if pending_enrollment:
            user.mfa_pending_secret = encrypt_secret(secret)
        else:
            user.mfa_secret = encrypt_secret(secret)
    if not pending_enrollment:
        user.mfa_backup_codes = normalized_codes
    # Later authorization refreshes must see consumption; success is durable only
    # when the protected action commits, so a rolled-back action can retry safely.
    db.flush()
    return MFAVerification(
        True, method=method, reason="verified",
        counter=matched_step if method == "totp" else None,
    )


def verify_mfa_code(user, code: str) -> bool:
    """Compatibility wrapper for callers that only need a boolean result."""
    return verify_mfa_code_result(user, code).verified


def _normalize_role(role: str | None) -> str:
    if not role:
        return "viewer"
    return str(role).lower()


class AuthMiddleware(BaseHTTPMiddleware):
    """Middleware to validate API keys and inject tenant_id and scopes"""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        canonical_path = path[4:] if path.startswith("/api/v1/") else path

        # Bypass authentication for public routes
        public_paths = {
            "/health",
            "/docs",
            "/openapi.json",
            "/redoc",
            "/v1/onboarding/signup",
            "/v1/onboarding/resend",
            "/v1/onboarding/verify",
            "/v1/auth/oidc/config",
            "/v1/auth/oidc/start",
            "/v1/auth/oidc/callback",
            "/v1/auth/login",
            "/v1/auth/password-reset/request",
            "/v1/auth/password-reset/confirm",
            "/api/public/v1/access-requests",
        }
        public_access_request = (
            request.method == "POST"
            and canonical_path == "/api/public/v1/access-requests"
        )
        public_route = canonical_path in public_paths and not (
            canonical_path == "/api/public/v1/access-requests"
        )
        if (
            request.method == "OPTIONS"
            or public_route
            or public_access_request
            or path.startswith("/static")
            or canonical_path.startswith("/v1/trust-center/public")
        ):
            return await call_next(request)

        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Missing Authorization Header"},
            )

        parts = auth_header.split(" ")
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "detail": "Invalid Authorization Format. Expected: Bearer <key>"
                },
            )

        credential = parts[1]
        credential_hash = hash_key(credential)
        credential_kind = (
            "session" if credential.startswith("acl_session_") else "api_key"
        )
        resolver = (
            "authn.bind_session_context"
            if credential_kind == "session"
            else "authn.bind_api_key_context"
        )

        db = SessionLocal()
        try:
            result = db.execute(
                text(
                    f"SELECT credential_id, tenant_id, scopes, user_id, role, "
                    f"platform_role, user_is_active, tenant_status "
                    f"FROM {resolver}(:credential_hash)"
                ),
                {"credential_hash": credential_hash},
            ).first()
            if not result and credential_kind == "session":
                result = db.execute(
                    text(
                        "SELECT credential_id, tenant_id, scopes, user_id, role, "
                        "platform_role, user_is_active, tenant_status "
                        "FROM authn.bind_platform_session_context(:credential_hash)"
                    ),
                    {"credential_hash": credential_hash},
                ).first()
                if result:
                    credential_kind = "platform_session"

            if not result:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Unauthorized: Invalid or expired credential"},
                )
            if not result.user_is_active:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Unauthorized: User is inactive or not found"},
                )
            tenant_lifecycle_path = canonical_path in {
                "/v1/tenants/current",
                "/v1/tenants/current/status",
            }
            if result.tenant_status != "active" and not tenant_lifecycle_path:
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "Forbidden: Tenant is not active"},
                )

            if credential_kind == "api_key":
                db.execute(
                    text("""
                        UPDATE api_keys
                           SET last_used = NOW(), last_used_ip = :ip,
                               last_used_user_agent = :user_agent,
                               last_used_request_id = :request_id,
                               updated_at = NOW()
                         WHERE id = :credential_id
                        """),
                    {
                        "credential_id": str(result.credential_id),
                        "ip": request.client.host if request.client else "",
                        "user_agent": request.headers.get("user-agent", "")[:512],
                        "request_id": request.headers.get("x-request-id", "")[:255],
                    },
                )
            db.commit()

            # Inject tenant info, scopes, and role into request state.
            request.state.tenant_id = result.tenant_id
            scopes = list(result.scopes or [])
            platform_role = str(result.platform_role).upper()
            request.state.scopes = scopes
            request.state.user_id = result.user_id
            request.state.credential_id = result.credential_id
            request.state.credential_kind = credential_kind
            request.state.credential_hash = credential_hash
            request.state.api_key_id = (
                result.credential_id if credential_kind == "api_key" else None
            )
            request.state.user_role = _normalize_role(result.role)
            request.state.tenant_role = request.state.user_role
            request.state.platform_role = platform_role
            request.state.user_is_active = bool(result.user_is_active)
        except Exception as e:
            db.rollback()
            logger.exception("Authentication middleware failed")
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Authentication failed"},
            )
        finally:
            db.close()

        with database_auth_context(credential_kind, credential_hash):
            return await call_next(request)


def get_tenant_db(
    request: Request, db: Session = Depends(get_db)
) -> Generator[Session, None, None]:
    """Re-bind the vetted credential inside the handler transaction."""
    revalidate_tenant_credential(request, db)
    yield db


def require_interactive_session(request: Request) -> None:
    """Machine credentials must not manage or attest an interactive factor."""
    if getattr(request.state, "credential_kind", None) != "session":
        raise HTTPException(status_code=403, detail="Interactive tenant session required")


def revalidate_tenant_credential(request: Request, db: Session) -> None:
    """Check revocation again after waiting on a credential-owner row lock."""
    kind = getattr(request.state, "credential_kind", None)
    credential_hash = getattr(request.state, "credential_hash", None)
    expected_tenant = getattr(request.state, "tenant_id", None)
    if kind == "platform_session" or expected_tenant is None:
        raise HTTPException(status_code=403, detail="Tenant-scoped credential required")
    if kind not in {"api_key", "session"} or not credential_hash:
        raise HTTPException(status_code=401, detail="Authentication context missing")
    resolver = (
        "authn.bind_session_context"
        if kind == "session"
        else "authn.bind_api_key_context"
    )
    bound = db.execute(
        text(f"SELECT tenant_id, user_id FROM {resolver}(:credential_hash)"),
        {"credential_hash": credential_hash},
    ).first()
    if (not bound or str(bound.tenant_id) != str(expected_tenant)
            or str(bound.user_id) != str(getattr(request.state, "user_id", None))):
        db.rollback()
        raise HTTPException(status_code=401, detail="Authentication context expired")
    # Retain only the already-validated request credential for same-request
    # transactions that must be re-bound after a commit (for example, audit
    # appends).  This is cleared with the request-scoped SQLAlchemy session.
    db.info["authclaw_database_auth_context"] = (kind, credential_hash)


def get_tenant_score_db(request: Request, db: Session = Depends(get_score_db)) -> Generator[Session, None, None]:
    """Authenticate inside the same consistent view used by compliance scoring."""
    yield from get_tenant_db(request, db)


def require_scopes(required_scopes: List[str]):
    """Enforce that the requesting client has the required scopes"""

    def dependency(request: Request):
        scopes = getattr(request.state, "scopes", [])
        if "admin" in scopes:
            return
        for scope in required_scopes:
            if scope not in scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Forbidden: Insufficient scopes",
                )

    return Depends(dependency)


def require_roles(required_roles: List[str]):
    """Enforce that the authenticated principal belongs to one of the allowed tenant roles."""
    allowed = {_normalize_role(role) for role in required_roles}

    def dependency(request: Request):
        role = _normalize_role(getattr(request.state, "user_role", None))
        if role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Insufficient role",
            )

    return Depends(dependency)


def require_platform_admin():
    """Require an active tenantless platform session and its dedicated scope."""

    def dependency(request: Request):
        platform_role = str(getattr(request.state, "platform_role", "NONE")).upper()
        scopes = getattr(request.state, "scopes", [])
        is_active = getattr(request.state, "user_is_active", False)
        if (
            not is_active
            or getattr(request.state, "credential_kind", None) != "platform_session"
            or getattr(request.state, "tenant_id", None) is not None
            or platform_role != "ADMIN"
            or "platform.admin" not in scopes
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Platform administrator access required",
            )

    return Depends(dependency)


def get_current_tenant(request: Request) -> str:
    """Dependency to retrieve the current tenant_id from the request state"""
    return str(request.state.tenant_id)

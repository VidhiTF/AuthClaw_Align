"""Authentication and tenant context middleware / dependencies"""
import hmac
import logging
import os
from typing import Generator, List
import pyotp
from fastapi import Request, Depends, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.db.dependencies import get_db
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
            raise RuntimeError("API_KEY_HASH_SECRET, SESSION_SECRET, or JWT_SECRET is required in production")
        secret = "authclaw-lite-dev-secret"
    return hmac.digest(secret.encode("utf-8"), key.encode("utf-8"), "sha3_256").hex()


def set_mfa_credentials(user, secret: str, backup_codes: list[str]) -> None:
    user.mfa_secret = encrypt_secret(secret)
    user.mfa_backup_codes = [
        hash_key(f"mfa-backup:{code.lower()}") for code in backup_codes
    ]
    user.mfa_enabled = True


def verify_mfa_code(user, code: str) -> bool:
    code = code.strip().lower()
    stored_secret = user.mfa_secret or ""
    encrypted = stored_secret.startswith(
        (SECRET_ENVELOPE_PREFIX, SECRET_ENVELOPE_V2_PREFIX)
    )
    secret = decrypt_secret(stored_secret) if encrypted else stored_secret
    if stored_secret and not encrypted:
        user.mfa_secret = encrypt_secret(stored_secret)

    backup_codes = list(user.mfa_backup_codes or [])
    normalized_codes = [
        stored if len(stored) == 64 else hash_key(f"mfa-backup:{stored.lower()}")
        for stored in backup_codes
    ]
    user.mfa_backup_codes = normalized_codes
    if secret and pyotp.TOTP(secret).verify(code, valid_window=1):
        return True

    candidate = hash_key(f"mfa-backup:{code}")
    for index, stored in enumerate(normalized_codes):
        if hmac.compare_digest(candidate, stored):
            user.mfa_backup_codes = (
                normalized_codes[:index] + normalized_codes[index + 1 :]
            )
            return True
    return False


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
            "/metrics",
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
        if request.method == "OPTIONS" or canonical_path in public_paths or path.startswith("/static") or canonical_path.startswith("/v1/trust-center/public"):
            return await call_next(request)

        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Missing Authorization Header"}
            )

        parts = auth_header.split(" ")
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid Authorization Format. Expected: Bearer <key>"}
            )

        api_key = parts[1]
        key_hash = hash_key(api_key)

        db = SessionLocal()
        try:
            # Query the resolve_api_key function (bypasses RLS due to SECURITY DEFINER)
            result = db.execute(
                text("SELECT id, tenant_id, scopes, created_by FROM resolve_api_key(:key_hash)"),
                {"key_hash": key_hash}
            ).first()

            if not result:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Unauthorized: Invalid or expired API Key"}
                )

            db.execute(
                text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
                {"tenant_id": str(result.tenant_id)},
            )
            principal = db.execute(
                text(
                    """
                    SELECT u.role, u.platform_role, u.is_active, t.status AS tenant_status
                    FROM users u
                    JOIN tenants t ON t.id = u.tenant_id
                    WHERE u.id = :user_id AND u.tenant_id = :tenant_id
                    """
                ),
                {"user_id": str(result.created_by), "tenant_id": str(result.tenant_id)},
            ).first()

            if not principal or not principal.is_active:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Unauthorized: User is inactive or not found"}
                )
            tenant_lifecycle_path = canonical_path in {"/v1/tenants/current", "/v1/tenants/current/status"}
            if principal.tenant_status != "active" and not tenant_lifecycle_path:
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "Forbidden: Tenant is not active"}
                )

            db.execute(
                text(
                    """
                    UPDATE api_keys
                    SET last_used = NOW(),
                        last_used_ip = :ip,
                        last_used_user_agent = :user_agent,
                        last_used_request_id = :request_id,
                        updated_at = NOW()
                    WHERE id = :api_key_id
                    """
                ),
                {
                    "api_key_id": str(result.id),
                    "ip": request.client.host if request.client else "",
                    "user_agent": request.headers.get("user-agent", "")[:512],
                    "request_id": request.headers.get("x-request-id", "")[:255],
                },
            )
            db.commit()

            # Inject tenant info, scopes, and role into request state.
            request.state.tenant_id = result.tenant_id
            request.state.scopes = result.scopes
            request.state.user_id = result.created_by
            request.state.api_key_id = result.id
            request.state.user_role = _normalize_role(principal.role)
            request.state.tenant_role = request.state.user_role
            request.state.platform_role = str(principal.platform_role).upper()
            request.state.user_is_active = bool(principal.is_active)
        except Exception as e:
            db.rollback()
            logger.exception("Authentication middleware failed")
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Authentication failed"}
            )
        finally:
            try:
                db.execute(text("SELECT set_config('app.current_tenant_id', '', false)"))
            except Exception:
                pass
            db.close()

        return await call_next(request)


def get_tenant_db(request: Request, db: Session = Depends(get_db)) -> Generator[Session, None, None]:
    """
    Dependency that sets the tenant context on the DB session to enforce RLS
    and clears it when the session is closed/returned to the pool.
    """
    tenant_id = getattr(request.state, "tenant_id", None)
    if tenant_id:
        db.info["tenant_id"] = str(tenant_id)
    try:
        yield db
    finally:
        db.info.pop("tenant_id", None)


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
                    detail="Forbidden: Insufficient scopes"
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
                detail="Forbidden: Insufficient role"
            )
    return Depends(dependency)


def require_platform_admin():
    """Require the global ADMIN role and its dedicated platform scope."""

    def dependency(request: Request):
        platform_role = str(getattr(request.state, "platform_role", "NONE")).upper()
        scopes = getattr(request.state, "scopes", [])
        is_active = getattr(request.state, "user_is_active", False)
        if (
            not is_active
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

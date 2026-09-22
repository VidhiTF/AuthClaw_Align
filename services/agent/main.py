import startup.env_loader
import os
import time
import uuid
import logging
import json
import base64
import hashlib
import hmac
import secrets
import threading
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple
from contextlib import asynccontextmanager, nullcontext
from fastapi import FastAPI, Header, HTTPException, Response, status, Request, UploadFile, File, Form, Depends
from fastapi.encoders import jsonable_encoder
from fastapi.exception_handlers import http_exception_handler
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import text

from graph import graph
from approval_store import (
    ApprovalCreationError,
    ApprovalPersistenceError,
    ApprovalStateConflict,
    approve_approval_atomic,
    begin_approval_execution_atomic,
    expire_approved_execution_atomic,
    finish_approval_execution_atomic,
    renew_approval_execution_lease_atomic,
    reject_approval_atomic,
    pending_approvals,
    approved_results,
    get_approval,
    get_all_approvals,
    get_approval_history,
    append_approval_audit,
    reconcile_due_approval_executions,
    reconcile_late_approval_execution_outcome_atomic,
    remaining_seconds,
)
from memory import add_message, delete_session_history, get_history, list_sessions, purge_session_history

from startup.validation import validate_environment
from startup.initialization import initialize_provider
from database import validate_database_security
from policy import compile_policy_to_rego, evaluate_opa_policy, get_policy, load_policy
from services.gateway_service import (
    ExecutionLeaseLostError,
    GatewayExecutionOutcome,
    GatewayProviderConfigurationError,
    GatewayProviderUnavailableError,
    GatewayService,
)
from services.canonical_agent_service import CanonicalAgentService, CanonicalExecutionError
from services.remediation_runtime import RemediationRuntime, RemediationRuntimeError
from services.enterprise_identity import (
    EnterpriseIdentityError,
    complete_oidc_callback,
    create_authorization_request,
    list_provider_configs,
    public_jwks,
    revoke_authclaw_refresh_token,
    security_posture,
    set_provider_enabled,
    upsert_provider_config,
)
from services.tenant_context import get_current_request_id, get_current_tenant_id, tenant_context
from services.control_plane_auth import authenticate_control_plane
from services.quota_service import admit, check_available, metrics_snapshot, record_unavailable, QuotaExceeded, QuotaUnavailable
from services.document_monitor_status import monitor_metrics_snapshot, monitor_status

# Set up basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("authclaw.gateway")

EXECUTION_LEASE_SECONDS = 60
EXECUTION_HEARTBEAT_SECONDS = 20


class _ExecutionLeaseHeartbeat:
    """Renew one fenced execution lease until its terminal write completes."""

    def __init__(self, record: dict):
        self.record = dict(record)
        self._stop = threading.Event()
        self._lost = threading.Event()
        self._record_lock = threading.Lock()
        self._loss_reason = "execution lease is no longer owned"
        self._thread = threading.Thread(
            target=self._run,
            name=f"approval-lease-{record.get('approval_id')}",
            daemon=True,
        )

    def start(self) -> "_ExecutionLeaseHeartbeat":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not threading.current_thread():
            self._thread.join(timeout=1)

    def assert_owned(self) -> None:
        """Renew synchronously at a side-effect boundary or cancel execution."""
        if self._lost.is_set():
            raise ExecutionLeaseLostError(self._loss_reason)
        renewed_at = datetime.now(timezone.utc)
        try:
            with self._record_lock:
                current = dict(self.record)
            with tenant_context(
                current.get("tenant_id"),
                request_id=str(current.get("request_id") or ""),
                required=True,
            ):
                renewed = renew_approval_execution_lease_atomic(
                    current,
                    renewed_at=renewed_at,
                    lease_expires_at=(
                        renewed_at + timedelta(seconds=EXECUTION_LEASE_SECONDS)
                    ),
                )
            with self._record_lock:
                self.record = renewed
        except (ApprovalStateConflict, ApprovalPersistenceError) as exc:
            self._loss_reason = str(exc)
            self._lost.set()
            raise ExecutionLeaseLostError(self._loss_reason) from exc

    def _run(self) -> None:
        while not self._stop.wait(EXECUTION_HEARTBEAT_SECONDS):
            try:
                self.assert_owned()
            except ExecutionLeaseLostError as exc:
                logger.error(
                    "Execution lease lost for approval %s: %s",
                    self.record.get("approval_id"),
                    exc,
                )
                return


def _finish_execution_with_lease(
    heartbeat: _ExecutionLeaseHeartbeat,
    record: dict,
    **kwargs,
) -> dict:
    try:
        return finish_approval_execution_atomic(record, **kwargs)
    finally:
        heartbeat.stop()

API_KEY = os.getenv("AUTHCLAW_TEST_API_KEY", "")

@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_environment()
    validate_database_security()
    initialize_provider()
    
    # 4. Start background compliance watcher for watched_documents folder.
    # Local smoke tests can disable this so provider/email limits do not obscure
    # the core gateway, auth, and UI startup path.
    if env_bool("AUTHCLAW_DISABLE_BACKGROUND_MONITOR", True):
        logger.info("Background document compliance monitor disabled by AUTHCLAW_DISABLE_BACKGROUND_MONITOR.")
    else:
        from document_processing.monitoring import start_background_monitoring
        try:
            start_background_monitoring(os.getenv("AUTHCLAW_BACKGROUND_MONITOR_TENANT_ID"))
        except Exception as ex:
            logger.error(f"Failed to start background document monitoring: {ex}")
        
    yield
    
    # Shutdown sequence:
    from document_processing.monitoring import stop_background_monitoring
    try:
        stop_background_monitoring()
    except Exception as ex:
        logger.error(f"Failed to stop background document monitoring: {ex}")

app = FastAPI(lifespan=lifespan)


@app.exception_handler(QuotaExceeded)
async def quota_exceeded_response(request: Request, exc: QuotaExceeded):
    return JSONResponse(status_code=429, content={"error": "rate_limit_exceeded"}, headers={"Retry-After": "60"})


@app.exception_handler(QuotaUnavailable)
async def quota_unavailable_response(request: Request, exc: QuotaUnavailable):
    return JSONResponse(status_code=503, content={"error": "rate_limit_unavailable"}, headers={"Retry-After": "1"})


@app.exception_handler(HTTPException)
async def sanitized_http_exception(request: Request, exc: HTTPException):
    if exc.status_code < 500:
        return await http_exception_handler(request, exc)
    logger.error(
        "Request failed status=%s path=%s error_type=%s",
        exc.status_code,
        request.url.path,
        type(exc).__name__,
    )
    return JSONResponse(status_code=exc.status_code, content={"detail": "Internal server error"})


@app.exception_handler(Exception)
async def sanitized_unhandled_exception(request: Request, exc: Exception):
    logger.error(
        "Unhandled request failure path=%s error_type=%s",
        request.url.path,
        type(exc).__name__,
    )
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

def get_allowed_origins() -> List[str]:
    configured = os.getenv("AUTHCLAW_ALLOWED_ORIGINS")
    if configured:
        return [origin.strip() for origin in configured.split(",") if origin.strip()]
    return ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:5174", "http://127.0.0.1:5174"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API_KEY removed for production security hardening

def _feature_enabled(name: str, default: bool = False) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}


def _is_production_env() -> bool:
    return os.getenv("AUTHCLAW_ENV", "development").strip().lower() in {"production", "prod"}


def _https_enforcement_enabled() -> bool:
    return _is_production_env() or _feature_enabled("AUTHCLAW_ENFORCE_HTTPS", False)


def _local_request_host(host: str) -> bool:
    hostname = (host or "").split(":", 1)[0].lower()
    return hostname in {"localhost", "127.0.0.1", "::1", "testserver"}


def _mark_set_cookie_headers_secure(response: Response) -> None:
    raw_headers = []
    for name, value in response.raw_headers:
        if name.lower() == b"set-cookie":
            cookie = value.decode("latin-1")
            lower_cookie = cookie.lower()
            if "secure" not in lower_cookie:
                cookie += "; Secure"
            if "samesite" not in lower_cookie:
                cookie += "; SameSite=Lax"
            raw_headers.append((name, cookie.encode("latin-1")))
        else:
            raw_headers.append((name, value))
    response.raw_headers = raw_headers


@app.middleware("http")
async def production_security_middleware(request: Request, call_next):
    enforce_https = _https_enforcement_enabled()
    forwarded_proto = request.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip().lower()
    scheme = forwarded_proto or request.url.scheme
    host = request.headers.get("host", "")

    if enforce_https and scheme == "http" and not _local_request_host(host):
        target = request.url.replace(scheme="https")
        return RedirectResponse(str(target), status_code=status.HTTP_308_PERMANENT_REDIRECT)

    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    if enforce_https and not _local_request_host(host):
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        _mark_set_cookie_headers_secure(response)
    return response


def _gateway_runtime_path(path: str) -> bool:
    normalized = path[4:] if path.startswith("/api/") else path
    return normalized in {"/gateway/chat", "/chat", "/v1/chat/completions"} or normalized.startswith("/gateway/documents/")


def _tenant_tier_limit(tenant_id: int) -> int:
    from database import engine
    from services.tenant_plan_service import PLAN_LIMITS, resolve_tenant_plan
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT subscription_tier, plan, tier FROM tenants WHERE id = :tenant_id"),
            {"tenant_id": tenant_id},
        ).fetchone()
    try:
        tier = resolve_tenant_plan(*(row or ()))
    except ValueError as exc:
        record_unavailable()
        raise QuotaUnavailable("Tenant plan unavailable") from exc
    limit = int(os.getenv(f"AUTHCLAW_RATE_LIMIT_{tier.upper()}_RPM", PLAN_LIMITS[tier]["requests_per_minute"]))
    if limit <= 0:
        record_unavailable()
        raise QuotaUnavailable("Invalid tenant plan limit")
    return limit


@app.middleware("http")
async def enterprise_gateway_middleware(request: Request, call_next):
    if (_gateway_runtime_path(request.url.path)
            and _feature_enabled("AUTHCLAW_REQUIRE_GO_GATEWAY", False)
            and request.headers.get("X-AuthClaw-Gateway") != "go"):
        return JSONResponse(status_code=426, content={"error": "go_gateway_required"})
    return await call_next(request)


import os
import hashlib
import base64
import hmac
import struct
import time
from services.secret_manager import SecretManager, SENSITIVE_ENV_NAMES, bootstrap_local_process_secrets

bootstrap_local_process_secrets()

DEFAULT_ITERATIONS = int(os.getenv("AUTHCLAW_PASSWORD_ITERATIONS", "600000"))

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    iterations = DEFAULT_ITERATIONS
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations
    )
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    key_b64 = base64.b64encode(key).decode('utf-8')
    return f"pbkdf2_sha256${iterations}${salt_b64}${key_b64}"

def verify_password(password: str, hashed_password: str) -> bool:
    try:
        if not hashed_password or not hashed_password.startswith("pbkdf2_sha256$"):
            return False
        parts = hashed_password.split('$')
        if len(parts) != 4:
            return False
        _, iterations_str, salt_b64, key_b64 = parts
        iterations = int(iterations_str)
        salt = base64.b64decode(salt_b64.encode('utf-8'))
        expected_key = base64.b64decode(key_b64.encode('utf-8'))
        actual_key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            iterations
        )
        return hmac.compare_digest(actual_key, expected_key)
    except Exception:
        return False

def get_hotp_token(secret: str, intervals_no: int) -> str:
    secret = secret.strip().replace(" ", "")
    missing_padding = len(secret) % 8
    if missing_padding:
        secret += '=' * (8 - missing_padding)
    try:
        key = base64.b32decode(secret, casefold=True)
    except Exception as e:
        raise ValueError(f"Invalid base32 secret: {e}")
        
    msg = struct.pack(">Q", intervals_no)
    hmac_result = hmac.new(key, msg, hashlib.sha1).digest()
    o = hmac_result[19] & 15
    token = (struct.unpack(">I", hmac_result[o:o+4])[0] & 0x7fffffff) % 1000000
    return f"{token:06d}"

def verify_totp_token(secret: str, token: str, window: int = 1) -> bool:
    if not secret or not token:
        return False
    token = str(token).strip()
    if not token.isdigit() or len(token) != 6:
        return False
    current_time = int(time.time())
    time_step = 30
    current_interval = current_time // time_step
    
    for i in range(-window, window + 1):
        try:
            if get_hotp_token(secret, current_interval + i) == token:
                return True
        except Exception:
            pass
    return False

def verify_totp_token_with_counter(secret: str, token: str, window: int = 1) -> Optional[int]:
    if not secret or not token:
        return None
    token = str(token).strip()
    if not token.isdigit() or len(token) != 6:
        return None
    current_interval = int(time.time()) // 30
    for i in range(-window, window + 1):
        counter = current_interval + i
        try:
            if get_hotp_token(secret, counter) == token:
                return counter
        except Exception:
            pass
    return None

def generate_totp_secret() -> str:
    return base64.b32encode(os.urandom(10)).decode('utf-8')

def build_otpauth_uri(email: str, secret: str) -> str:
    from urllib.parse import quote
    account = quote(email)
    issuer = quote("AuthClaw")
    return f"otpauth://totp/AuthClaw:{account}?secret={secret}&issuer={issuer}"

def encrypt_secret(raw_value: str) -> str:
    return SecretManager().encrypt_for_database(raw_value)

def decrypt_secret(encrypted_value: str) -> str:
    return SecretManager().decrypt_from_database(encrypted_value)

def decrypt_totp_secret(stored_value: Optional[str]) -> Optional[str]:
    if not stored_value:
        return None
    if stored_value.startswith(("v2:aes256gcm:", "v3:envelope:")):
        return decrypt_secret(stored_value)
    return stored_value

def resolve_tenant(x_api_key: str, authorization: str = None) -> int:
    context_tenant_id = get_current_tenant_id()
    if context_tenant_id is not None:
        return int(context_tenant_id)

    key_to_check = x_api_key
    if not key_to_check and authorization:
        if authorization.startswith("Bearer "):
            key_to_check = authorization[7:]
        else:
            key_to_check = authorization

    if not key_to_check:
        raise HTTPException(status_code=401, detail="Authentication credentials missing.")

    # 1. Check if the key_to_check is a valid JWT session token
    jwt_payload = decode_jwt(key_to_check)
    if jwt_payload and "tenant_id" in jwt_payload:
        return jwt_payload["tenant_id"]

    # 2. Otherwise, treat it as a raw API key, calculate its SHA-256 hash
    h = hashlib.sha256(key_to_check.encode('utf-8')).hexdigest()

    # 3. Check in database
    from database import engine
    from sqlalchemy import text
    with engine.begin() as conn:
        tenant_id = conn.execute(
            text("SELECT resolve_tenant_api_key(:h)"), {"h": h}
        ).scalar()
        if tenant_id is None:
            raise HTTPException(status_code=401, detail="Invalid API Key.")
        return tenant_id


def require_tenant_context() -> int:
    tenant_id = get_current_tenant_id()
    if tenant_id is None:
        raise HTTPException(status_code=401, detail="Authenticated tenant context required.")
    return int(tenant_id)


def resolve_tenant_from_authorization(authorization: str = None) -> int:
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization credentials missing.")
    token = authorization[7:] if authorization.startswith("Bearer ") else authorization
    payload = decode_jwt(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid session token.")
    tenant_id = payload.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=401, detail="Session token is missing tenant scope.")
    return tenant_id

def get_current_user_from_authorization(authorization: str = Header(None)) -> dict:
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization credentials missing.")
    token = authorization[7:] if authorization.startswith("Bearer ") else authorization
    payload = decode_jwt(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid session token.")
    return payload


def _audit_stale_session_denial(payload: dict, current_role: Optional[str]) -> None:
    from verify_audit import create_audit_block

    create_audit_block(
        query="Privileged session authorization",
        response="Denied because persisted tenant authority changed after token issue.",
        allowed=False,
        risk_level="HIGH",
        approval_status="authorization_denied",
        execution_status="denied",
        username=str(payload.get("email") or payload.get("sub") or payload.get("user_id")),
        tenant_id=payload.get("tenant_id"),
        policy_name="authoritative_tenant_role",
        policy_type="authorization",
        matched_pattern=f"claimed={payload.get('role')};current={current_role or 'inactive'}",
    )


def revalidate_tenant_session_payload(payload: dict) -> dict:
    """Replace JWT role claims with current persisted tenant-user authority."""
    tenant_id = payload.get("tenant_id")
    user_id = payload.get("user_id")
    if not tenant_id or not user_id:
        raise HTTPException(status_code=401, detail="Session token is missing canonical user scope.")

    from database import engine
    with tenant_context(tenant_id, required=True), engine.connect() as conn:
        row = conn.execute(
            text(
                """
                SELECT id, role, permissions, status
                FROM tenant_users
                WHERE id = :user_id AND tenant_id = :tenant_id
                """
            ),
            {"user_id": user_id, "tenant_id": tenant_id},
        ).fetchone()

    current_role = (
        str(row._mapping["role"])
        if row and row._mapping.get("status") == "active"
        else None
    )
    claimed_role = str(payload.get("role") or "")
    if current_role is None or current_role != claimed_role:
        with tenant_context(tenant_id, required=True):
            _audit_stale_session_denial(payload, current_role)
    if current_role is None:
        raise HTTPException(status_code=403, detail="Tenant user is inactive or unavailable.")

    refreshed = dict(payload)
    refreshed["role"] = current_role
    refreshed["permissions"] = row._mapping.get("permissions")
    return refreshed


def optional_user_from_request(request: Request) -> dict:
    principal = getattr(request.state, "control_plane_principal", None)
    if principal:
        return principal
    principal = getattr(request.state, "api_key_principal", None)
    if principal:
        return principal
    principal = getattr(request.state, "session_principal", None)
    if principal:
        return principal
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return {}
    token = auth_header[7:] if auth_header.startswith("Bearer ") else auth_header
    payload = decode_jwt(token)
    return payload or {}


def _is_public_or_auth_path(path: str) -> bool:
    public_exact = {
        "/",
        "/openapi.json",
        "/docs",
        "/redoc",
        "/health",
        "/health/ready",
        "/api/v1/agent/health",
        "/api/v1/agent/health/ready",
        "/internal/metrics/quota",
        "/favicon.ico",
    }
    return path in public_exact or path.startswith(("/auth/", "/static/", "/assets/"))


def _tenant_id_from_request_headers(request: Request) -> Optional[int]:
    principal = getattr(request.state, "verified_service_principal", None)
    if principal:
        from database import engine
        with engine.begin() as conn:
            tenant_id = conn.execute(
                text(
                    """
                    SELECT upsert_control_plane_tenant(:name, :control_plane_id)
                    """
                ),
                {
                    "name": f"Control Plane {principal.tenant_id}",
                    "control_plane_id": principal.tenant_id,
                },
            ).scalar_one()
        request.state.control_plane_principal = {
            "auth_source": "control_plane",
            "tenant_id": tenant_id,
            "external_tenant_id": principal.tenant_id,
            "sub": principal.user_id,
            "role": principal.role,
            "mfa_verified_at": principal.mfa_verified_at,
            "mfa_operation": principal.mfa_operation,
            "mfa_body_sha256": principal.mfa_body_sha256,
            "mfa_assertion_id": principal.mfa_assertion_id,
        }
        request.state.quota_user_id = principal.user_id
        return tenant_id

    authorization = request.headers.get("Authorization")
    x_api_key = request.headers.get("X-API-Key")

    if authorization:
        token = authorization[7:] if authorization.startswith("Bearer ") else authorization
        payload = decode_jwt(token)
        if payload and payload.get("tenant_id"):
            payload = revalidate_tenant_session_payload(payload)
            request.state.session_principal = payload
            request.state.quota_user_id = payload.get("user_id") or payload.get("sub")
            if not request.state.quota_user_id:
                raise HTTPException(status_code=401, detail="Authenticated user identity required.")
            return payload["tenant_id"]
        if token:
            x_api_key = token

    if x_api_key:
        tenant_id = resolve_tenant(x_api_key=x_api_key, authorization=None)
        key_hash = hashlib.sha256(x_api_key.encode("utf-8")).hexdigest()
        service_subject = f"api-key:{key_hash}"
        request.state.quota_key_id = key_hash
        request.state.quota_user_id = "service:tenant"
        # Tenant API keys are tenant-wide service credentials. Preserve their
        # existing authorization while giving approval workflows a unique,
        # immutable maker identity bound to the validated key record hash.
        request.state.api_key_principal = {
            "auth_source": "api_key",
            "tenant_id": tenant_id,
            "sub": service_subject,
            "role": "owner",
        }
        return tenant_id

    return None


@app.middleware("http")
async def tenant_database_context_middleware(request: Request, call_next):
    from starlette.concurrency import run_in_threadpool
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    tenant_id = None
    protected = not _is_public_or_auth_path(request.url.path)
    try:
        request.state.verified_service_principal = await authenticate_control_plane(request)
        principal = request.state.verified_service_principal
        if principal:
            from services.rbac_matrix import enforce_request_access, agent_operation_allowed
            enforce_request_access(request.method, request.url.path,
                                   {"external_tenant_id": principal.tenant_id, "role": principal.role})
            if request.method == "POST" and request.url.path.rstrip("/") == "/api/v1/agent/executions":
                try:
                    operation = AgentExecutionRequest.model_validate_json(await request.body()).operation.strip().lower()
                except ValueError as exc:
                    raise HTTPException(status_code=422, detail="Invalid agent execution request.") from exc
                if operation not in {"chat", "rag", "remediation_plan"}:
                    raise HTTPException(status_code=422, detail="operation must be one of: chat, rag, remediation_plan")
                if not agent_operation_allowed(principal.role, operation):
                    raise HTTPException(status_code=403, detail="Role is not authorized for this agent operation.")
        if protected:
            tenant_id = await run_in_threadpool(_tenant_id_from_request_headers, request)
            if tenant_id is None:
                raise HTTPException(status_code=401, detail="Authentication credentials missing.")
        if _rbac_enforcement_enabled():
            from services.rbac_matrix import enforce_request_access
            enforce_request_access(request.method, request.url.path, optional_user_from_request(request))
    except HTTPException as exc:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail},
                            headers={"X-Request-ID": request_id})
    except Exception:
        return JSONResponse(status_code=503, content={"error": "authentication_unavailable"}, headers={"Retry-After": "1"})
    request.state.correlation_id = request_id
    request.state.tenant_id = tenant_id
    with tenant_context(tenant_id, request_id=request_id, required=tenant_id is not None):
        if protected:
            try:
                await run_in_threadpool(
                    reconcile_due_approval_executions,
                    tenant_id,
                    transition_at=datetime.now(timezone.utc),
                )
            except ApprovalPersistenceError:
                return JSONResponse(
                    status_code=503,
                    content={"error": "approval_reconciliation_unavailable"},
                    headers={"Retry-After": "1"},
                )
            try:
                limit = await run_in_threadpool(_tenant_tier_limit, tenant_id)
                await run_in_threadpool(
                    admit, tenant_id,
                    user_id=getattr(request.state, "quota_user_id", None),
                    key_id=getattr(request.state, "quota_key_id", None),
                    tenant_limit=limit,
                )
            except QuotaExceeded:
                return JSONResponse(status_code=429, content={"error": "rate_limit_exceeded"}, headers={"Retry-After": "60"})
            except QuotaUnavailable:
                return JSONResponse(status_code=503, content={"error": "rate_limit_unavailable"}, headers={"Retry-After": "1"})
            except Exception:
                record_unavailable()
                return JSONResponse(status_code=503, content={"error": "rate_limit_unavailable"}, headers={"Retry-After": "1"})
        path = request.url.path
        if path.startswith(("/evidence", "/compliance/evidence/", "/reports/")) or (path.startswith("/compliance/controls/") and path.endswith("/evidence")):
            from services.evidence_access import audit_access
            principal = optional_user_from_request(request)
            purpose = "delete" if request.method == "DELETE" else "export" if "/export/" in path or path.startswith("/reports/") else "download" if "/download/" in path else "view"
            try:
                await run_in_threadpool(audit_access, tenant_id, principal.get("sub"), purpose, path)
            except HTTPException as exc:
                return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
        # Downstream execution is outside authentication/admission exception handling.
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        if tenant_id is not None:
            response.headers["X-Tenant-ID"] = str(tenant_id)
        return response


def _rbac_enforcement_enabled() -> bool:
    explicit = os.getenv("AUTHCLAW_ENABLE_RBAC_ENFORCEMENT")
    automated_test = bool(os.getenv("PYTEST_CURRENT_TEST")) or env_bool("AUTHCLAW_AUTOMATED_TEST_MODE", False)
    if explicit is not None and automated_test:
        return explicit.strip().lower() in {"1", "true", "yes", "on"}
    return True


def approval_actor_from_payload(payload: dict) -> str:
    actor = payload.get("sub")
    if not isinstance(actor, str) or not actor.strip():
        raise HTTPException(status_code=401, detail="Immutable authenticated identity is required.")
    return actor.strip()

def approval_identity_aliases(payload: dict) -> set[str]:
    aliases = set()
    for claim in ("sub", "user_id", "email"):
        value = payload.get(claim)
        if isinstance(value, str) and value.strip():
            aliases.add(value.strip().casefold())
    return aliases

def ensure_approval_tenant_access(record: dict, payload: dict) -> None:
    tenant_id = payload.get("tenant_id")
    if tenant_id is None or record.get("tenant_id") is None or record.get("tenant_id") != tenant_id:
        raise HTTPException(status_code=404, detail="Approval ID not found")

def approval_response_record(record: dict, tenant_id: int = None) -> dict:
    return {
        "approval_id": record["approval_id"],
        "status": record["status"],
        "created_at": record["created_at"],
        "expires_at": record["expires_at"],
        "remaining_seconds": remaining_seconds(record),
        "approved_at": record["approved_at"],
        "rejected_at": record["rejected_at"],
        "executed_at": record["executed_at"],
        "requested_action": record["requested_action"],
        "query": record["query"],
        "request_id": record["request_id"],
        "correlation_id": record["correlation_id"],
        "tenant_id": record.get("tenant_id"),
        "risk_level": record.get("risk_level"),
        "reason": record.get("reason") or "high_risk",
        "comments": record.get("comments") or [],
        "approved_by": record.get("approved_by"),
        "rejected_by": record.get("rejected_by"),
        "executed_by": record.get("executed_by"),
        "mfa_verified": bool(record.get("mfa_verified", False)),
        "approval_mfa_verified": bool(record.get("approval_mfa_verified", record.get("mfa_verified", False))),
        "execution_mfa_verified": bool(record.get("execution_mfa_verified", False)),
        "execution_expires_at": record.get("execution_expires_at"),
        "execution_operation_id": record.get("execution_operation_id"),
        "execution_provider_operation_id": record.get("execution_provider_operation_id"),
        "execution_outcome": record.get("execution_outcome") or {},
        "last_action_at": record.get("last_action_at"),
        "history": get_approval_history(record["approval_id"], tenant_id=tenant_id),
        "metadata": record.get("metadata", {}),
    }

async def parse_approval_action_payload(request: Request) -> dict:
    body_bytes = await request.body()
    if not body_bytes:
        return {"_body_present": False}
    try:
        payload = json.loads(body_bytes)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload"
        )
    if not isinstance(payload, dict):
        payload = {}
    payload["_body_present"] = True
    return payload

def _approval_execution_expiry_minutes() -> int:
    try:
        value = get_policy().get("approval", {}).get("execution_expiry_minutes", 10)
        return max(1, int(value))
    except Exception:
        return 10

def _approval_action_payload_hash(record: dict) -> str:
    metadata = record.get("metadata") or {}
    payload = {
        "approval_id": record.get("approval_id"),
        "tenant_id": record.get("tenant_id"),
        "requested_action": record.get("requested_action"),
        "query": record.get("query"),
        "risk_level": record.get("risk_level"),
        "reason": record.get("reason"),
        "execution_target": metadata.get("execution_target", "gateway"),
        "remediation_plan_id": metadata.get("remediation_plan_id"),
        "finding_id": metadata.get("finding_id"),
        "action_payload": metadata.get("action_payload"),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

def _approval_mfa_binding_hash(record: dict, actor: str, stage: str, counter: int, expiry_at: str) -> str:
    payload = {
        "tenant_id": record.get("tenant_id"),
        "approver": actor,
        "approval_id": record.get("approval_id"),
        "action_payload_hash": _approval_action_payload_hash(record),
        "expiry_window": expiry_at,
        "stage": stage,
        "totp_counter": counter,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

def _approval_authenticated_payload(request: Request) -> dict:
    payload = optional_user_from_request(request)
    if not payload.get("tenant_id"):
        raise HTTPException(status_code=401, detail="Authorization credentials missing.")
    return payload

def _consume_approval_totp_counter(
    record: dict,
    user_payload: dict,
    mfa_code: str,
    *,
    connection=None,
    deferred_failure: Optional[list] = None,
) -> Optional[int]:
    """Verify and atomically consume a user's TOTP counter.

    The row lock makes replay prevention global for the identity, including
    concurrent approvals handled by different workers. Failures and lockout
    are durable rather than process-local.
    """
    tenant_id = record.get("tenant_id")
    if not tenant_id:
        return None
    request_id = (
        get_current_request_id()
        or record.get("request_id")
        or record.get("approval_id")
    )
    if not request_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Approval request context is unavailable",
        )
    from database import engine
    from sqlalchemy import text
    now = datetime.now(timezone.utc)
    failure_detail = None
    transaction = nullcontext(connection) if connection is not None else engine.begin()
    with tenant_context(
        int(tenant_id), request_id=str(request_id), required=True
    ), transaction as conn:
        user_id = user_payload.get("user_id")
        username = user_payload.get("sub") or user_payload.get("email")
        if user_id:
            row = conn.execute(
                text("""
                    SELECT u.id, u.totp_secret, u.mfa_last_totp_counter,
                           u.mfa_failed_attempts, u.mfa_locked_until
                    FROM tenant_users u
                    JOIN tenants t ON t.id = u.tenant_id
                    WHERE u.id = :user_id
                      AND u.tenant_id = :tenant_id
                      AND u.status = 'active'
                      AND u.mfa_enabled IS TRUE
                      AND t.status = 'active'
                    LIMIT 1
                    FOR UPDATE
                """),
                {"user_id": user_id, "tenant_id": tenant_id},
            ).mappings().first()
        elif username:
            row = conn.execute(
                text("""
                    SELECT u.id, u.totp_secret, u.mfa_last_totp_counter,
                           u.mfa_failed_attempts, u.mfa_locked_until
                    FROM tenant_users u
                    JOIN tenants t ON t.id = u.tenant_id
                    WHERE lower(u.email) = lower(:email)
                      AND u.tenant_id = :tenant_id
                      AND u.status = 'active'
                      AND u.mfa_enabled IS TRUE
                      AND t.status = 'active'
                    LIMIT 1
                    FOR UPDATE
                """),
                {"email": username, "tenant_id": tenant_id},
            ).mappings().first()
        else:
            row = None

        if not row or not row.get("totp_secret"):
            return None

        # Access JWTs that carry a persisted session identifier lose authority
        # immediately when that exact session is revoked. Older access JWTs do
        # not have a server-side credential record, so current user/tenant/MFA
        # state above is the applicable revocation boundary for them.
        credential_id = user_payload.get("jti")
        if credential_id:
            credential_valid = conn.execute(
                text("""
                    SELECT 1
                    FROM auth_refresh_tokens
                    WHERE jti = :jti
                      AND tenant_id = :tenant_id
                      AND user_id = :user_id
                      AND revoked_at IS NULL
                      AND expires_at > NOW()
                    FOR UPDATE
                """),
                {"jti": credential_id, "tenant_id": tenant_id, "user_id": row["id"]},
            ).scalar()
            if not credential_valid:
                return None

        locked_until = row.get("mfa_locked_until")
        if locked_until and locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        if locked_until and locked_until > now:
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="MFA verification is temporarily locked",
            )

        secret = decrypt_totp_secret(row["totp_secret"])
        counter = verify_totp_token_with_counter(secret, mfa_code, window=1) if secret else None
        last_counter = row.get("mfa_last_totp_counter")
        replayed = counter is not None and last_counter is not None and int(counter) <= int(last_counter)
        if counter is None or replayed:
            attempts = int(row.get("mfa_failed_attempts") or 0) + 1
            lock_until = (
                (now + timedelta(minutes=5)).replace(tzinfo=None)
                if attempts >= 5
                else None
            )
            conn.execute(
                text("""
                    UPDATE tenant_users
                    SET mfa_failed_attempts = :attempts,
                        mfa_locked_until = :locked_until,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = :id AND tenant_id = :tenant_id
                """),
                {
                    "attempts": 0 if lock_until else attempts,
                    "locked_until": lock_until,
                    "id": row["id"],
                    "tenant_id": tenant_id,
                },
            )
            failure_detail = "Stale MFA code is not allowed" if replayed else "Invalid MFA code"
        else:
            conn.execute(
                text("""
                    UPDATE tenant_users
                    SET mfa_last_totp_counter = :counter,
                        mfa_failed_attempts = 0,
                        mfa_locked_until = NULL,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = :id AND tenant_id = :tenant_id
                """),
                {"counter": counter, "id": row["id"], "tenant_id": tenant_id},
            )
    if failure_detail and deferred_failure is not None:
        deferred_failure.append(failure_detail)
        return None
    if failure_detail:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=failure_detail)
    return int(counter)

def _verify_approval_stage_mfa(
    record: dict,
    user_payload: dict,
    payload: dict,
    stage: str,
    expiry_at: str,
    *,
    connection=None,
    deferred_failure: Optional[list] = None,
) -> Tuple[bool, str, int]:
    assertion_id = (
        user_payload.get("mfa_assertion_id")
        if user_payload.get("auth_source") == "control_plane"
        else None
    )
    if assertion_id:
        route = "approve" if stage == "approval" else "execute"
        expected_operation = f"POST /{route}/{record.get('approval_id')}"
        if user_payload.get("mfa_operation") != expected_operation:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="MFA assertion is not bound to this privileged action",
            )
        actor = approval_actor_from_payload(user_payload)
        replay_token = int(hashlib.sha256(assertion_id.encode("ascii")).hexdigest()[:15], 16)
        return (
            True,
            _approval_mfa_binding_hash(record, actor, stage, replay_token, expiry_at),
            replay_token,
        )

    mfa_code = payload.get("mfa_code") if isinstance(payload, dict) else None
    if not mfa_code:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="MFA code is required")

    counter = _consume_approval_totp_counter(
        record,
        user_payload,
        mfa_code,
        connection=connection,
        deferred_failure=deferred_failure,
    )
    if counter is None:
        return False, "", 0

    prior_counter_key = "approval_mfa_counter" if stage == "approval" else "execution_mfa_counter"
    prior_counter = record.get(prior_counter_key)
    if prior_counter is not None and int(prior_counter) == int(counter):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Stale MFA code is not allowed")
    if stage == "execution" and record.get("approval_mfa_counter") is not None and int(record["approval_mfa_counter"]) == int(counter):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Fresh execution MFA code is required")

    actor = approval_actor_from_payload(user_payload)
    return True, _approval_mfa_binding_hash(record, actor, stage, counter, expiry_at), counter

def _utc_from_iso(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed

def _approval_is_expired(record: dict) -> bool:
    expires_at = record.get("expires_at")
    if not expires_at:
        return False
    return datetime.now(timezone.utc) >= _utc_from_iso(expires_at)

def require_platform_admin(payload: dict = Depends(get_current_user_from_authorization)) -> dict:
    if payload.get("role") != "Platform Admin":
        raise HTTPException(status_code=403, detail="Platform admin access required.")
    return payload

def require_tenant_access_admin(payload: dict = Depends(get_current_user_from_authorization)) -> dict:
    payload = revalidate_tenant_session_payload(payload)
    if payload.get("role") not in {"Super Admin", "Security Admin"}:
        raise HTTPException(status_code=403, detail="Tenant access administrator role required.")
    if not payload.get("tenant_id"):
        raise HTTPException(status_code=401, detail="Session token is missing tenant scope.")
    return payload


# SaaS Onboarding & Management Schemas
class RegisterRequest(BaseModel):
    name: Optional[str] = None
    full_name: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    company_name: Optional[str] = None
    email: str
    password: str
    domain: str

class VerifyEmailRequest(BaseModel):
    token: str

class DomainVerifyRequest(BaseModel):
    domain: str
    token: str

class KeyGenerateRequest(BaseModel):
    name: str

class KeyRotateRequest(BaseModel):
    name: Optional[str] = None

class ProviderConnectRequest(BaseModel):
    provider: str
    payload: Optional[dict] = None
    api_key: Optional[str] = None
    model: Optional[str] = None
    api_base: Optional[str] = None
    endpoint: Optional[str] = None
    base_url: Optional[str] = None
    api_version: Optional[str] = None
    deployment: Optional[str] = None
    deployment_name: Optional[str] = None
    azure_endpoint: Optional[str] = None
    azure_api_version: Optional[str] = None
    live_test: Optional[bool] = None


class RemediationConnectorRequest(BaseModel):
    provider: str
    name: Optional[str] = None
    credential_ref: Optional[str] = None
    role_identifier: Optional[str] = None
    region: Optional[str] = None
    scope: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class RemediationScanRequest(BaseModel):
    connector_id: int


class ChatRequest(BaseModel):
    session_id: str
    message: str
    provider: Optional[str] = None
    model: Optional[str] = None


class AgentExecutionRequest(BaseModel):
    operation: str = Field(default="chat")
    message: Optional[str] = None
    session_id: Optional[str] = None
    route_id: Optional[str] = None
    finding_id: Optional[int] = None


class RedactPlaygroundRequest(BaseModel):
    text: str


class ChatCompletionMessage(BaseModel):
    role: str
    content: str


class ChatCompletionRequest(BaseModel):
    model: str
    messages: List[ChatCompletionMessage]
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    stream: Optional[bool] = False


class ChatCompletionResponseChoice(BaseModel):
    index: int
    message: ChatCompletionMessage
    finish_reason: str


class ChatCompletionResponse(BaseModel):
    id: str = Field(default_factory=lambda: f"chatcmpl-{uuid.uuid4()}")
    object: str = "chat.completion"
    created: int = Field(default_factory=lambda: int(time.time()))
    model: str = "authclaw-gateway"
    choices: List[ChatCompletionResponseChoice]


def _stream_text_chunks(text: str, chunk_size: int = 80):
    if not text:
        return
    for start in range(0, len(text), chunk_size):
        yield text[start:start + chunk_size]


def _openai_completion_stream(
    *,
    content: str,
    model: str,
    request_id: str,
    tenant_id: int,
    trace: list,
):
    completion_id = f"chatcmpl-{uuid.uuid4()}"
    created = int(time.time())

    def sse(payload: dict) -> str:
        return f"data: {json.dumps(payload)}\n\n"

    yield sse({
        "id": completion_id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "request_id": request_id,
        "tenant_id": tenant_id,
        "choices": [
            {
                "index": 0,
                "delta": {"role": "assistant"},
                "finish_reason": None,
            }
        ],
    })

    for chunk in _stream_text_chunks(content):
        yield sse({
            "id": completion_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "request_id": request_id,
            "tenant_id": tenant_id,
            "choices": [
                {
                    "index": 0,
                    "delta": {"content": chunk},
                    "finish_reason": None,
                }
            ],
        })

    yield sse({
        "id": completion_id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "request_id": request_id,
        "tenant_id": tenant_id,
        "trace": trace,
        "choices": [
            {
                "index": 0,
                "delta": {},
                "finish_reason": "stop",
            }
        ],
    })
    yield "data: [DONE]\n\n"


@app.get("/")
def home():
    return {
        "message": "AuthClaw Running"
    }


def get_gateway_service() -> GatewayService:
    return GatewayService(graph=graph, resolve_tenant=resolve_tenant, decode_jwt=decode_jwt)


def get_canonical_agent_service() -> CanonicalAgentService:
    from retriever import retrieve_context

    return CanonicalAgentService(
        rag_retriever=retrieve_context,
        remediation_runtime_factory=RemediationRuntime,
    )


@app.post("/api/v1/agent/executions")
def execute_agent_capability(
    execution_request: AgentExecutionRequest,
    request: Request,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    operation = execution_request.operation.strip().lower()
    if operation not in {"chat", "rag", "remediation_plan"}:
        raise HTTPException(
            status_code=422,
            detail="operation must be one of: chat, rag, remediation_plan",
        )

    from services.execution_auth import authorize_agent_operation

    principal = optional_user_from_request(request)
    # The tenant middleware has already resolved a signed external tenant to the
    # internal tenant ID. Forwarded gateway credentials remain transport inputs;
    # they cannot replace the authenticated control-plane tenant or identity.
    tenant_id = require_tenant_context()
    try:
        execution_identity = authorize_agent_operation(principal, operation, tenant_id)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    correlation_id = request.state.correlation_id
    canonical_service = get_canonical_agent_service()
    logger.info(
        "canonical_agent_execution_started operation=%s tenant_id=%s correlation_id=%s",
        operation,
        tenant_id,
        correlation_id,
    )

    try:
        if operation == "rag":
            result = canonical_service.execute_rag(
                message=execution_request.message,
                tenant_id=tenant_id,
                correlation_id=correlation_id,
            )
        elif operation == "remediation_plan":
            result = canonical_service.create_remediation_plan(
                finding_id=execution_request.finding_id,
                tenant_id=tenant_id,
                correlation_id=correlation_id,
            )
        else:
            if not execution_request.message or not execution_request.message.strip():
                raise CanonicalExecutionError("message is required for chat execution")
            gateway_service = get_gateway_service()
            execution = gateway_service.execute_chat(
                message=execution_request.message.strip(),
                session_id=execution_request.session_id,
                x_api_key=x_api_key,
                authorization=authorization,
                username=execution_identity.user_id,
                route_id=execution_request.route_id,
                correlation_id=correlation_id,
            )
            result = canonical_service.format_chat(
                formatted_result=gateway_service.format_chat_response(execution),
                tenant_id=execution.tenant_id,
                correlation_id=correlation_id,
            )
    except CanonicalExecutionError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RemediationRuntimeError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except GatewayProviderConfigurationError as exc:
        raise HTTPException(status_code=500, detail="provider_not_configured") from exc
    except GatewayProviderUnavailableError as exc:
        return JSONResponse(
            status_code=503,
            content={
                "api_version": "v1",
                "operation": operation,
                "status": "provider_unavailable",
                "tenant_id": tenant_id,
                "correlation_id": correlation_id,
                "request_id": exc.request_id,
                "message": PROVIDER_UNAVAILABLE_MESSAGE,
                "trace": exc.trace,
            },
        )

    logger.info(
        "canonical_agent_execution_completed operation=%s tenant_id=%s correlation_id=%s",
        operation,
        tenant_id,
        correlation_id,
    )
    return result


PROVIDER_UNAVAILABLE_MESSAGE = (
    "The configured model provider is currently unavailable. Check provider "
    "credentials and outbound network access, then try again."
)


@app.post("/gateway/chat")
def gateway_chat(
    request: ChatRequest,
    x_api_key: str = Header(None),
    authorization: Optional[str] = Header(None)
):
    service = get_gateway_service()
    try:
        execution = service.execute_chat(
            message=request.message,
            session_id=request.session_id,
            x_api_key=x_api_key,
            authorization=authorization,
            provider=request.provider or "AuthClaw Gateway",
            model=request.model or "authclaw-gateway",
        )
        return service.format_chat_response(execution)
    except GatewayProviderConfigurationError as e:
        logger.error(f"Provider configuration error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"error": "provider_not_configured"}
        )
    except GatewayProviderUnavailableError as e:
        logger.error(f"Provider invocation error: {e}", exc_info=True)
        return JSONResponse(
            status_code=503,
            content={
                "status": "provider_unavailable",
                "error": "provider_unavailable",
                "message": PROVIDER_UNAVAILABLE_MESSAGE,
                "request_id": e.request_id,
                "trace": e.trace,
            }
        )


@app.post("/chat")
def chat(
    request: ChatRequest,
    x_api_key: str = Header(None),
    authorization: Optional[str] = Header(None)
):
    service = get_gateway_service()
    try:
        execution = service.execute_chat(
            message=request.message,
            session_id=request.session_id,
            x_api_key=x_api_key,
            authorization=authorization,
            provider=request.provider or "AuthClaw Gateway",
            model=request.model or "authclaw-gateway",
        )
        return service.format_chat_response(execution)
    except GatewayProviderConfigurationError as e:
        logger.error(f"Provider configuration error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"error": "provider_not_configured"}
        )
    except GatewayProviderUnavailableError as e:
        logger.error(f"Provider invocation error: {e}", exc_info=True)
        return JSONResponse(
            status_code=503,
            content={
                "status": "provider_unavailable",
                "error": "provider_unavailable",
                "message": PROVIDER_UNAVAILABLE_MESSAGE,
                "request_id": e.request_id,
                "trace": e.trace,
            }
        )



class SessionCreate(BaseModel):
    session_id: str
    title: Optional[str] = "New Chat"

@app.post("/chat/sessions")
def create_chat_session(
    req: SessionCreate,
    authorization: Optional[str] = Header(None),
    tenant_id: int = Depends(require_tenant_context),
):
    username = "admin_user"
    if authorization:
        if authorization.startswith("Bearer "):
            token = authorization[7:]
        else:
            token = authorization
        try:
            payload = decode_jwt(token)
            if payload and "sub" in payload:
                username = payload["sub"]
        except Exception:
            pass

    try:
        from database import engine, text
        with engine.connect() as conn:
            conn.execute(
                text("""
                INSERT INTO chat_sessions (session_id, title, user_id, tenant_id, created_at, updated_at)
                VALUES (:session_id, :title, :user_id, :tenant_id, NOW(), NOW())
                ON CONFLICT (tenant_id, session_id) DO UPDATE SET title = EXCLUDED.title, updated_at = NOW()
                """),
                {"session_id": req.session_id, "title": req.title, "user_id": username, "tenant_id": tenant_id}
            )
            conn.commit()
    except Exception as e:
        logger.error("Database error in create_chat_session error_type=%s", type(e).__name__)

    return {"status": "success", "session_id": req.session_id, "title": req.title}


@app.get("/chat/sessions")
def get_chat_sessions(
    authorization: Optional[str] = Header(None),
    tenant_id: int = Depends(require_tenant_context),
):
    try:
        return [
            {
                "session_id": row[0],
                "title": row[1],
                "created_at": row[2].isoformat() if hasattr(row[2], "isoformat") else str(row[2]),
                "updated_at": row[3].isoformat() if hasattr(row[3], "isoformat") else str(row[3]),
                "user_id": row[4],
            }
            for row in list_sessions(tenant_id)
        ]
    except Exception as e:
        logger.error("Database error in get_chat_sessions error_type=%s", type(e).__name__)
        return []


@app.get("/chat/sessions/{session_id}")
def get_chat_session_messages(
    session_id: str,
    tenant_id: int = Depends(require_tenant_context),
):
    return get_history(session_id, tenant_id)


@app.delete("/chat/sessions/{session_id}")
@app.delete("/sessions/{session_id}")
def delete_chat_session(
    session_id: str,
    tenant_id: int = Depends(require_tenant_context),
):
    try:
        delete_session_history(session_id, tenant_id)
        return {"status": "success", "message": f"Session {session_id} deleted."}
    except Exception as e:
        logger.error("Database error in delete_chat_session error_type=%s", type(e).__name__)
        return {"status": "error", "message": "Session deletion failed"}

@app.delete("/chat/sessions")
@app.delete("/sessions")
def purge_all_sessions(tenant_id: int = Depends(require_tenant_context)):
    try:
        purge_session_history(tenant_id)
        return {"status": "success", "message": "Tenant sessions purged."}
    except Exception as e:
        logger.error("Database error in purge_all_sessions error_type=%s", type(e).__name__)
        return {"status": "error", "message": "Session purge failed"}


@app.post("/policies/redact")
def redact_playground(
    request: RedactPlaygroundRequest,
    authorization: Optional[str] = Header(None)
):
    username = "admin_user"
    if authorization:
        if authorization.startswith("Bearer "):
            token = authorization[7:]
        else:
            token = authorization
        try:
            payload = decode_jwt(token)
            if payload and "sub" in payload:
                username = payload["sub"]
        except Exception:
            pass

    from redaction import redact_sensitive_data_rich
    redacted_text, triggered = redact_sensitive_data_rich(request.text, username)

    triggered_names = "None"
    if triggered:
        triggered_names = ", ".join(list(set([t["policy_name"] for t in triggered])))
    confidence = 100
    if triggered:
        confidence = round(max(float(t.get("confidence", 0.8)) for t in triggered) * 100)

    return {
        "redacted_text": redacted_text,
        "count": len(triggered),
        "confidence": confidence,
        "triggered": triggered_names,
        "findings": triggered
    }


@app.get("/approvals")
def get_approvals_list(authorization: Optional[str] = Header(None)):
    tenant_id = None
    if authorization:
        tenant_id = resolve_tenant_from_authorization(authorization)
    approvals = get_all_approvals(tenant_id=tenant_id)
    return [approval_response_record(record, tenant_id=tenant_id) for record in approvals.values()]


@app.get("/approvals/{approval_id}")
def get_approval_by_id(approval_id: str, authorization: Optional[str] = Header(None)):
    record = get_approval(approval_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Approval ID not found"
        )
    tenant_id = None
    if authorization:
        payload = get_current_user_from_authorization(authorization)
        ensure_approval_tenant_access(record, payload)
        tenant_id = payload.get("tenant_id")
    return approval_response_record(record, tenant_id=tenant_id)


@app.get("/approvals/{approval_id}/history")
def get_approval_history_by_id(approval_id: str, authorization: Optional[str] = Header(None)):
    record = get_approval(approval_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval ID not found")
    tenant_id = None
    if authorization:
        payload = get_current_user_from_authorization(authorization)
        ensure_approval_tenant_access(record, payload)
        tenant_id = payload.get("tenant_id")
    return get_approval_history(approval_id, tenant_id=tenant_id)


@app.post("/approve/{approval_id}")
async def approve_request(approval_id: str, request: Request):
    record = get_approval(approval_id, fresh=True)
    if record is None:
        # For backward compatibility, return JSON dict rather than raising 404
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": "Approval ID not found"}
        )

    user_payload = _approval_authenticated_payload(request)
    ensure_approval_tenant_access(record, user_payload)
    approver = approval_actor_from_payload(user_payload)

    # Approval is a single-use pending-to-approved transition. The database
    # compare-and-swap below enforces this again for concurrent workers.
    if record["status"] != "pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Approval request is already resolved (status={record['status']})",
        )

    # Policy checks for MFA configuration
    policy = get_policy()
    approval_policy = policy.get("approval", {})
    require_mfa = approval_policy.get("require_mfa", True)
    require_separate_approver = approval_policy.get("require_separate_approver", True)

    requester = str(
        record.get("requested_by")
        or (record.get("metadata") or {}).get("requested_by")
        or ""
    ).strip()
    if not requester:
        append_approval_audit(
            record,
            action="approval_identity_missing",
            actor=approver,
            metadata={"control": "requester_identity_required"},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Approval requester identity is unavailable",
        )
    if require_separate_approver and requester.casefold() in approval_identity_aliases(user_payload):
        append_approval_audit(
            record,
            action="self_approval_rejected",
            actor=approver,
            metadata={"control": "separation_of_duties"},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The requesting actor cannot approve this action",
        )

    payload = await parse_approval_action_payload(request)
    body_present = bool(payload.pop("_body_present", False))
    comment = (payload.get("comment") or "").strip() or None

    from startup.audit import log_approval_event

    if require_mfa and not body_present:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MFA code is required"
        )

    mfa_verified = False
    mfa_binding_hash = None
    mfa_counter = None
    approved_at = datetime.now(timezone.utc)
    execution_expires_at = datetime.now(timezone.utc) + timedelta(minutes=_approval_execution_expiry_minutes())
    if require_mfa:
        deferred_failure = []
        try:
            from database import engine
            with tenant_context(
                int(record["tenant_id"]), request_id=str(record["request_id"]), required=True
            ), engine.begin() as conn:
                mfa_verified, mfa_binding_hash, mfa_counter = _verify_approval_stage_mfa(
                    record,
                    user_payload,
                    payload,
                    "approval",
                    record["expires_at"],
                    connection=conn,
                    deferred_failure=deferred_failure,
                )
                if mfa_verified:
                    record = approve_approval_atomic(
                        record,
                        approver=approver,
                        approved_at=approved_at,
                        mfa_verified=True,
                        mfa_binding_hash=mfa_binding_hash,
                        mfa_counter=mfa_counter,
                        execution_expires_at=execution_expires_at,
                        comment=comment,
                        audit_metadata={
                            "action_payload_hash": _approval_action_payload_hash(record),
                            "mfa_binding_hash": mfa_binding_hash,
                            "execution_expires_at": execution_expires_at.isoformat(),
                        },
                        connection=conn,
                    )
            if deferred_failure:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=deferred_failure[0],
                )
        except ApprovalStateConflict as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Approval request is already resolved (status={exc.current_status})",
            ) from exc
        except HTTPException as exc:
            log_approval_event(
                event="approval_mfa_failed",
                approval_id=record["approval_id"],
                request_id=record["request_id"],
                correlation_id=record["correlation_id"],
                extra={"error": str(exc.detail)}
            )
            append_approval_audit(
                record,
                action="approval_mfa_failed",
                actor=approver,
                metadata={"error": str(exc.detail)},
            )
            raise
        if not mfa_verified:
            log_approval_event(
                event="approval_mfa_failed",
                approval_id=record["approval_id"],
                request_id=record["request_id"],
                correlation_id=record["correlation_id"],
                extra={"error": "MFA_NOT_CONFIGURED"}
            )
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "error": "MFA_NOT_CONFIGURED",
                    "message": "MFA is not configured for this tenant."
                }
            )

    else:
        try:
            record = approve_approval_atomic(
                record,
                approver=approver,
                approved_at=approved_at,
                mfa_verified=False,
                mfa_binding_hash=mfa_binding_hash,
                mfa_counter=mfa_counter,
                execution_expires_at=execution_expires_at,
                comment=comment,
                audit_metadata={
                    "action_payload_hash": _approval_action_payload_hash(record),
                    "mfa_binding_hash": mfa_binding_hash,
                    "execution_expires_at": execution_expires_at.isoformat(),
                },
            )
        except ApprovalStateConflict as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Approval request is already resolved (status={exc.current_status})",
            ) from exc

    log_approval_event(
        event="approval_approved",
        approval_id=record["approval_id"],
        request_id=record["request_id"],
        correlation_id=record["correlation_id"],
        extra={"approved_at": record["approved_at"], "mfa_verified": mfa_verified}
    )

    # Create blockchain audit record for approval decision
    from verify_audit import create_audit_block
    create_audit_block(
        query=record["query"],
        response=f"Approval request approved. MFA validation passed.",
        allowed=True,
        risk_level=record["risk_level"],
        approval_status="approved",
        session_id=record["correlation_id"],
        approval_id=record["approval_id"],
        approver=approver,
        original_request=record["query"],
        approval_timestamp=datetime.fromisoformat(record["approved_at"]),
        execution_timestamp=None,
        execution_status="approved",
        tenant_id=record.get("tenant_id")
    )

    # Maintain backward compatibility in response format
    return {
        "message": "Request Approved",
        "approval_id": approval_id,
        "status": record["status"],
        "created_at": record["created_at"],
        "expires_at": record["expires_at"],
        "remaining_seconds": remaining_seconds(record),
        "data": record
    }



@app.post("/reject/{approval_id}")
async def reject_request(approval_id: str, request: Request):
    record = get_approval(approval_id, fresh=True)
    if record is None:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": "Approval ID not found"}
        )

    user_payload = optional_user_from_request(request)
    ensure_approval_tenant_access(record, user_payload)
    approver = approval_actor_from_payload(user_payload)
    payload = await parse_approval_action_payload(request)
    payload.pop("_body_present", None)
    comment = (payload.get("comment") or "").strip() or None

    if record["status"] != "pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Approval request is already resolved (status={record['status']})",
        )

    rejected_at = datetime.now(timezone.utc)
    try:
        record = reject_approval_atomic(
            record,
            actor=approver,
            rejected_at=rejected_at,
            comment=comment,
            audit_metadata={"reason": record.get("reason")},
        )
    except ApprovalStateConflict as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Approval request is already resolved (status={exc.current_status})",
        ) from exc

    from startup.audit import log_approval_event
    log_approval_event(
        event="approval_rejected",
        approval_id=record["approval_id"],
        request_id=record["request_id"],
        correlation_id=record["correlation_id"],
        extra={"rejected_at": record["rejected_at"]}
    )

    # Create blockchain audit record for rejection decision
    from verify_audit import create_audit_block
    create_audit_block(
        query=record["query"],
        response=f"Approval request explicitly rejected.",
        allowed=False,
        risk_level=record["risk_level"],
        approval_status="rejected",
        session_id=record["correlation_id"],
        approval_id=record["approval_id"],
        approver=approver,
        original_request=record["query"],
        approval_timestamp=None,
        execution_timestamp=datetime.fromisoformat(record["rejected_at"]),
        execution_status="rejected",
        tenant_id=record.get("tenant_id")
    )

    return {
        "message": "Request Rejected",
        "approval_id": approval_id,
        "status": record["status"],
        "created_at": record["created_at"],
        "expires_at": record["expires_at"],
        "remaining_seconds": remaining_seconds(record),
        "data": record
    }


@app.post("/execute/{approval_id}")
async def execute_request(approval_id: str, request: Request):
    record = get_approval(approval_id, fresh=True)
    if record is None:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": "Request not approved"} # Match legacy error message
        )

    user_payload = _approval_authenticated_payload(request)
    ensure_approval_tenant_access(record, user_payload)
    approver = approval_actor_from_payload(user_payload)
    payload = await parse_approval_action_payload(request)
    body_present = bool(payload.pop("_body_present", False))
    comment = (payload.get("comment") or "").strip() or None

    if record["status"] != "approved":
        if record["status"] in {
            "executing", "executed", "execution_failed", "execution_indeterminate"
        }:
            append_approval_audit(
                record,
                action="replay_rejected",
                actor=approver,
                metadata={"status": record["status"]},
            )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": f"Request not approved. Status is '{record['status']}'."}
        )

    if record.get("approved_by") and record.get("approved_by") != approver:
        append_approval_audit(
            record,
            action="transfer_rejected",
            actor=approver,
            metadata={"approved_by": record.get("approved_by")},
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Approval execution is bound to the approving actor.")

    now = datetime.now(timezone.utc)
    execution_window_expired = (
        not record.get("execution_expires_at")
        or now >= _utc_from_iso(record["execution_expires_at"])
    )
    if _approval_is_expired(record) or execution_window_expired:
        record, _ = expire_approved_execution_atomic(record, expired_at=now)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Approval request is already resolved (status={record['status']})",
        )

    if not body_present:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="MFA code is required")

    from startup.audit import log_approval_event
    execution_operation_id = secrets.token_hex(16)
    execution_token_hash = hashlib.sha256(execution_operation_id.encode("utf-8")).hexdigest()
    execution_worker_id = (
        f"{os.getenv('HOSTNAME') or 'agent'}:{os.getpid()}:{secrets.token_hex(8)}"
    )
    execution_fence_token = secrets.token_hex(16)
    transition_at = datetime.now(timezone.utc)
    deferred_failure = []
    try:
        from database import engine
        with tenant_context(
            int(record["tenant_id"]), request_id=str(record["request_id"]), required=True
        ), engine.begin() as conn:
            execution_mfa_verified, execution_mfa_binding_hash, execution_mfa_counter = _verify_approval_stage_mfa(
                record,
                user_payload,
                payload,
                "execution",
                record.get("execution_expires_at") or record["expires_at"],
                connection=conn,
                deferred_failure=deferred_failure,
            )
            if execution_mfa_verified:
                record = begin_approval_execution_atomic(
                    record,
                    actor=approver,
                    transition_at=transition_at,
                    execution_token_hash=execution_token_hash,
                    execution_operation_id=execution_operation_id,
                    execution_worker_id=execution_worker_id,
                    execution_fence_token=execution_fence_token,
                    reconcile_after=(
                        transition_at + timedelta(seconds=EXECUTION_LEASE_SECONDS)
                    ),
                    mfa_binding_hash=execution_mfa_binding_hash,
                    mfa_counter=execution_mfa_counter,
                    comment=comment,
                    audit_metadata={
                        "action_payload_hash": _approval_action_payload_hash(record),
                        "mfa_binding_hash": execution_mfa_binding_hash,
                        "execution_operation_id": execution_operation_id,
                    },
                    connection=conn,
                )
        if deferred_failure:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=deferred_failure[0],
            )
    except ApprovalStateConflict as exc:
        if exc.current_status != "expired":
            append_approval_audit(
                record,
                action="replay_rejected",
                actor=approver,
                metadata={"reason": "single_use_token_already_consumed"},
            )
        return JSONResponse(
            status_code=400,
            content={"error": f"Approval execution is already resolved (status={exc.current_status})."},
        )
    except HTTPException as exc:
        append_approval_audit(
            record,
            action="execution_mfa_failed",
            actor=approver,
            metadata={"error": str(exc.detail)},
        )
        log_approval_event(
            event="execution_mfa_failed",
            approval_id=record["approval_id"],
            request_id=record["request_id"],
            correlation_id=record["correlation_id"],
            extra={"error": str(exc.detail)}
        )
        raise
    if not execution_mfa_verified:
        append_approval_audit(
            record,
            action="execution_mfa_failed",
            actor=approver,
            metadata={"error": "MFA_NOT_CONFIGURED"},
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "MFA_NOT_CONFIGURED", "message": "MFA is not configured for this tenant."}
        )

    if record["status"] != "executing":
        append_approval_audit(
            record,
            action="replay_rejected",
            actor=approver,
            metadata={"reason": "single_use_token_already_consumed"},
        )
        return JSONResponse(status_code=400, content={"error": "Approval execution token already used."})

    query = record["query"]
    heartbeat = _ExecutionLeaseHeartbeat(record).start()

    # Execute the approved query through the canonical gateway lifecycle.
    try:
        if (record.get("metadata") or {}).get("execution_target") == "remediation":
            from services.remediation_runtime import RemediationRuntime
            remediation_result = RemediationRuntime().execute_approved_plan(
                record,
                idempotency_key=record["execution_operation_id"],
                pre_effect_check=heartbeat.assert_owned,
            )
            result = {"response": remediation_result.get("summary", "Remediation executed."), "remediation": remediation_result}
            execution = type("RemediationExecution", (), {
                "request_id": (
                    remediation_result.get("evidence", {}).get("provider_request_id")
                    or remediation_result.get("worker_run_id")
                ),
                "provider": remediation_result.get("provider"),
                "model": "remediation-worker",
                "route_id": remediation_result.get("connector_id"),
                "decision": "EXECUTED",
                "provider_operation_id": record["execution_operation_id"],
                "outcome": GatewayExecutionOutcome.SUCCEEDED,
                "trace": remediation_result.get("audit_events", []),
            })()
        else:
            service = get_gateway_service()
            execution = service.execute_approval(
                approval_record=record,
                x_api_key=request.headers.get("X-API-Key"),
                authorization=request.headers.get("Authorization"),
                idempotency_key=record["execution_operation_id"],
                pre_effect_check=heartbeat.assert_owned,
            )
            result = execution.result
    except ExecutionLeaseLostError as e:
        logger.warning(
            "Execution ownership lost for approval %s: %s",
            record.get("approval_id"),
            e,
        )
        heartbeat.stop()
        try:
            reconcile_late_approval_execution_outcome_atomic(
                record,
                actor="system:late-outcome-reconciler",
                transition_at=datetime.now(timezone.utc),
            )
        except ApprovalPersistenceError as reconcile_error:
            logger.error(
                "Late execution reconciliation failed for approval %s: %s",
                record.get("approval_id"),
                reconcile_error,
            )
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "status": "reconciliation_pending",
                "error": "execution_lease_lost",
            },
        )
    except GatewayProviderConfigurationError as e:
        logger.error(f"Provider configuration error in execute: {e}", exc_info=True)
        record = _finish_execution_with_lease(
            heartbeat,
            record,
            actor=approver,
            final_status="execution_failed",
            transition_at=datetime.now(timezone.utc),
            audit_metadata={
                "error": "provider_not_configured",
                "allowed": False,
                "executed": False,
                "outcome": "provider_configuration_error",
            },
            execution_outcome={
                "status": "failed",
                "error": "provider_not_configured",
                "outcome": "provider_configuration_error",
                "allowed": False,
                "executed": False,
            },
        )
        return JSONResponse(
            status_code=500,
            content={"error": "provider_not_configured"}
        )
    except GatewayProviderUnavailableError as e:
        logger.error(f"Provider invocation error in execute: {e}", exc_info=True)
        record = _finish_execution_with_lease(
            heartbeat,
            record,
            actor=approver,
            final_status="execution_indeterminate",
            transition_at=datetime.now(timezone.utc),
            audit_metadata={
                "error": "provider_unavailable",
                "request_id": e.request_id,
                "execution_operation_id": record.get("execution_operation_id"),
                "allowed": False,
                "executed": False,
                "outcome": "provider_unavailable",
            },
            provider_operation_id=e.provider_operation_id,
            execution_outcome={
                "status": "indeterminate",
                "error": "provider_unavailable",
                "outcome": "provider_unavailable",
                "allowed": False,
                "executed": False,
            },
        )
        return JSONResponse(
            status_code=503,
            content={
                "status": "provider_unavailable",
                "error": "provider_unavailable",
                "message": PROVIDER_UNAVAILABLE_MESSAGE,
                "request_id": e.request_id,
                "trace": e.trace,
            }
        )
    except Exception as e:
        logger.error(f"Execution failed: {e}", exc_info=True)
        record = _finish_execution_with_lease(
            heartbeat,
            record,
            actor=approver,
            final_status="execution_indeterminate",
            transition_at=datetime.now(timezone.utc),
            audit_metadata={
                "error": type(e).__name__,
                "execution_operation_id": record.get("execution_operation_id"),
                "allowed": False,
                "executed": False,
                "outcome": "execution_error",
            },
            execution_outcome={
                "status": "indeterminate",
                "error": type(e).__name__,
                "outcome": "execution_error",
                "allowed": False,
                "executed": False,
            },
        )
        raise

    if execution.outcome != GatewayExecutionOutcome.SUCCEEDED:
        denied = execution.outcome == GatewayExecutionOutcome.POLICY_DENIED
        outcome_name = execution.outcome.value
        record = _finish_execution_with_lease(
            heartbeat,
            record,
            actor=approver,
            final_status="execution_failed",
            transition_at=datetime.now(timezone.utc),
            comment=comment,
            mfa_verified=True,
            provider_operation_id=execution.provider_operation_id,
            execution_outcome={
                "status": "denied" if denied else "failed",
                "outcome": outcome_name,
                "decision": execution.decision,
                "provider": execution.provider,
                "allowed": False,
                "executed": False,
            },
            audit_metadata={
                "execution_request_id": execution.request_id,
                "provider": execution.provider,
                "model": execution.model,
                "execution_mfa_binding_hash": execution_mfa_binding_hash,
                "execution_operation_id": record.get("execution_operation_id"),
                "allowed": False,
                "executed": False,
                "outcome": outcome_name,
            },
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN if denied else status.HTTP_502_BAD_GATEWAY,
            content={
                "status": "denied" if denied else "execution_error",
                "allowed": False,
                "executed": False,
                "decision": execution.decision,
                "request_id": execution.request_id,
            },
        )

    record = _finish_execution_with_lease(
        heartbeat,
        record,
        actor=approver,
        final_status="executed",
        transition_at=datetime.now(timezone.utc),
        comment=comment,
        mfa_verified=True,
        provider_operation_id=execution.provider_operation_id,
        execution_outcome={
            "status": "succeeded",
            "outcome": "succeeded",
            "decision": execution.decision,
            "provider": execution.provider,
            "allowed": True,
            "executed": True,
        },
        audit_metadata={
            "execution_request_id": execution.request_id,
            "provider": execution.provider,
            "model": execution.model,
            "execution_mfa_binding_hash": execution_mfa_binding_hash,
            "execution_operation_id": record.get("execution_operation_id"),
            "allowed": True,
            "executed": True,
            "outcome": "succeeded",
        },
    )
    log_approval_event(
        event="approval_executed",
        approval_id=record["approval_id"],
        request_id=record["request_id"],
        correlation_id=record["correlation_id"],
        extra={
            "execution_request_id": execution.request_id,
        }
    )

    # Create blockchain audit record for execution
    app_ts = None
    if record.get("approved_at"):
        try:
            app_ts = datetime.fromisoformat(record["approved_at"])
        except Exception:
            pass

    from verify_audit import create_audit_block
    create_audit_block(
        query=query,
        response=result.get("response", "No response generated"),
        allowed=True,
        risk_level=record["risk_level"],
        approval_status="executed",
        session_id=record["correlation_id"],
        approval_id=record["approval_id"],
        approver=approver,
        original_request=query,
        approval_timestamp=app_ts,
        execution_timestamp=datetime.fromisoformat(record["executed_at"]),
        execution_status="executed",
        tenant_id=record.get("tenant_id")
    )

    return {
        "message": "Executed Successfully",
        "query": query,
        "response": result.get("response"),
        "request_id": execution.request_id,
        "provider": execution.provider,
        "model": execution.model,
        "route_id": execution.route_id,
        "decision": execution.decision,
        "trace": execution.trace,
    }


@app.post("/test/expire/{approval_id}")
def test_expire_approval(approval_id: str):
    record = get_approval(approval_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Approval ID not found")
    # Force expires_at to be in the past
    past_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    record["expires_at"] = past_time.isoformat()
    record["status"] = "pending"
    return {"message": "Approval simulated to expire", "record": record}


@app.get("/audit/verify")
def verify_audit(authorization: Optional[str] = Header(None)):
    tenant_id = resolve_tenant_from_authorization(authorization)
    correlation_id = str(uuid.uuid4())
    from startup.audit import log_audit_event
    log_audit_event(
        event="audit_verification_started",
        correlation_id=correlation_id
    )

    from verify_audit import verify_audit_chain
    res = verify_audit_chain(tenant_id=tenant_id)

    outcome = "passed" if res["valid"] is True else "failed" if res["valid"] is False else "unknown"
    log_audit_event(event=f"audit_verification_{outcome}", correlation_id=correlation_id,
                    extra={"records_checked": res["records_checked"]})
    return res


@app.get("/audit/verify/summary")
def verify_audit_summary(authorization: Optional[str] = Header(None)):
    tenant_id = resolve_tenant_from_authorization(authorization)
    from verify_audit import verify_audit_chain
    res = verify_audit_chain(tenant_id=tenant_id)

    if not res["valid"]:
        return {
            "valid": res["valid"],
            "status": "unknown" if res["valid"] is None else "degraded",
            "records_checked": res["records_checked"],
            "last_verified_record": res.get("failed_record_id"),
            "chain_started_at": None,
            "latest_hash": None
        }

    # Fetch the latest record ID and hash
    from database import engine
    from sqlalchemy import text
    with engine.connect() as conn:
        row = conn.execute(
            text("""
            SELECT id, integrity_hash
            FROM audit_logs
            WHERE integrity_hash IS NOT NULL AND tenant_id = :tenant_id
            ORDER BY id DESC
            LIMIT 1
            """),
            {"tenant_id": tenant_id}
        ).fetchone()

    last_verified_record = row[0] if row else 0
    latest_hash = row[1] if row else None

    return {
        "valid": True,
        "records_checked": res["records_checked"],
        "last_verified_record": last_verified_record,
        "chain_started_at": res["chain_started_at"],
        "latest_hash": latest_hash
    }


@app.get("/audit/hash-chain")
def get_audit_hash_chain(limit: int = 50, authorization: Optional[str] = Header(None)):
    tenant_id = resolve_tenant_from_authorization(authorization)
    from database import engine
    from sqlalchemy import text
    with engine.connect() as conn:
        res = conn.execute(
            text("""
            SELECT id, previous_hash, integrity_hash, created_at, approval_id, user_query,
                   approver, approval_status, original_request, approval_timestamp,
                   execution_timestamp, execution_status, tenant_id, username,
                   risk_level, allowed, response, policy_name, policy_type
            FROM audit_logs 
            WHERE integrity_hash IS NOT NULL
              AND tenant_id = :tenant_id
            ORDER BY id DESC 
            LIMIT :limit
            """),
            {"limit": limit, "tenant_id": tenant_id}
        )
        rows = res.fetchall()

    result = []
    for r in rows:
        created_at_str = r[3].isoformat() if hasattr(r[3], "isoformat") else str(r[3])
        result.append({
            "record_id": r[0],
            "previous_hash": r[1],
            "integrity_hash": r[2],
            "timestamp": created_at_str,
            "approval_id": r[4],
            "user_query": r[5],
            "approver": r[6],
            "approval_status": r[7],
            "original_request": r[8] or r[5],
            "approval_timestamp": r[9].isoformat() if hasattr(r[9], "isoformat") else (str(r[9]) if r[9] else None),
            "execution_timestamp": r[10].isoformat() if hasattr(r[10], "isoformat") else (str(r[10]) if r[10] else None),
            "execution_status": r[11] or r[7],
            "status": r[11] or r[7],
            "tenant_id": r[12],
            "username": r[13],
            "risk_level": r[14],
            "allowed": r[15],
            "response": r[16],
            "security_decision": "ALLOW" if r[15] else "BLOCK",
            "policy_decision": r[17] or r[18] or r[7],
            "provider": None,
            "hash_reference": r[2]
        })
    return result


@app.post("/v1/chat/completions")
def chat_completions(
    request: ChatCompletionRequest,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
    x_session_id: Optional[str] = Header(None)
):
    # API Key Authentication
    api_key_val = None
    if authorization:
        if authorization.startswith("Bearer "):
            api_key_val = authorization[7:]
        else:
            api_key_val = authorization
    elif x_api_key:
        api_key_val = x_api_key

    tenant_id = resolve_tenant(api_key_val, authorization)

    if not request.messages:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Messages list cannot be empty"
        )

    last_msg = request.messages[-1]
    if last_msg.role != "user":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Last message must be from user"
        )

    user_query = last_msg.content
    session_id = x_session_id or f"session-{uuid.uuid4()}"

    # Pre-populate history in database if currently empty
    db_history = get_history(session_id)
    if not db_history:
        for msg in request.messages[:-1]:
            add_message(session_id, msg.role, msg.content)

    service = get_gateway_service()
    try:
        execution = service.execute_chat(
            message=user_query,
            session_id=session_id,
            x_api_key=api_key_val,
            authorization=authorization,
            model=request.model or "authclaw-gateway",
        )
    except GatewayProviderConfigurationError as e:
        logger.error(f"Provider configuration error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "type": "provider_not_configured",
                    "message": "Model provider is not configured."
                }
            }
        )
    except GatewayProviderUnavailableError as e:
        logger.error(f"Error executing graph pipeline: {e}", exc_info=True)
        return JSONResponse(
            status_code=503,
            content={
                "error": {
                    "type": "provider_unavailable",
                    "message": PROVIDER_UNAVAILABLE_MESSAGE,
                    "request_id": e.request_id,
                    "trace": e.trace,
                },
            }
        )

    result = execution.result
    if not result.get("allowed", True):
        logger.warning("Request blocked by policy: request_id=%s", execution.request_id)
        category = result.get("block_category", "data_exfiltration")
        service.format_chat_response(execution)
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "request_id": execution.request_id,
                "error": {
                    "message": "Request blocked by policy engine",
                    "type": "policy_violation",
                    "category": category
                }
            }
        )

    if result.get("approval_status") == "PENDING_APPROVAL":
        approval_id = result.get("approval_id")
        logger.info(f"Request flagged for approval. ID: {approval_id}")
        service.format_chat_response(execution)
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content={
                "request_id": execution.request_id,
                "approval_id": approval_id,
                "status": "pending_approval",
                "message": "High-risk request requires approval."
            }
        )

    response_text = result.get("response", "No response generated")
    response_model = execution.model or request.model or "authclaw-gateway"

    if request.stream:
        return StreamingResponse(
            _openai_completion_stream(
                content=response_text,
                model=response_model,
                request_id=execution.request_id,
                tenant_id=execution.tenant_id,
                trace=execution.trace,
            ),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    response_payload = {
        "id": f"chatcmpl-{uuid.uuid4()}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": response_model,
        "request_id": execution.request_id,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": response_text
                },
                "finish_reason": "stop"
            }
        ]
    }
    return response_payload




@app.get("/policies")
def get_policies_endpoint():
    try:
        policy = get_policy()
        return policy
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve policies: {str(e)}"
        )


@app.post("/policies/reload")
def reload_policies_endpoint():
    try:
        new_policy = load_policy()
        reload_log = {
            "event": "policy_reload",
            "status": "success",
            "message": "Policies reloaded successfully.",
            "details": {
                "version": new_policy.get("version")
            }
        }
        logger.info(json.dumps(reload_log))
        print(json.dumps(reload_log), flush=True)

        # Create blockchain audit block for policy modification
        from verify_audit import create_audit_block
        create_audit_block(
            query="reload policies",
            response=f"Policies reloaded successfully. Version: {new_policy.get('version')}",
            allowed=True,
            risk_level="LOW",
            approval_status="N/A",
            session_id="system"
        )

        return {
            "message": "Policies reloaded successfully",
            "policies": new_policy
        }
    except Exception as e:
        reload_log = {
            "event": "policy_reload",
            "status": "failed",
            "error_type": type(e).__name__,
        }
        logger.error(json.dumps(reload_log))
        print(json.dumps(reload_log), flush=True)
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "error": "Failed to reload policies",
                "details": "Policy reload failed"
            }
        )


@app.get("/api/v1/agent/health")
@app.get("/health")
def get_health():
    return {"status": "alive", "scope": "process_liveness"}


@app.get("/internal/metrics/quota", include_in_schema=False)
def get_quota_metrics(authorization: str = Header(None)):
    expected = os.getenv("AUTHCLAW_QUOTA_METRICS_SECRET", "").strip()
    if not expected:
        raise HTTPException(status_code=503, detail="Metrics authentication unavailable.")
    scheme, _, provided = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not secrets.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="Metrics authentication failed.")
    snapshot = metrics_snapshot()
    names = {
        "available": "authclaw_quota_available",
        "admitted": "authclaw_quota_admitted_total",
        "rejected": "authclaw_quota_rejected_total",
        "unavailable": "authclaw_quota_unavailable_total",
        "ambiguous": "authclaw_quota_ambiguous_total",
        "latency_seconds": "authclaw_quota_latency_seconds_sum",
        "decisions": "authclaw_quota_decisions_total",
    }
    lines = [f"{name} {snapshot[key]}\n" for key, name in names.items()]
    monitor = monitor_metrics_snapshot()
    lines.extend([
        f"authclaw_document_monitor_enabled {monitor['enabled']}\n",
        f"authclaw_document_monitor_healthy {monitor['healthy']}\n",
        f"authclaw_document_monitor_failures_total {monitor['failures_total']}\n",
        f"authclaw_document_monitor_last_success_timestamp_seconds {monitor['last_success_timestamp_seconds']}\n",
    ])
    return Response("".join(lines), media_type="text/plain; version=0.0.4")


@app.get("/health/details")
def get_health_details():
    readiness = get_readiness()
    payload = json.loads(readiness.body)
    return JSONResponse(status_code=readiness.status_code, content={
        "status": payload["health_status"],
        "scope": "agent_readiness",
        "checks": payload["checks"],
        "unmeasured": ["provider", "audit_chain", "hitl", "policy_enforcement", "redaction"],
        "audit_chain_active": None,
        "hitl_enabled": None,
        "policy_enforcement_enabled": None,
        "redaction_enabled": None,
        "provider_status": "unknown",
        "database_status": "unavailable" if payload["checks"]["database"] == "unhealthy" else payload["checks"]["database"],
    })


@app.get("/api/v1/agent/health/ready")
@app.get("/health/ready")
def get_readiness():
    checks = {
        "database": "unknown",
        "production_validation": "not_applicable",
        "document_storage": os.getenv("AUTHCLAW_DOCUMENT_STORAGE_BACKEND", "local"),
        "rbac_enforcement": "enabled" if _rbac_enforcement_enabled() else "disabled",
    }
    http_status = 200
    try:
        check_available()
        checks["rate_limiter"] = "healthy"
    except Exception:
        checks["rate_limiter"] = "unhealthy"
        http_status = 503
    try:
        validate_database_security()
        checks["database"] = "healthy"
    except Exception:
        checks["database"] = "unhealthy"
        http_status = 503

    if os.getenv("AUTHCLAW_ENV", "development").lower() in {"production", "prod"}:
        from startup.validation import validate_production_environment
        try:
            validation_errors = validate_production_environment()
        except Exception:
            validation_errors = ["Production validation unavailable"]
        if validation_errors:
            checks["production_validation"] = "failed"
            checks["production_errors"] = validation_errors
            http_status = 503
        else:
            checks["production_validation"] = "passed"

    return JSONResponse(status_code=http_status, content={"status": "ready" if http_status == 200 else "not_ready", "health_status": "healthy" if http_status == 200 else "unavailable", "checks": checks})


@app.get("/trust/public/health")
def get_public_trust_health():
    from services.trust_center_runtime import trust_runtime_health

    result = trust_runtime_health()
    status_code = 503 if result.get("status") == "unavailable" else 200
    return JSONResponse(status_code=status_code, content=jsonable_encoder(result))


@app.get("/metrics")
def get_metrics():
    from database import engine
    from sqlalchemy import text
    try:
        with engine.connect() as conn:
            total_requests = conn.execute(text("SELECT COUNT(*) FROM gateway_requests")).scalar() or 0
            blocked_requests = conn.execute(text("SELECT COUNT(*) FROM gateway_requests WHERE allowed = FALSE")).scalar() or 0
            avg_latency = conn.execute(text("SELECT CASE WHEN COUNT(*) = COUNT(CASE WHEN latency_recorded THEN COALESCE(duration_ms, latency) END) THEN AVG(COALESCE(duration_ms, latency)) END FROM gateway_requests")).scalar()
            avg_latency = float(avg_latency) if avg_latency is not None else None
            
            token_consumption = conn.execute(text("SELECT CASE WHEN COUNT(*) = COUNT(CASE WHEN token_usage_recorded THEN tokens_in + tokens_out END) THEN COALESCE(SUM(tokens_in + tokens_out), 0) END FROM gateway_requests")).scalar()
            
            active_tenants = conn.execute(text("SELECT COUNT(*) FROM tenants WHERE status = 'active' AND id = :tenant_id"), {"tenant_id": get_current_tenant_id()}).scalar() or 0
            active_routes = conn.execute(text("SELECT COUNT(*) FROM gateway_routes WHERE enabled = TRUE")).scalar() or 0
            active_policies = conn.execute(text("SELECT COUNT(*) FROM policies WHERE enabled = TRUE")).scalar() or 0
            open_findings = conn.execute(text("SELECT COUNT(*) FROM remediation_findings WHERE approval_status = 'pending'")).scalar() or 0
            active_workers = conn.execute(text("SELECT COUNT(*) FROM ephemeral_workers WHERE status = 'running'")).scalar() or 0
            audit_chain_records = conn.execute(text("SELECT COUNT(*) FROM audit_logs WHERE integrity_hash IS NOT NULL")).scalar() or 0

            # Document Intelligence Database Aggregations
            total_documents = conn.execute(text("SELECT COUNT(*) FROM documents")).scalar() or 0
            total_findings = conn.execute(text("SELECT COUNT(*) FROM document_findings")).scalar() or 0
            total_violations = conn.execute(text("SELECT COUNT(*) FROM document_findings WHERE finding_type = 'Regulatory'")).scalar() or 0
            evidence_count = conn.execute(text("SELECT COUNT(*) FROM compliance_evidence")).scalar() or 0

            scanned_today = conn.execute(text("SELECT COUNT(*) FROM documents WHERE created_at >= CURRENT_DATE")).scalar() or 0
            drift_alerts = conn.execute(text("SELECT COUNT(*) FROM compliance_drift_alerts WHERE tenant_id = :tenant_id"), {"tenant_id": get_current_tenant_id()}).scalar() or 0
            secret_leaks = conn.execute(text("SELECT COUNT(*) FROM document_findings WHERE finding_type IN ('Secret', 'Credentials')")).scalar() or 0
            pii_violations = conn.execute(text("SELECT COUNT(*) FROM document_findings WHERE finding_type = 'PII'")).scalar() or 0
            provider_errors = conn.execute(text("""
                SELECT COUNT(*)
                FROM gateway_requests
                WHERE lower(COALESCE(status, decision, '')) LIKE '%error%'
                   OR lower(COALESCE(status, decision, '')) LIKE '%fail%'
                   OR lower(COALESCE(status, decision, '')) LIKE '%unavailable%'
                   OR lower(COALESCE(status, decision, '')) LIKE '%timeout%'
            """)).scalar() or 0
            approval_latency_row = conn.execute(text("""
                SELECT AVG(EXTRACT(EPOCH FROM (COALESCE(executed_at, approved_at, rejected_at, last_action_at, NOW()) - created_at)))
                FROM gateway_approvals
                WHERE created_at IS NOT NULL
            """)).fetchone()
            avg_approval_latency_seconds = float(approval_latency_row[0]) if approval_latency_row and approval_latency_row[0] is not None else None
            rate_limit_blocked = conn.execute(text("SELECT COUNT(*) FROM rate_limit_events WHERE allowed = FALSE AND created_at >= NOW() - INTERVAL '1 hour'")).scalar() or 0
            worker_throttle_blocked = conn.execute(text("SELECT COUNT(*) FROM worker_throttle_events WHERE allowed = FALSE AND created_at >= NOW() - INTERVAL '1 hour'")).scalar() or 0

            risk_res = conn.execute(text("SELECT risk_level, COUNT(*) FROM gateway_requests GROUP BY risk_level")).fetchall()
            risk_dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "UNKNOWN": 0}
            for row in risk_res:
                lvl = row[0].upper() if row[0] else "UNKNOWN"
                risk_dist[lvl if lvl in risk_dist else "UNKNOWN"] += row[1]
                    
            # Framework scores are calculated by the canonical compliance API, not this counter endpoint.
            from services.event_pipeline import EventPipeline
            from verify_audit import verify_audit_chain
            event_pipeline_metrics = EventPipeline().delivery_metrics()
            audit_chain_status = verify_audit_chain(tenant_id=get_current_tenant_id())
            approval_counts = dict(conn.execute(text("SELECT lower(status), COUNT(*) FROM gateway_approvals GROUP BY lower(status)")).fetchall())
            
    except Exception as e:
        logger.error("Telemetry source failed (%s)", type(e).__name__)
        return JSONResponse(status_code=503, content={
            "status": "unavailable", "error": "telemetry_source_unavailable",
            "avg_latency": None, "gateway_latency_ms": None, "compliance_score": None,
            "compliance_status": "unavailable", "compliance_authoritative": False,
            "audit_chain_status": {"status": "unavailable", "valid": None, "records_checked": None},
        })

    from services.observability_service import ObservabilityService, aggregate_health
    queue = ObservabilityService()._queue_lag(event_pipeline_metrics)
    redaction_rate = round((pii_violations + secret_leaks) / total_requests, 4) if total_requests else None

    return {
        "total_requests": total_requests,
        "status": aggregate_health(
            "unknown" if audit_chain_status.get("valid") is None else "healthy" if audit_chain_status["valid"] else "degraded",
            queue["status"],
        ),
        "compliance_status": "unknown",
        "blocked_requests": blocked_requests,
        "pending_approvals": approval_counts.get("pending", 0),
        "executed_approvals": approval_counts.get("executed", 0),
        "approved_approvals": approval_counts.get("approved", 0),
        "rejected_approvals": approval_counts.get("rejected", 0),
        "audit_chain_records": audit_chain_records,
        "risk_distribution": risk_dist,
        "avg_latency": avg_latency,
        "gateway_latency_ms": avg_latency,
        "redaction_rate": redaction_rate,
        "provider_errors": provider_errors,
        "avg_approval_latency_seconds": avg_approval_latency_seconds,
        "queue_status": queue["status"],
        "queue_lag_seconds": queue["max_lag_seconds"],
        "queue_pending_events": queue["pending_events"],
        "dead_letter_events": queue["dead_letter_count"],
        "audit_chain_status": audit_chain_status,
        "event_pipeline": event_pipeline_metrics,
        "rate_limit_blocked": rate_limit_blocked,
        "rate_limiter": metrics_snapshot(),
        "worker_throttle_blocked": worker_throttle_blocked,
        "token_consumption": token_consumption,
        "active_tenants": active_tenants,
        "active_routes": active_routes,
        "active_policies": active_policies,
        "compliance_score": None,
        "compliance_authoritative": False,
        "compliance_score_kind": "diagnostic",
        "compliance_calculation_version": "agent-diagnostic-v2",
        "compliance_evidence_gaps": ["Aggregate activity metrics do not qualify control assessments."],
        "open_findings": open_findings,
        "active_workers": active_workers,
        
        # New Document Intelligence metrics
        "total_documents": total_documents,
        "total_findings": total_findings,
        "total_violations": total_violations,
        "evidence_count": evidence_count,
        "scanned_today": scanned_today,
        "drift_alerts": drift_alerts,
        "secret_leaks": secret_leaks,
        "pii_violations": pii_violations
    }


@app.post("/observability/pipeline/retry")
def retry_event_pipeline_dead_letters(
    limit: int = 100,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    from services.event_pipeline import EventPipeline

    tenant_id = resolve_tenant(x_api_key, authorization)
    result = EventPipeline().retry_dead_letters(limit=max(1, min(limit, 1000)))
    result["tenant_id"] = tenant_id
    return result


@app.get("/platform/summary")
def get_platform_summary(_: dict = Depends(require_platform_admin)):
    from database import engine
    from sqlalchemy import text

    with engine.connect() as conn:
        total_tenants = conn.execute(text("SELECT COUNT(*) FROM tenants")).scalar() or 0
        active_tenants = conn.execute(
            text("SELECT COUNT(*) FROM tenants WHERE COALESCE(status, 'active') = 'active'")
        ).scalar() or 0
        total_users = conn.execute(text("SELECT COUNT(*) FROM tenant_users")).scalar() or 0
        platform_admins = conn.execute(
            text("SELECT COUNT(*) FROM tenant_users WHERE role = 'Platform Admin'")
        ).scalar() or 0
        total_requests = conn.execute(text("SELECT COUNT(*) FROM gateway_requests")).scalar() or 0
        blocked_requests = conn.execute(
            text("""
                SELECT COUNT(*)
                FROM gateway_requests
                WHERE allowed = FALSE OR lower(COALESCE(decision, status, '')) LIKE '%block%'
            """)
        ).scalar() or 0
        pending_approvals = conn.execute(
            text("SELECT COUNT(*) FROM gateway_approvals WHERE lower(COALESCE(status, '')) = 'pending'")
        ).scalar() or 0
        provider_rows = conn.execute(
            text("""
                SELECT COALESCE(NULLIF(provider, ''), 'unknown') AS provider, COUNT(*)
                FROM gateway_requests
                GROUP BY COALESCE(NULLIF(provider, ''), 'unknown')
                ORDER BY COUNT(*) DESC
                LIMIT 8
            """)
        ).fetchall()

    return {
        "total_tenants": total_tenants,
        "active_tenants": active_tenants,
        "total_users": total_users,
        "platform_admins": platform_admins,
        "total_gateway_requests": total_requests,
        "blocked_gateway_requests": blocked_requests,
        "pending_approvals": pending_approvals,
        "provider_usage": {row[0]: row[1] for row in provider_rows},
    }


@app.get("/platform/tenants")
def list_platform_tenants(limit: int = 100, _: dict = Depends(require_platform_admin)):
    from database import engine
    from sqlalchemy import text

    safe_limit = max(1, min(limit, 250))
    with engine.connect() as conn:
        rows = conn.execute(
            text("""
                SELECT
                    t.id,
                    t.name,
                    t.domain,
                    t.email,
                    COALESCE(t.status, 'active') AS status,
                    COALESCE(t.email_verified, false) AS email_verified,
                    COALESCE(t.domain_verified, false) AS domain_verified,
                    t.created_at,
                    COUNT(DISTINCT u.id) AS users_count,
                    COUNT(DISTINCT k.id) AS api_keys_count,
                    COUNT(DISTINCT s.id) AS provider_credentials_count,
                    COUNT(DISTINCT gr.id) AS gateway_requests_count
                FROM tenants t
                LEFT JOIN tenant_users u ON u.tenant_id = t.id
                LEFT JOIN tenant_api_keys k ON k.tenant_id = t.id AND k.revoked_at IS NULL
                LEFT JOIN secrets s ON s.tenant_id = t.id
                LEFT JOIN gateway_requests gr ON gr.tenant_id::text = t.id::text
                GROUP BY t.id, t.name, t.domain, t.email, t.status, t.email_verified, t.domain_verified, t.created_at
                ORDER BY t.created_at DESC NULLS LAST, t.id DESC
                LIMIT :limit
            """),
            {"limit": safe_limit},
        ).fetchall()

    return [
        {
            "id": row[0],
            "name": row[1],
            "domain": row[2],
            "email": row[3],
            "status": row[4],
            "email_verified": row[5],
            "domain_verified": row[6],
            "created_at": row[7].isoformat() if row[7] else None,
            "users_count": row[8],
            "api_keys_count": row[9],
            "provider_credentials_count": row[10],
            "gateway_requests_count": row[11],
        }
        for row in rows
    ]


# --- NEW COMPONENTS SCHEMA DEFINITIONS ---

class RouteRequest(BaseModel):
    name: str
    provider: str
    endpoint: str
    model: str
    rate_limit: int
    redaction_enabled: bool
    enabled: bool
    tenant_assignment: str

class TenantRequest(BaseModel):
    name: str
    status: str


def is_valid_work_email(value: str) -> bool:
    email = (value or "").strip()
    if any(char.isspace() for char in email) or email.count("@") != 1:
        return False
    local, domain = email.split("@", 1)
    return bool(local and domain and "." in domain and not domain.startswith(".") and not domain.endswith("."))



class PolicyRequest(BaseModel):
    name: str
    type: str
    rules: str
    enabled: bool
    status: Optional[str] = None
    severity_level: Optional[str] = None

class PolicySimulationRequest(BaseModel):
    name: Optional[str] = "Simulation Policy"
    type: Optional[str] = "Custom"
    rules: str
    enabled: Optional[bool] = True
    severity_level: Optional[str] = "MEDIUM"
    sample_text: str

class GatewayPolicyEvaluationRequest(BaseModel):
    method: str
    path: str
    request_id: Optional[str] = None
    body: Optional[Any] = None
    body_raw: Optional[str] = None

def policy_rules_checksum(rules: Dict[str, Any]) -> str:
    canonical = json.dumps(rules or {}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

def policy_actor_from_authorization(authorization: Optional[str]) -> str:
    try:
        payload = get_current_user_from_authorization(authorization)
        return payload.get("email") or payload.get("sub") or "system"
    except Exception:
        return "system"

def persist_policy_version(
    conn,
    tenant_id: int,
    policy_id: int,
    version: int,
    status_value: str,
    rules: Dict[str, Any],
    actor: str,
    approver: Optional[str] = None,
    changelog: Optional[str] = None,
) -> Optional[int]:
    checksum = policy_rules_checksum(rules)
    row = conn.execute(
        text("""
            INSERT INTO policy_versions (
                tenant_id, policy_id, version, status, rules, checksum,
                author, approver, changelog, created_at, approved_at, published_at
            )
            VALUES (
                :tenant_id, :policy_id, :version, :status, :rules, :checksum,
                :author, :approver, :changelog, NOW(),
                CASE WHEN :status IN ('approved', 'published') THEN NOW() ELSE NULL END,
                CASE WHEN :status = 'published' THEN NOW() ELSE NULL END
            )
            ON CONFLICT (policy_id, version) DO UPDATE
            SET status = EXCLUDED.status,
                rules = EXCLUDED.rules,
                checksum = EXCLUDED.checksum,
                approver = COALESCE(EXCLUDED.approver, policy_versions.approver),
                changelog = COALESCE(EXCLUDED.changelog, policy_versions.changelog),
                approved_at = CASE
                    WHEN EXCLUDED.status IN ('approved', 'published') THEN COALESCE(policy_versions.approved_at, NOW())
                    ELSE policy_versions.approved_at
                END,
                published_at = CASE
                    WHEN EXCLUDED.status = 'published' THEN COALESCE(policy_versions.published_at, NOW())
                    ELSE policy_versions.published_at
                END
            RETURNING id
        """),
        {
            "tenant_id": tenant_id,
            "policy_id": policy_id,
            "version": version,
            "status": status_value,
            "rules": json.dumps(rules),
            "checksum": checksum,
            "author": actor,
            "approver": approver,
            "changelog": changelog,
        },
    ).fetchone()
    return int(row[0]) if row else None

def persist_policy_change_approval(
    conn,
    tenant_id: int,
    policy_id: int,
    version_id: Optional[int],
    status_value: str,
    requested_by: str,
    reviewed_by: Optional[str] = None,
    comments: Optional[str] = None,
) -> None:
    conn.execute(
        text("""
            INSERT INTO policy_change_approvals (
                tenant_id, policy_id, version_id, status, requested_by,
                reviewed_by, comments, created_at, decided_at
            )
            VALUES (
                :tenant_id, :policy_id, :version_id, :status, :requested_by,
                :reviewed_by, :comments, NOW(),
                CASE WHEN :status IN ('approved', 'rejected') THEN NOW() ELSE NULL END
            )
        """),
        {
            "tenant_id": tenant_id,
            "policy_id": policy_id,
            "version_id": version_id,
            "status": status_value,
            "requested_by": requested_by,
            "reviewed_by": reviewed_by,
            "comments": comments,
        },
    )

def extract_policy_text_from_gateway_payload(payload: GatewayPolicyEvaluationRequest) -> str:
    body = payload.body
    if isinstance(body, dict):
        if isinstance(body.get("message"), str):
            return body["message"]
        messages = body.get("messages")
        if isinstance(messages, list):
            for item in reversed(messages):
                if isinstance(item, dict) and item.get("role") == "user":
                    content = item.get("content")
                    if isinstance(content, str):
                        return content
        prompt = body.get("prompt")
        if isinstance(prompt, str):
            return prompt
        return json.dumps(body, sort_keys=True)
    if isinstance(payload.body_raw, str) and payload.body_raw.strip():
        return payload.body_raw
    if isinstance(body, str):
        return body
    return ""

class DocumentUploadRequest(BaseModel):
    name: str
    type: str
    size_bytes: int

class ComplianceAnalyzeRequest(BaseModel):
    document_id: str

class DocumentChatRequest(BaseModel):
    document_id: str
    question: str



class UserRoleRequest(BaseModel):
    username: str
    role: str
    permissions: str



class EvidenceUploadRequest(BaseModel):
    name: str
    category: str
    file_path: str


class SignedExportVerifyRequest(BaseModel):
    payload: Optional[Dict[str, Any]] = None
    payload_b64: Optional[str] = None
    manifest: Dict[str, Any]


class PolicyBundlePromotionRequest(BaseModel):
    bundle_id: str


class TenantPlanUpdateRequest(BaseModel):
    plan: str
    override_reason: Optional[str] = None


# --- NEW COMPONENTS ENDPOINTS IMPLEMENTATIONS ---

@app.post("/internal/policy/evaluate")
def evaluate_gateway_policy(
    payload: GatewayPolicyEvaluationRequest,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
    x_authclaw_gateway_request_id: Optional[str] = Header(None),
):
    from database import engine
    from services.policy_engine import ACTION_BLOCK, PolicyEngine
    started_at = time.time()
    tenant_id = resolve_tenant(x_api_key, authorization)
    actor = "api-client"
    if authorization:
        actor = policy_actor_from_authorization(authorization)
    request_id = payload.request_id or x_authclaw_gateway_request_id or f"policy-{uuid.uuid4()}"
    text_value = extract_policy_text_from_gateway_payload(payload)
    opa_result = evaluate_opa_policy(
        text_value,
        tenant_id=tenant_id,
        context={"path": payload.path, "method": payload.method, "request_id": request_id, "actor": actor},
    )
    if opa_result:
        matched_policies = opa_result.get("findings") or [
            {
                "policy_name": "OPA Policy",
                "category": opa_result.get("category", "opa"),
                "action": opa_result.get("decision", "ALLOW"),
                "confidence": "enterprise-rego",
            }
        ]
        decision = opa_result.get("decision", "ALLOW")
        allowed = bool(opa_result.get("allowed", True))
        reason = opa_result.get("reason", "OPA policy decision")
        risk_level = opa_result.get("risk_level") or ("HIGH" if decision in {"BLOCK", "REQUIRE_APPROVAL"} else "LOW")
        policy_versions = [{"engine": "opa", "status": "evaluated"}]
    else:
        result = PolicyEngine().evaluate(text_value, tenant_id=tenant_id, username=actor)
        matched_policies = [
            {
                "policy_id": finding.get("policy_id"),
                "policy_name": finding.get("policy_name"),
                "category": finding.get("category"),
                "action": finding.get("action"),
                "confidence": finding.get("confidence"),
            }
            for finding in result.findings
        ]
        decision = "BLOCK" if result.action == ACTION_BLOCK else result.action
        allowed = result.action != ACTION_BLOCK
        reason = result.reason
        risk_level = result.risk_level
        policy_versions = result.policy_versions
    duration_ms = int((time.time() - started_at) * 1000)
    response_payload = {
        "status": "evaluated",
        "decision": decision,
        "allowed": allowed,
        "enforcement": "fail_closed",
        "matched_policies": matched_policies,
        "policy_versions": policy_versions,
        "evaluation_time_ms": duration_ms,
        "explanation": reason,
        "reason": reason,
        "risk_level": risk_level,
        "request_id": request_id,
        "tenant_id": tenant_id,
    }
    with engine.connect() as conn:
        conn.execute(
            text("""
                INSERT INTO policy_evaluation_audit (
                    tenant_id, request_id, route_path, decision, reason,
                    evaluation_time_ms, matched_policies, policy_versions, created_at
                )
                VALUES (
                    :tenant_id, :request_id, :route_path, :decision, :reason,
                    :evaluation_time_ms, :matched_policies, :policy_versions, NOW()
                )
            """),
            {
                "tenant_id": tenant_id,
                "request_id": request_id,
                "route_path": payload.path,
                "decision": decision,
                "reason": reason,
                "evaluation_time_ms": duration_ms,
                "matched_policies": json.dumps(matched_policies, default=str),
                "policy_versions": json.dumps(policy_versions, default=str),
            },
        )
        conn.commit()
    return response_payload


# 6. RAG DOCUMENTS
@app.get("/rag/documents")
def get_documents(
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    from database import engine
    from sqlalchemy import text
    tenant_id = resolve_tenant(x_api_key, authorization)
    with engine.connect() as conn:
        res = conn.execute(
            text("""
                SELECT id, name, type, size_bytes, status, last_indexed, chunks_count
                FROM knowledge_documents
                WHERE tenant_id = :tenant_id
                ORDER BY id DESC
            """),
            {"tenant_id": tenant_id}
        )
        return [dict(r._mapping) for r in res]

@app.post("/rag/documents")
def create_document(
    doc: DocumentUploadRequest,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    from database import engine
    from sqlalchemy import text
    from verify_audit import create_audit_block
    from rag.embeddings import generate_embedding
    tenant_id = resolve_tenant(x_api_key, authorization)
    today = datetime.now(timezone.utc).date().isoformat()
    chunks_count = max(1, int(doc.size_bytes // 50000))
    with engine.begin() as conn:
        res = conn.execute(
            text("""
            INSERT INTO knowledge_documents (tenant_id, name, type, size_bytes, status, last_indexed, chunks_count)
            VALUES (:tenant_id, :name, :type, :size_bytes, 'indexed', :last_indexed, :chunks_count)
            RETURNING id
            """),
            {
                "tenant_id": tenant_id,
                "name": doc.name,
                "type": doc.type,
                "size_bytes": doc.size_bytes,
                "last_indexed": today,
                "chunks_count": chunks_count
            }
        )
        inserted_id = res.fetchone()[0]

        # Insert chunks and generate actual embeddings
        for i in range(chunks_count):
            content_text = f"Document chunk {i+1} from {doc.name}. Contains policy compliance vectors for {doc.type} files."
            vector = generate_embedding(content_text)
            conn.execute(
                text("""
                INSERT INTO knowledge_chunks (tenant_id, document_id, content, embedding_preview, embedding_vector)
                VALUES (:tenant_id, :doc_id, :content, :emb, :vec)
                """),
                {
                    "tenant_id": tenant_id,
                    "doc_id": inserted_id,
                    "content": content_text,
                    "emb": f"[{round(0.1*i,2)}, {round(-0.15*i,2)}, ...]",
                    "vec": json.dumps(vector)
                }
            )
    create_audit_block(
        query=f"Upload Knowledge Document: {doc.name}",
        response=f"Document uploaded and indexed successfully into {chunks_count} vector chunks.",
        allowed=True,
        risk_level="LOW",
        approval_status="N/A",
        tenant_id=tenant_id
    )
    return {"status": "success", "message": "Document uploaded and indexed successfully."}

def parse_document_id(doc_id_str: str) -> int:
    if doc_id_str.startswith("doc_"):
        return int(doc_id_str[4:])
    try:
        return int(doc_id_str)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid document ID format. Must be like 'doc_123' or '123'")

def resolve_document_record(conn, doc_id: int, tenant_id: int):
    from sqlalchemy import text

    row = conn.execute(
        text("SELECT id, filename FROM documents WHERE id = :id AND tenant_id = :tenant_id"),
        {"id": doc_id, "tenant_id": tenant_id}
    ).fetchone()
    if row:
        return row

    k_doc = conn.execute(
        text("SELECT name FROM knowledge_documents WHERE id = :id AND tenant_id = :tenant_id"),
        {"id": doc_id, "tenant_id": tenant_id}
    ).fetchone()
    if not k_doc:
        return None

    return conn.execute(
        text("SELECT id, filename FROM documents WHERE filename = :name AND tenant_id = :tenant_id ORDER BY id DESC LIMIT 1"),
        {"name": k_doc[0], "tenant_id": tenant_id}
    ).fetchone()

@app.post("/documents/upload")
async def upload_document(
    request: Request,
    file: UploadFile = File(...),
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)

    contents = await file.read()
    filename = file.filename
    size_bytes = len(contents)

    from database import engine
    from sqlalchemy import text
    from datetime import datetime, timezone

    # 1. Register document in documents table first
    with engine.connect() as conn:
        res = conn.execute(
            text("""
            INSERT INTO documents (tenant_id, filename, source, size_bytes, status, risk_score, severity)
            VALUES (:tenant_id, :filename, 'local', :size_bytes, 'pending', 0, 'LOW')
            RETURNING id
            """),
            {
                "tenant_id": tenant_id,
                "filename": filename,
                "size_bytes": size_bytes
            }
        )
        doc_id = res.fetchone()[0]
        conn.commit()
        
    # 2. Run compliance scanning pipeline
    from document_processing.orchestrator import run_document_scan_pipeline
    try:
        principal = optional_user_from_request(request)
        pipeline_res = run_document_scan_pipeline(
            doc_id,
            contents,
            filename,
            source="local",
            tenant_id=tenant_id,
            request_id=get_current_request_id() or f"document-{uuid.uuid4()}",
            requested_by=principal.get("sub"),
        )
    except (QuotaExceeded, QuotaUnavailable):
        raise
    except ApprovalCreationError as ex:
        raise HTTPException(status_code=401, detail=str(ex)) from ex
    except ApprovalPersistenceError as ex:
        raise HTTPException(status_code=503, detail="Approval persistence is unavailable") from ex
    except Exception as ex:
        logger.error("Document scan failed: %s", type(ex).__name__)
        with engine.begin() as conn:
            conn.execute(text("UPDATE documents SET status='scan_failed' WHERE id=:id AND tenant_id=:tenant AND status NOT IN ('alert_delivery_pending', 'alert_delivery_failed')"),
                         {"id": doc_id, "tenant": tenant_id})
        raise HTTPException(503, "Document scan unavailable; no successful assessment was produced") from ex
    
    # 3. Find matching knowledge_document ID for frontend backward compatibility
    with engine.connect() as conn:
        k_doc_row = conn.execute(
            text("SELECT id FROM knowledge_documents WHERE name = :name AND tenant_id = :tenant_id"),
            {"name": filename, "tenant_id": tenant_id}
        ).fetchone()
        k_doc_id = k_doc_row[0] if k_doc_row else doc_id
        
    return {
        "document_id": f"doc_{k_doc_id}",
        "status": pipeline_res["status"],
        "pipeline_results": pipeline_res
    }

@app.post("/gateway/documents/redact")
async def redact_gateway_document(
    file: UploadFile = File(...),
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    start_time = time.time()
    request_id = f"doc-{uuid.uuid4()}"
    session_id = request_id
    tenant_id = resolve_tenant(x_api_key, authorization)
    username = "gateway_document_user"
    if authorization:
        token = authorization[7:] if authorization.startswith("Bearer ") else authorization
        payload = decode_jwt(token)
        if payload:
            username = payload.get("sub") or payload.get("email") or username

    filename = file.filename or "uploaded-document"
    extension = os.path.splitext(filename)[1].lower()
    image_extensions = {".png", ".jpg", ".jpeg", ".tiff", ".tif"}
    supported_extensions = {
        ".pdf", ".docx", ".txt", ".text", ".md", ".markdown", ".csv", ".xlsx", ".xls", *image_extensions
    }

    def event(agent: str, event_type: str, details: str, sequence: int) -> dict:
        from verify_audit import log_agent_event
        log_agent_event(
            tenant_id=tenant_id,
            session_id=session_id,
            agent_name=agent,
            event_type=event_type,
            details=details,
            request_id=request_id,
            sequence=sequence,
        )
        return {
            "agent": agent,
            "event": event_type,
            "details": details,
            "request_id": request_id,
            "sequence": sequence,
        }

    trace = [
        event("Gateway Agent", "DOCUMENT_RECEIVED", f"Accepted upload '{filename}' for tenant {tenant_id}.", 1)
    ]

    contents = await file.read()
    size_bytes = len(contents)
    max_size_bytes = int(os.getenv("AUTHCLAW_DOCUMENT_REDACTION_MAX_BYTES", str(10 * 1024 * 1024)))
    if size_bytes > max_size_bytes:
        trace.append(event("Security Agent", "DOCUMENT_REJECTED_SIZE_LIMIT", f"Upload size {size_bytes} exceeds limit {max_size_bytes}.", 2))
        raise HTTPException(status_code=413, detail="Document is too large for gateway redaction.")

    if extension not in supported_extensions:
        trace.append(event("Security Agent", "DOCUMENT_REJECTED_UNSUPPORTED_TYPE", f"Unsupported file extension '{extension or 'none'}'.", 2))
        raise HTTPException(status_code=415, detail="Unsupported document type for gateway redaction.")

    from document_processing.parsers import extract_document_pages
    extraction = extract_document_pages(contents, filename)
    extracted_text = extraction.text
    if not extracted_text.strip():
        detail = "No extractable text found in document."
        if extraction.ocr_status == "unavailable":
            detail = f"OCR is unavailable for this file: {extraction.ocr_error}"
        trace.append(event("Security Agent", "DOCUMENT_TEXT_EXTRACTION_EMPTY", detail, 2))
        raise HTTPException(status_code=422, detail=detail)

    trace.append(event(
        "Security Agent",
        "DOCUMENT_TEXT_EXTRACTED",
        f"Extracted {len(extracted_text)} characters from '{filename}' using {extraction.extraction_method}. OCR status: {extraction.ocr_status}.",
        2
    ))

    from document_processing.intelligence import analyze_and_redact_document
    document_analysis = analyze_and_redact_document(extraction, username=username, tenant_id=tenant_id)
    redacted_text = document_analysis["redacted_text"]
    triggered = document_analysis["findings"]
    redacted_count = len(triggered)
    finding_actions = {str(item.get("action_taken") or item.get("action") or "").lower() for item in triggered}
    decision = "BLOCK" if "block" in finding_actions else ("REDACT" if redacted_count else "ALLOW")
    risk_level = "HIGH" if decision == "BLOCK" else ("MEDIUM" if redacted_count else "LOW")
    trace.append(event(
        "Security Agent",
        "DOCUMENT_REDACTION_APPLIED" if redacted_count else "DOCUMENT_REDACTION_CLEAN",
        f"Detected {redacted_count} sensitive field(s). Actions: {', '.join(sorted(finding_actions)) or 'allow'}.",
        3,
    ))
    trace.append(event("Policy Agent", "DOCUMENT_POLICY_EVALUATED", f"Decision: {decision}; risk level: {risk_level}.", 4))

    from verify_audit import create_audit_block
    audit_id = create_audit_block(
        query=f"Document Redaction: {filename}",
        response=f"Redacted {redacted_count} sensitive field(s) from uploaded document.",
        allowed=decision != "BLOCK",
        risk_level=risk_level,
        approval_status="N/A",
        session_id=session_id,
        username=username,
        tenant_id=tenant_id,
        policy_name="gateway_document_redaction",
        policy_type="document_redaction",
    )
    trace.append(event("Audit Agent", "DOCUMENT_REDACTION_AUDITED", f"Committed document redaction audit block #{audit_id}.", 5))

    duration_ms = int((time.time() - start_time) * 1000)
    from document_processing.storage import persist_document_intelligence_result
    document_record = persist_document_intelligence_result(
        tenant_id=tenant_id,
        request_id=request_id,
        filename=filename,
        content_type=file.content_type,
        size_bytes=size_bytes,
        content_bytes=contents,
        extraction=extraction,
        analysis=document_analysis,
        decision=decision,
        risk_level=risk_level,
        username=username,
        duration_ms=duration_ms,
    )
    trace.append(event(
        "Registrar Agent",
        "DOCUMENT_INTELLIGENCE_PERSISTED",
        f"Persisted document #{document_record['document_id']} and scan {document_record['scan_id']}.",
        6,
    ))

    from database import engine
    from sqlalchemy import text
    with engine.connect() as conn:
        conn.execute(
            text("""
                INSERT INTO gateway_requests (
                    timestamp, risk_level, allowed, status, request_id, tenant_id,
                    route_id, provider, model, latency, latency_recorded, tokens_in, tokens_out,
                    created_at, decision, duration_ms
                )
                VALUES (
                    NOW(), :risk_level, :allowed, :status, :request_id, :tenant_id,
                    :route_id, :provider, :model, :latency, TRUE, NULL, NULL,
                    NOW(), :decision, :duration_ms
                )
            """),
            {
                "risk_level": risk_level,
                "allowed": decision != "BLOCK",
                "status": "blocked" if decision == "BLOCK" else ("redacted" if redacted_count else "allowed"),
                "request_id": request_id,
                "tenant_id": str(tenant_id),
                "route_id": "gateway-document-redaction",
                "provider": "authclaw",
                "model": "document-redaction",
                "latency": duration_ms,
                "decision": decision,
                "duration_ms": duration_ms,
            },
        )
        conn.commit()
    trace.append(event("Registrar Agent", "GATEWAY_DOCUMENT_REQUEST_RECORDED", f"Recorded document request lifecycle metadata in {duration_ms} ms.", 7))

    def serialize_trigger(item):
        result = {}
        for key, value in item.items():
            if hasattr(value, "isoformat"):
                result[key] = value.isoformat()
            else:
                result[key] = value
        return result

    return {
        "request_id": request_id,
        "tenant_id": tenant_id,
        "filename": filename,
        "content_type": file.content_type,
        "size_bytes": size_bytes,
        "document_id": document_record["document_id"],
        "document_uid": document_record["document_uid"],
        "scan_id": document_record["scan_id"],
        "processing_progress": document_record["progress"],
        "content_sha256": document_record["content_sha256"],
        "status": "blocked" if decision == "BLOCK" else ("redacted" if redacted_count else "clean"),
        "decision": decision,
        "risk_level": risk_level,
        "duration_ms": duration_ms,
        "redacted_count": redacted_count,
        "extraction_method": extraction.extraction_method,
        "ocr_status": extraction.ocr_status,
        "ocr_required": bool(getattr(extraction, "ocr_required", False)),
        "ocr_error": extraction.ocr_error,
        "document_metadata": document_analysis["metadata"],
        "compliance_summary": document_analysis["compliance_summary"],
        "triggered_policies": [serialize_trigger(item) for item in triggered],
        "findings": [serialize_trigger(item) for item in triggered],
        "findings_report": document_analysis["findings_report"],
        "redacted_pages": document_analysis["redacted_pages"],
        "redacted_pdf_base64": document_analysis["redacted_pdf_base64"],
        "extracted_text": extracted_text,
        "redacted_text": redacted_text,
        "trace": trace,
    }

@app.get("/documents/scans/{scan_id}")
def get_document_scan_status(
    scan_id: str,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    tenant_id = resolve_tenant(x_api_key, authorization)
    from database import engine
    from sqlalchemy import text
    with tenant_context(tenant_id, required=True), engine.connect() as conn:
        row = conn.execute(
            text("""
                SELECT s.scan_id, s.status, s.progress, s.scan_duration_ms,
                       s.extraction_method, s.ocr_status, s.ocr_required,
                       s.compliance_summary, d.id, d.filename, d.document_uid,
                       d.status AS document_status
                FROM document_scans s
                JOIN documents d ON d.id = s.document_id AND d.tenant_id = s.tenant_id
                WHERE s.scan_id = :scan_id AND s.tenant_id = :tenant_id
                LIMIT 1
            """),
            {"scan_id": scan_id, "tenant_id": tenant_id},
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Document scan not found.")
    compliance_summary = {}
    try:
        compliance_summary = json.loads(row[7] or "{}")
    except Exception:
        compliance_summary = {}
    return {
        "scan_id": row[0],
        "status": row[1],
        "progress": row[2],
        "duration_ms": row[3],
        "extraction_method": row[4],
        "ocr_status": row[5],
        "ocr_required": row[6],
        "compliance_summary": compliance_summary,
        "document_id": row[8],
        "filename": row[9],
        "document_uid": row[10],
        "document_status": row[11],
    }

class DocumentScanRequest(BaseModel):
    document_id: str

@app.post("/documents/scan")
def scan_document(
    req: DocumentScanRequest,
    request: Request,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)
    
    doc_id = parse_document_id(req.document_id)
    
    from database import engine
    from sqlalchemy import text
    
    with engine.connect() as conn:
        # Check in knowledge_documents
        k_doc = conn.execute(
            text("SELECT name, size_bytes FROM knowledge_documents WHERE id = :id AND tenant_id = :tenant_id"),
            {"id": doc_id, "tenant_id": tenant_id}
        ).fetchone()
        if not k_doc:
            raise HTTPException(status_code=404, detail="Document not found")
        filename = k_doc[0]
        size_bytes = k_doc[1]
        
        chunks_res = conn.execute(
            text("SELECT content FROM knowledge_chunks WHERE document_id = :doc_id AND tenant_id = :tenant_id ORDER BY id ASC"),
            {"doc_id": doc_id, "tenant_id": tenant_id}
        ).fetchall()
        text_content = "\n\n".join([r[0] for r in chunks_res])
        
        # Check or insert into documents table
        doc_row = conn.execute(
            text("SELECT id FROM documents WHERE filename = :name AND tenant_id = :tenant_id"),
            {"name": filename, "tenant_id": tenant_id}
        ).fetchone()
        if doc_row:
            d_id = doc_row[0]
        else:
            res = conn.execute(
                text("""
                INSERT INTO documents (tenant_id, filename, source, size_bytes, status, risk_score, severity)
                VALUES (:tenant_id, :filename, 'local', :size, 'pending', 0, 'LOW')
                RETURNING id
                """),
                {"tenant_id": tenant_id, "filename": filename, "size": size_bytes}
            )
            d_id = res.fetchone()[0]
            conn.commit()
            
    from document_processing.orchestrator import run_document_scan_pipeline
    principal = optional_user_from_request(request)
    try:
        pipeline_res = run_document_scan_pipeline(
            d_id,
            text_content.encode("utf-8"),
            filename,
            source="local",
            tenant_id=tenant_id,
            request_id=get_current_request_id() or f"document-{uuid.uuid4()}",
            requested_by=principal.get("sub"),
        )
    except ApprovalCreationError as ex:
        raise HTTPException(status_code=401, detail=str(ex)) from ex
    except ApprovalPersistenceError as ex:
        raise HTTPException(status_code=503, detail="Approval persistence is unavailable") from ex
    return pipeline_res

@app.get("/documents")
def list_all_documents(
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)
    
    from database import engine
    from sqlalchemy import text
    with engine.connect() as conn:
        res = conn.execute(
            text("""
                SELECT id, filename, source, status, size_bytes, risk_score, severity, created_at, updated_at
                FROM documents
                WHERE tenant_id = :tenant_id
                ORDER BY id DESC
            """),
            {"tenant_id": tenant_id}
        )
        return [dict(r._mapping) for r in res]

@app.get("/documents/{id}")
def get_document_details(
    id: str,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)
        
    doc_id = parse_document_id(id)
    
    from database import engine
    from sqlalchemy import text
    
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT * FROM documents WHERE id = :id AND tenant_id = :tenant_id"),
            {"id": doc_id, "tenant_id": tenant_id}
        ).fetchone()
        if not row:
            k_doc = conn.execute(
                text("SELECT name FROM knowledge_documents WHERE id = :id AND tenant_id = :tenant_id"),
                {"id": doc_id, "tenant_id": tenant_id}
            ).fetchone()
            if k_doc:
                filename = k_doc[0]
                row = conn.execute(
                    text("SELECT * FROM documents WHERE filename = :name AND tenant_id = :tenant_id ORDER BY id DESC LIMIT 1"),
                    {"name": filename, "tenant_id": tenant_id}
                ).fetchone()
                
        if not row:
            raise HTTPException(status_code=404, detail="Document not found")
            
        return dict(row._mapping)

@app.get("/documents/{id}/findings")
def get_document_findings(
    id: str,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)
        
    doc_id = parse_document_id(id)
    
    from database import engine
    from sqlalchemy import text
    
    with engine.connect() as conn:
        row = resolve_document_record(conn, doc_id, tenant_id)
                
        if not row:
            raise HTTPException(status_code=404, detail="Document not found")
            
        real_doc_id = row[0]
        
        findings_res = conn.execute(
            text("""
                SELECT id, finding_type, matched_pattern, matched_text, risk_level, recommendation, impact, priority, location_evidence
                FROM document_findings
                WHERE document_id = :doc_id AND tenant_id = :tenant_id
            """),
            {"doc_id": real_doc_id, "tenant_id": tenant_id}
        ).fetchall()
        
        return [dict(f._mapping) for f in findings_res]

@app.get("/documents/{id}/audit")
def get_document_audit_trail(
    id: str,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)
        
    doc_id = parse_document_id(id)
    
    from database import engine
    from sqlalchemy import text
    from document_processing.auditor import verify_document_audit_chain
    
    with engine.connect() as conn:
        row = resolve_document_record(conn, doc_id, tenant_id)
                
        if not row:
            raise HTTPException(status_code=404, detail="Document not found")
            
        real_doc_id = row[0]
        
        audit_res = conn.execute(
            text("""
                SELECT id, timestamp, action, actor, details, integrity_hash, previous_hash
                FROM document_audits
                WHERE document_id = :doc_id AND tenant_id = :tenant_id
                ORDER BY id ASC
            """),
            {"doc_id": real_doc_id, "tenant_id": tenant_id}
        ).fetchall()
        
        audit_list = [dict(a._mapping) for a in audit_res]
        verification = verify_document_audit_chain(real_doc_id, tenant_id=tenant_id)
        
        return {
            "audit_trail": audit_list,
            "verification": verification
        }

@app.post("/compliance/analyze")
def compliance_analyze(
    req: ComplianceAnalyzeRequest,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)
        
    doc_id = parse_document_id(req.document_id)
    
    from rag.compliance_analyzer import analyze_document_compliance, get_document_text
    try:
        # Get document text and name first
        _, doc_name = get_document_text(doc_id, tenant_id=tenant_id)
        # Perform analysis
        analysis = analyze_document_compliance(doc_id, tenant_id=tenant_id)
    except (QuotaExceeded, QuotaUnavailable):
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Compliance analysis failed: {str(e)}")
        
    # Generate and store evidence reports
    try:
        from rag.compliance_analyzer import generate_and_vault_reports
        generate_and_vault_reports(doc_id, doc_name, analysis, tenant_id=tenant_id)
    except Exception as e:
        logger.error(f"Failed to generate and store evidence reports: {str(e)}")
        
    # Audit logging
    from verify_audit import create_audit_block
    create_audit_block(
        query=f"Run Compliance Analysis: doc_{doc_id}",
        response=f"Compliance analysis completed for {doc_name}. Overall Risk: {analysis['overall_risk']}",
        allowed=True,
        risk_level="LOW",
        approval_status="N/A",
        tenant_id=tenant_id
    )
    
    # Emit audit event
    from startup.audit import log_audit_event
    log_audit_event(
        event="compliance_analysis",
        correlation_id="system",
        extra={"document_id": req.document_id, "overall_risk": analysis["overall_risk"]}
    )
    
    return analysis

@app.post("/documents/chat")
def document_chat(
    req: DocumentChatRequest,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)
        
    doc_id = parse_document_id(req.document_id)
    
    import os
    import requests
    from rag.compliance_analyzer import get_document_text
    try:
        _, doc_name = get_document_text(doc_id, tenant_id=tenant_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Document not found: {str(e)}")
        
    # Retrieve relevant context
    from rag.retriever import retrieve_formatted_context
    context, citations = retrieve_formatted_context(req.question, top_k=3, document_id=doc_id, tenant_id=tenant_id)
    
    # Query Gemini
    api_key = os.getenv("GOOGLE_API_KEY")
    api_url = os.getenv("GOOGLE_API_URL", "https://generativelanguage.googleapis.com")
    model = os.getenv("MODEL_NAME", "gemini-2.5-flash")
    
    answer = ""
    is_key_valid = api_key and api_key not in ("dummy", "dummy-api-key", "")
    
    if is_key_valid:
        try:
            prompt = f"""
You are an expert compliance assistant. Answer the user's question about the document '{doc_name}' using only the provided context.
If the answer is not in the context, say "I cannot find the answer in the document."

Context:
{context}

Question:
{req.question}
"""
            url = f"{api_url}/v1beta/models/{model}:generateContent"
            payload = {
                "contents": [{
                    "role": "user",
                    "parts": [{"text": prompt}]
                }]
            }
            from providers.base import admit_provider_call
            admit_provider_call("gemini", model)
            res = requests.post(url, json=payload, headers={"Content-Type": "application/json", "x-goog-api-key": api_key}, timeout=15)
            if res.status_code == 200:
                data = res.json()
                answer = data["candidates"][0]["content"]["parts"][0]["text"].strip()
            else:
                logger.warning("Gemini document chat failed: status=%s", res.status_code)
        except (QuotaExceeded, QuotaUnavailable):
            raise
        except Exception as e:
            logger.warning("Gemini document chat failed: error_type=%s", type(e).__name__)
            
    # Fallback to local answering if offline or Gemini failed
    if not answer:
        if citations:
            best_chunk = citations[0]["text"]
            answer = f"According to the document context: \"{best_chunk[:300]}...\". (Note: Gemini API is currently offline or unconfigured, utilizing local semantic search retrieval)."
        else:
            answer = "I cannot find the answer in the document."
            
    # Audit logging
    from verify_audit import create_audit_block
    create_audit_block(
        query=f"Document Copilot Question (doc_{doc_id}): {req.question}",
        response=f"Answer: {answer[:100]}...",
        allowed=True,
        risk_level="LOW",
        approval_status="N/A",
        tenant_id=tenant_id
    )
    
    # Emit audit event
    from startup.audit import log_audit_event
    log_audit_event(
        event="document_question",
        correlation_id="system",
        extra={"document_id": req.document_id}
    )
    
    return {
        "answer": answer,
        "citations": citations
    }


@app.get("/evidence/download/{evidence_id}")
def download_evidence_file(evidence_id: str, tenant_id: int = Depends(require_tenant_context)):
    from database import engine
    from services.evidence_access import download_file
    with engine.connect() as conn:
        return download_file(conn, tenant_id, evidence_id)

@app.delete("/rag/documents/{doc_id}")
def delete_document(
    doc_id: int,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)
        
    from database import engine
    from sqlalchemy import text
    from verify_audit import create_audit_block
    
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT name FROM knowledge_documents WHERE id = :id AND tenant_id = :tenant_id"),
            {"id": doc_id, "tenant_id": tenant_id}
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Document not found.")
        name = row[0]
        
        # Deleting from documents table triggers cascade delete of scans and findings
        conn.execute(text("DELETE FROM documents WHERE filename = :name AND tenant_id = :tenant_id"), {"name": name, "tenant_id": tenant_id})
        conn.execute(text("DELETE FROM knowledge_documents WHERE id = :id AND tenant_id = :tenant_id"), {"id": doc_id, "tenant_id": tenant_id})
        conn.execute(text("DELETE FROM knowledge_chunks WHERE document_id = :id AND tenant_id = :tenant_id"), {"id": doc_id, "tenant_id": tenant_id})
        conn.commit()
        
    create_audit_block(
        query=f"Delete Knowledge Document: {name}",
        response=f"Document '{name}' and its vector chunks purged from index.",
        allowed=True,
        risk_level="LOW",
        approval_status="N/A",
        tenant_id=tenant_id
    )
    return {"status": "success", "message": "Document deleted."}

@app.get("/rag/chunks/{doc_id}")
def get_document_chunks(
    doc_id: int,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    from database import engine
    from sqlalchemy import text
    tenant_id = resolve_tenant(x_api_key, authorization)
    with engine.connect() as conn:
        doc = conn.execute(
            text("SELECT id FROM knowledge_documents WHERE id = :doc_id AND tenant_id = :tenant_id"),
            {"doc_id": doc_id, "tenant_id": tenant_id}
        ).fetchone()
        if not doc:
            raise HTTPException(status_code=404, detail="Document not found.")
        res = conn.execute(
            text("SELECT id, content, embedding_preview FROM knowledge_chunks WHERE document_id = :doc_id AND tenant_id = :tenant_id ORDER BY id ASC"),
            {"doc_id": doc_id, "tenant_id": tenant_id}
        )
        return [dict(r._mapping) for r in res]

class SimilaritySearchRequest(BaseModel):
    query: str
    top_k: Optional[int] = 3

@app.post("/rag/search")
def rag_search_endpoint(
    req: SimilaritySearchRequest,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)

        
    from rag.retriever import retrieve_context
    hits = retrieve_context(req.query, top_k=req.top_k, tenant_id=tenant_id)
    return hits





# 9. ACCESS CONTROL
@app.get("/access-control/users")
def get_users(payload: dict = Depends(require_tenant_access_admin)):
    from database import engine
    from sqlalchemy import text
    tenant_id = payload["tenant_id"]
    with engine.connect() as conn:
        res = conn.execute(
            text("""
                SELECT id, email AS username, role, permissions, status,
                       email_verified, last_login_at
                FROM tenant_users
                WHERE tenant_id = :tenant_id
                ORDER BY id ASC
            """),
            {"tenant_id": tenant_id},
        )
        return [dict(r._mapping) for r in res]

@app.post("/access-control/users")
def create_user_role(role_req: UserRoleRequest, payload: dict = Depends(require_tenant_access_admin)):
    from database import engine
    from sqlalchemy import text
    from verify_audit import create_audit_block
    tenant_id = payload["tenant_id"]
    allowed_roles = {
        "Super Admin",
        "Security Admin",
        "Compliance Officer",
        "Developer",
        "Auditor",
        "Viewer",
    }
    if role_req.role not in allowed_roles:
        raise HTTPException(status_code=400, detail="Unsupported tenant role.")
    normalized_email = role_req.username.strip().lower()
    if not is_valid_work_email(normalized_email):
        raise HTTPException(status_code=400, detail="Enter a valid tenant user work email, for example user@company.com.")
    with engine.connect() as conn:
        row = conn.execute(
            text("""
            UPDATE tenant_users
            SET role = :role, permissions = :permissions, updated_at = NOW()
            WHERE tenant_id = :tenant_id AND lower(email) = lower(:email)
            RETURNING id
            """),
            {
                "tenant_id": tenant_id,
                "email": normalized_email,
                "role": role_req.role,
                "permissions": role_req.permissions,
            },
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Tenant user not found. Choose an existing tenant user from this tenant before assigning a role.")
        conn.commit()
    create_audit_block(
        query=f"Modify Access Control: {normalized_email}",
        response=f"Username {normalized_email} role updated/set to {role_req.role}.",
        allowed=True,
        risk_level="MEDIUM",
        approval_status="N/A",
        username=normalized_email,
        tenant_id=tenant_id
    )
    return {"status": "success", "message": "User access mapping updated."}





# 11. EVIDENCE VAULT
@app.get("/evidence")
def get_evidence(
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    from database import engine
    from sqlalchemy import text
    tenant_id = resolve_tenant(x_api_key, authorization)
    with engine.connect() as conn:
        res = conn.execute(
            text("""
                SELECT id, name, category, file_path, collected_at, hash
                FROM compliance_evidence
                WHERE tenant_id = :tenant_id
                ORDER BY id DESC
            """),
            {"tenant_id": tenant_id}
        )
        return [dict(r._mapping) for r in res]

@app.post("/evidence/collect")
def collect_evidence(
    req: EvidenceUploadRequest,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    from database import engine
    from sqlalchemy import text
    from verify_audit import create_audit_block
    import hashlib
    tenant_id = resolve_tenant(x_api_key, authorization)
    now_str = datetime.now(timezone.utc).date().isoformat()
    f_hash = f"sha256-{hashlib.sha256(req.name.encode()).hexdigest()[:16]}"
    category_upper = str(req.category or "").upper()
    framework = category_upper if category_upper in {"SOC2", "GDPR", "HIPAA"} else None
    with engine.connect() as conn:
        conn.execute(
            text("""
            INSERT INTO compliance_evidence (
                tenant_id, name, category, file_path, collected_at, hash,
                framework, source_type, metadata
            )
            VALUES (
                :tenant_id, :name, :category, :file_path, :collected_at, :hash,
                :framework, 'manual', :metadata
            )
            """),
            {
                "tenant_id": tenant_id,
                "name": req.name,
                "category": req.category,
                "file_path": req.file_path,
                "collected_at": now_str,
                "hash": f_hash,
                "framework": framework,
                "metadata": json.dumps({"collected_via": "evidence_api"}),
            }
        )
        conn.commit()
    create_audit_block(
        query=f"Vault Compliance Evidence: {req.name}",
        response=f"Evidence vaulted under category: {req.category}.",
        allowed=True,
        risk_level="MEDIUM",
        approval_status="N/A",
        tenant_id=tenant_id
    )
    return {"status": "success", "message": f"Compliance evidence '{req.name}' successfully vaulted."}


@app.get("/compliance/controls")
def get_compliance_controls(
    framework: Optional[str] = None,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    resolve_tenant(x_api_key, authorization)
    from services.compliance_evidence_engine import ComplianceEvidenceEngine
    return ComplianceEvidenceEngine().catalog(framework)


@app.get("/compliance/corpus")
def get_regulatory_corpus_status(
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    resolve_tenant(x_api_key, authorization)
    from services.compliance_evidence_engine import ComplianceEvidenceEngine
    return ComplianceEvidenceEngine().corpus_status()


@app.get("/compliance/score-changes")
def get_compliance_score_changes(
    framework: Optional[str] = None,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)
    from services.compliance_evidence_engine import ComplianceEvidenceEngine
    return ComplianceEvidenceEngine().score_changes(tenant_id, framework)


@app.get("/compliance/controls/{control_id}/evidence")
def get_control_evidence(
    control_id: str,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)
    from services.compliance_evidence_engine import ComplianceEvidenceEngine
    return ComplianceEvidenceEngine().evidence_export_rows(tenant_id, control_id=control_id)


@app.get("/compliance/evidence/export/csv")
def export_control_evidence_csv(
    framework: Optional[str] = None,
    control_id: Optional[str] = None,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)
    from services.compliance_evidence_engine import ComplianceEvidenceEngine
    data = ComplianceEvidenceEngine().evidence_csv(tenant_id, framework=framework, control_id=control_id)
    return Response(content=data, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=control_evidence.csv"})

@app.delete("/evidence/{id}")
def delete_evidence(
    id: int,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)
        
    import os
    from database import engine
    from sqlalchemy import text
    from verify_audit import create_audit_block
    
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT name, file_path FROM compliance_evidence WHERE id = :id AND tenant_id = :tenant_id"),
            {"id": id, "tenant_id": tenant_id}
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Evidence not found")
        name = row[0]
        file_path = row[1]
        if file_path:
            raise HTTPException(403, "Evidence file is retained; deletion is not permitted")
        
        conn.execute(
            text("DELETE FROM compliance_evidence WHERE id = :id AND tenant_id = :tenant_id"),
            {"id": id, "tenant_id": tenant_id}
        )
        conn.commit()
        
        # Registry removal must never unlink a client-supplied filesystem path.
        # Retained files require the storage retention lifecycle for physical purge.
                    
    create_audit_block(
        query=f"Delete Compliance Evidence: {name}",
        response=f"Evidence registry #{id} permanently purged.",
        allowed=True,
        risk_level="MEDIUM",
        approval_status="N/A",
        tenant_id=tenant_id
    )
    return {"status": "success", "message": f"Compliance evidence '{name}' permanently deleted."}

@app.get("/evidence/export/csv")
def export_evidence_csv_endpoint(
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)
    from document_processing.exports import generate_evidence_csv
    csv_data = generate_evidence_csv(tenant_id=tenant_id)
    return Response(content=csv_data, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=evidence_vault.csv"})

@app.get("/evidence/export/pdf")
def export_evidence_pdf_endpoint(
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)
    from document_processing.exports import generate_evidence_pdf
    pdf_data = generate_evidence_pdf(tenant_id=tenant_id)
    return Response(content=pdf_data, media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=evidence_vault.pdf"})

@app.get("/audit/export/csv")
def export_audit_csv_endpoint(
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)
    from document_processing.exports import generate_audit_csv
    from verify_audit import sign_export_payload
    csv_data = generate_audit_csv(tenant_id=tenant_id)
    headers = {"Content-Disposition": "attachment; filename=audit_ledger.csv"}
    headers.update(sign_export_payload(csv_data, tenant_id=tenant_id, export_type="audit-csv"))
    return Response(content=csv_data, media_type="text/csv", headers=headers)

@app.get("/audit/export/pdf")
def export_audit_pdf_endpoint(
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)
    from document_processing.exports import generate_audit_pdf
    from verify_audit import sign_export_payload
    pdf_data = generate_audit_pdf(tenant_id=tenant_id)
    headers = {"Content-Disposition": "attachment; filename=audit_ledger.pdf"}
    headers.update(sign_export_payload(pdf_data, tenant_id=tenant_id, export_type="audit-pdf"))
    return Response(content=pdf_data, media_type="application/pdf", headers=headers)


@app.get("/compliance/framework-scores")
def get_compliance_framework_scores(
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)
    from services.compliance_evidence_engine import ComplianceEvidenceEngine
    return ComplianceEvidenceEngine().calculate_scores(tenant_id)


def _compact_framework_evidence(row: Dict[str, Any]) -> Dict[str, Any]:
    created_at = row.get("created_at")
    reason = str(row.get("reason") or "")
    return {
        "framework": row.get("framework"),
        "control_id": row.get("control_id"),
        "source_type": row.get("source_type"),
        "source_id": row.get("source_id"),
        "evidence_hash": row.get("evidence_hash"),
        "reason": reason[:500],
        "impact": row.get("impact"),
        "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else created_at,
    }


def _compact_framework_scores(scores: Dict[str, Any]) -> Dict[str, Any]:
    compact: Dict[str, Any] = {}
    for key, value in scores.items():
        if key.endswith("_controls") and isinstance(value, dict):
            compact[key] = {
                "passed": value.get("passed", 0),
                "failed": value.get("failed", 0),
                "watch": value.get("watch", 0),
                "unknown": value.get("unknown", 0),
                "unassessed": value.get("unassessed", 0),
                "status": value.get("status", "unassessed"),
                "authoritative": False,
                "score_kind": "diagnostic",
                "calculation_version": value.get("calculation_version"),
                "evidence_status": value.get("evidence_status", "unsupported"),
                "evidence_gaps": value.get("evidence_gaps", []),
                "items": [
                    {
                        "framework": item.get("framework"),
                        "control_id": item.get("control_id"),
                        "title": item.get("title"),
                        "score": item.get("score"),
                        "status": item.get("status"),
                        "evidence_count": item.get("evidence_count", 0),
                        "negative_findings": item.get("negative_findings", 0),
                        "reason": item.get("reason"),
                        "source_event": item.get("source_event"),
                        "calculated_at": item.get("calculated_at"),
                        "authoritative": False,
                        "score_kind": "diagnostic",
                        "calculation_version": item.get("calculation_version"),
                        "evidence_status": item.get("evidence_status", "unsupported"),
                        "evidence_gaps": item.get("evidence_gaps", []),
                    }
                    for item in value.get("items", [])
                ],
            }
        else:
            compact[key] = value
    return compact


@app.get("/compliance/framework-explorer")
def get_compliance_framework_explorer(
    framework: Optional[str] = None,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)
    from services.compliance_evidence_engine import ComplianceEvidenceEngine

    engine = ComplianceEvidenceEngine()
    try:
        controls = engine.catalog(framework)
        scores = engine.calculate_scores(tenant_id)

        evidence_rows = engine.evidence_export_rows(tenant_id, framework=framework, refresh_scores=False, limit=300)
        changes = engine.score_changes(tenant_id, framework=framework, limit=50)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Compliance telemetry unavailable") from exc
    evidence_by_control: Dict[str, List[Dict[str, Any]]] = {}
    for row in evidence_rows:
        evidence_by_control.setdefault(row["control_id"], []).append(_compact_framework_evidence(row))
    score_items: Dict[str, Dict[str, Any]] = {}
    for key, value in scores.items():
        if key.endswith("_controls") and isinstance(value, dict):
            for item in value.get("items", []):
                score_items[item["control_id"]] = item
    return {
        "tenant_id": tenant_id,
        "framework_filter": framework,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "framework_scores": _compact_framework_scores(scores),
        "controls": [
            {
                **control,
                **engine.diagnostic_metadata(),
                "score": score_items.get(control["control_id"], {}).get("score"),
                "status": score_items.get(control["control_id"], {}).get("status", "catalog_only"),
                "risk": "UNASSESSED",
                "evidence": evidence_by_control.get(control["control_id"], []),
                "linked_audit_logs": [
                    item for item in evidence_by_control.get(control["control_id"], [])
                    if item.get("source_type") == "audit"
                ],
                "linked_policy": [
                    item for item in evidence_by_control.get(control["control_id"], [])
                    if item.get("source_type") == "policy"
                ],
                "linked_document": [
                    item for item in evidence_by_control.get(control["control_id"], [])
                    if item.get("source_type") in {"document", "evidence"}
                ],
                "timestamp": score_items.get(control["control_id"], {}).get("calculated_at"),
            }
            for control in controls
        ],
        "score_changes": changes,
    }


@app.get("/policy/bundles")
def list_policy_bundles(
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)
    from services.policy_bundle_manager import PolicyBundleManager
    return PolicyBundleManager().list_bundles(tenant_id)


@app.post("/policy/bundles/build")
def build_policy_bundle(
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)
    actor = policy_actor_from_authorization(authorization)
    from services.policy_bundle_manager import PolicyBundleManager
    return PolicyBundleManager().build_bundle(tenant_id, actor=actor)


@app.post("/policy/bundles/promote")
def promote_policy_bundle(
    req: PolicyBundlePromotionRequest,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)
    actor = policy_actor_from_authorization(authorization)
    from services.policy_bundle_manager import PolicyBundleManager
    try:
        return PolicyBundleManager().promote_bundle(tenant_id, req.bundle_id, actor=actor)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/policy/bundles/rollback")
def rollback_policy_bundle(
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)
    actor = policy_actor_from_authorization(authorization)
    from services.policy_bundle_manager import PolicyBundleManager
    try:
        return PolicyBundleManager().rollback_bundle(tenant_id, actor=actor)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/redteam/history")
def get_redteam_history(
    limit: int = 100,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)
    from services.redteam_service import RedTeamService
    return RedTeamService().history(tenant_id, limit=limit)


@app.get("/redteam/report")
def get_redteam_report(
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)
    from services.redteam_service import RedTeamService
    return RedTeamService().report(tenant_id)


@app.post("/redteam/run")
def run_redteam(
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)
    actor = policy_actor_from_authorization(authorization)
    from services.redteam_service import RedTeamService
    return RedTeamService().run(tenant_id, actor=actor)


@app.get("/tenant/plan")
def get_tenant_plan(
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)
    from services.tenant_plan_service import TenantPlanService
    return TenantPlanService().get_plan(tenant_id)


@app.post("/tenant/plan/override")
def update_tenant_plan(
    req: TenantPlanUpdateRequest,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    payload = revalidate_tenant_session_payload(
        get_current_user_from_authorization(authorization)
    )
    if payload.get("role") not in {"Super Admin", "Security Admin"}:
        raise HTTPException(status_code=403, detail="Tenant access administrator role required.")
    tenant_id = resolve_tenant(x_api_key, authorization)
    actor = payload.get("email") or payload.get("sub") or "tenant_admin"
    from services.tenant_plan_service import TenantPlanService
    try:
        return TenantPlanService().update_plan(tenant_id, req.plan, actor, req.override_reason or "")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


def _build_auditor_package_payload(tenant_id: int, framework: Optional[str] = None) -> Dict[str, Any]:
    from services.compliance_evidence_engine import ComplianceEvidenceEngine
    from verify_audit import verify_audit_chain

    engine = ComplianceEvidenceEngine()
    framework_scope = framework.upper() if framework else None
    return {
        "package_type": "auditor_evidence",
        "tenant_id": tenant_id,
        "framework_scope": framework_scope or "all",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "framework_scores": engine.calculate_scores(tenant_id),
        "control_evidence": engine.evidence_export_rows(tenant_id, framework=framework_scope),
        "score_changes": engine.score_changes(tenant_id, framework=framework_scope),
        "corpus": engine.corpus_status(),
        "audit_chain": verify_audit_chain(tenant_id=tenant_id),
    }


@app.get("/audit/export/package")
def export_signed_audit_package(
    framework: Optional[str] = None,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)
    from document_processing.exports import generate_audit_csv, generate_evidence_csv
    from services.compliance_evidence_engine import ComplianceEvidenceEngine
    from verify_audit import create_signed_export_package, verify_audit_chain

    audit_csv = generate_audit_csv(tenant_id=tenant_id)
    evidence_csv = generate_evidence_csv(tenant_id=tenant_id)
    payload = {
        "package_type": "audit_export",
        "tenant_id": tenant_id,
        "framework_scope": framework.upper() if framework else "all",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "audit_chain": verify_audit_chain(tenant_id=tenant_id),
        "framework_scores": ComplianceEvidenceEngine().calculate_scores(tenant_id),
        "artifacts": [
            {
                "name": "audit_ledger.csv",
                "media_type": "text/csv",
                "sha256": hashlib.sha256(audit_csv).hexdigest(),
                "content_b64": base64.b64encode(audit_csv).decode("ascii"),
            },
            {
                "name": "evidence_vault.csv",
                "media_type": "text/csv",
                "sha256": hashlib.sha256(evidence_csv).hexdigest(),
                "content_b64": base64.b64encode(evidence_csv).decode("ascii"),
            },
        ],
    }
    return create_signed_export_package(
        payload,
        tenant_id=tenant_id,
        export_type="audit-package",
        framework_scope=framework.upper() if framework else "all",
    )


@app.get("/auditor/package/export")
def export_signed_auditor_package(
    framework: Optional[str] = None,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    tenant_id = resolve_tenant(x_api_key, authorization)
    from verify_audit import create_signed_export_package

    payload = _build_auditor_package_payload(tenant_id, framework=framework)
    return create_signed_export_package(
        payload,
        tenant_id=tenant_id,
        export_type="auditor-package",
        framework_scope=framework.upper() if framework else "all",
    )


@app.post("/audit/export/verify")
def verify_signed_export(req: SignedExportVerifyRequest):
    from verify_audit import verify_signed_export_package
    return verify_signed_export_package(payload=req.payload, payload_b64=req.payload_b64, manifest=req.manifest)


@app.get("/trust/public")
def get_public_trust_state():
    from services.trust_center_runtime import build_public_trust_state

    return build_public_trust_state()


# ==============================================================================
# AUTHENTICATION & SESSION MANAGEMENT ENDPOINTS
# ==============================================================================

class LoginRequest(BaseModel):
    username: str
    password: str

class VerifyOTPRequest(BaseModel):
    session_id: str
    code: str

class MFAResetRequest(BaseModel):
    username: str
    password: str

class MFAResetConfirmRequest(BaseModel):
    token: str
    username: Optional[str] = None
    password: Optional[str] = None

class PasswordResetRequest(BaseModel):
    username: str

class PasswordResetConfirmRequest(BaseModel):
    token: str
    password: str

class RefreshRequest(BaseModel):
    refresh_token: str

class OIDCProviderConfigRequest(BaseModel):
    id: Optional[int] = None
    provider_type: str = "generic_oidc"
    display_name: Optional[str] = None
    client_id: str
    client_secret: str
    discovery_url: Optional[str] = None
    issuer: Optional[str] = None
    authorization_endpoint: Optional[str] = None
    token_endpoint: Optional[str] = None
    userinfo_endpoint: Optional[str] = None
    jwks_uri: Optional[str] = None
    redirect_uri: str
    scopes: Optional[str] = None
    groups_claim: Optional[str] = "groups"
    role_mapping: Optional[dict] = None
    enabled: bool = True

class OIDCProviderEnableRequest(BaseModel):
    enabled: bool

class OIDCCallbackRequest(BaseModel):
    state: str
    code: str

class LogoutRequest(BaseModel):
    refresh_token: Optional[str] = None

JWT_SECRET = SecretManager().get_secret("JWT_SECRET") or SecretManager().get_secret("AUTHCLAW_JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT secret is not available through the AuthClaw SecretManager.")

AUTH_SESSION_TTL_SECONDS = int(os.getenv("AUTHCLAW_MFA_SESSION_TTL_SECONDS", "600"))

def base64_url_encode(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def base64_url_decode(data: str) -> bytes:
    import base64
    padding = '=' * (4 - len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

def jwt_key_ring() -> Tuple[str, Dict[str, str]]:
    active = os.getenv("AUTHCLAW_JWT_KEY_VERSION", "v1").strip() or "v1"
    keys = {
        version.lower(): value
        for name, value in os.environ.items()
        if name.startswith("JWT_SECRET_V") and (version := name.removeprefix("JWT_SECRET_").lower()) and value
    }
    keys.setdefault(active.lower(), JWT_SECRET)
    return active.lower(), keys

def create_jwt(payload: dict) -> str:
    import hmac
    import hashlib
    active, keys = jwt_key_ring()
    header = {"alg": "HS256", "typ": "JWT", "kid": active}
    header_encoded = base64_url_encode(json.dumps(header).encode('utf-8'))
    payload_encoded = base64_url_encode(json.dumps(payload).encode('utf-8'))
    signature_input = f"{header_encoded}.{payload_encoded}".encode('utf-8')
    signature = hmac.new(keys[active].encode('utf-8'), signature_input, hashlib.sha256).digest()
    signature_encoded = base64_url_encode(signature)
    return f"{header_encoded}.{payload_encoded}.{signature_encoded}"

def decode_jwt(token: str) -> dict:
    import hmac
    import hashlib
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        header_encoded, payload_encoded, signature_encoded = parts
        header = json.loads(base64_url_decode(header_encoded).decode('utf-8'))
        if header.get("alg") != "HS256":
            return None
        signature_input = f"{header_encoded}.{payload_encoded}".encode('utf-8')
        _, keys = jwt_key_ring()
        kid = str(header.get("kid") or "").lower()
        candidates = [keys[kid]] if kid in keys else ([] if kid else list(dict.fromkeys(keys.values())))
        if not any(
            hmac.compare_digest(
                signature_encoded,
                base64_url_encode(hmac.new(secret.encode('utf-8'), signature_input, hashlib.sha256).digest()),
            )
            for secret in candidates
        ):
            return None
        payload_bytes = base64_url_decode(payload_encoded)
        payload = json.loads(payload_bytes.decode('utf-8'))
        if payload.get("exp") and int(payload["exp"]) < int(time.time()):
            return None
        if os.getenv("AUTHCLAW_ENV", "development").lower() in {"production", "prod"} and not payload.get("exp"):
            return None
        return payload
    except Exception:
        return None

def store_auth_session(session_id: str, session: dict) -> None:
    from database import engine
    from sqlalchemy import text

    with engine.connect() as conn:
        conn.execute(
            text("""
                INSERT INTO auth_mfa_sessions (
                    session_id, username, role, permissions, tenant_id, user_id,
                    email_verified, domain_verified, step, expires_at
                )
                VALUES (
                    :session_id, :username, :role, :permissions, :tenant_id, :user_id,
                    :email_verified, :domain_verified, :step, NOW() + (:ttl_seconds * INTERVAL '1 second')
                )
                ON CONFLICT (session_id) DO UPDATE SET
                    username = EXCLUDED.username,
                    role = EXCLUDED.role,
                    permissions = EXCLUDED.permissions,
                    tenant_id = EXCLUDED.tenant_id,
                    user_id = EXCLUDED.user_id,
                    email_verified = EXCLUDED.email_verified,
                    domain_verified = EXCLUDED.domain_verified,
                    step = EXCLUDED.step,
                    expires_at = EXCLUDED.expires_at
            """),
            {
                "session_id": session_id,
                "username": session["username"],
                "role": session["role"],
                "permissions": session["permissions"],
                "tenant_id": session["tenant_id"],
                "user_id": session["user_id"],
                "email_verified": session["email_verified"],
                "domain_verified": session["domain_verified"],
                "step": session["step"],
                "ttl_seconds": AUTH_SESSION_TTL_SECONDS,
            },
        )
        conn.commit()


def load_auth_session(session_id: str) -> Optional[dict]:
    from database import engine
    from sqlalchemy import text

    with engine.connect() as conn:
        conn.execute(
            text("DELETE FROM auth_mfa_sessions WHERE expires_at <= NOW()")
        )
        row = conn.execute(
            text("""
                SELECT session_id, username, role, permissions, tenant_id, user_id,
                       email_verified, domain_verified, step
                FROM auth_mfa_sessions
                WHERE session_id = :session_id AND expires_at > NOW()
            """),
            {"session_id": session_id},
        ).fetchone()
        conn.commit()

    if not row:
        return None
    return {
        "session_id": row[0],
        "username": row[1],
        "role": row[2],
        "permissions": row[3],
        "tenant_id": row[4],
        "user_id": row[5],
        "email_verified": bool(row[6]),
        "domain_verified": bool(row[7]),
        "step": row[8],
    }


def delete_auth_session(session_id: str) -> None:
    from database import engine
    from sqlalchemy import text

    with engine.connect() as conn:
        conn.execute(
            text("DELETE FROM auth_mfa_sessions WHERE session_id = :session_id"),
            {"session_id": session_id},
        )
        conn.commit()

def create_refresh_token_for_user(user_id: int, tenant_id: int, subject: str) -> str:
    from database import engine
    from sqlalchemy import text

    now_ts = int(time.time())
    jti = str(uuid.uuid4())
    expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=1)
    payload = {
        "sub": subject,
        "tenant_id": tenant_id,
        "user_id": user_id,
        "jti": jti,
        "iat": now_ts,
        "exp": now_ts + 86400
    }
    token = create_jwt(payload)
    with tenant_context(tenant_id, required=True), engine.connect() as conn:
        conn.execute(
            text("""
                INSERT INTO auth_refresh_tokens (
                    jti, tenant_id, user_id, subject, expires_at
                )
                VALUES (:jti, :tenant_id, :user_id, :subject, :expires_at)
            """),
            {
                "jti": jti,
                "tenant_id": tenant_id,
                "user_id": user_id,
                "subject": subject,
                "expires_at": expires_at,
            },
        )
        conn.commit()
    return token

def generate_reset_token() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8").rstrip("=")

def hash_reset_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def validate_refresh_token_record(payload: dict):
    from database import engine
    from sqlalchemy import text

    jti = payload.get("jti")
    user_id = payload.get("user_id")
    tenant_id = payload.get("tenant_id")
    if not jti or not user_id or not tenant_id:
        return None

    with tenant_context(tenant_id, required=True), engine.connect() as conn:
        row = conn.execute(
            text("""
                SELECT u.id, u.tenant_id, u.email, u.role, u.permissions,
                       u.email_verified, u.status
                FROM auth_refresh_tokens rt
                JOIN tenant_users u ON u.id = rt.user_id
                WHERE rt.jti = :jti
                  AND rt.user_id = :user_id
                  AND rt.tenant_id = :tenant_id
                  AND rt.revoked_at IS NULL
                  AND rt.expires_at > NOW()
                  AND u.status = 'active'
            """),
            {"jti": jti, "user_id": user_id, "tenant_id": tenant_id},
        ).fetchone()

    return row


def _tenant_id_from_domain(domain: Optional[str]) -> Optional[int]:
    if not domain:
        return None
    from database import engine
    from sqlalchemy import text

    with engine.connect() as conn:
        return conn.execute(
            text("SELECT resolve_tenant_domain(:domain)"), {"domain": domain}
        ).scalar()


def _public_oidc_providers_for_tenant(tenant_id: int) -> List[dict]:
    providers = list_provider_configs(tenant_id)
    return [
        {
            "id": provider["id"],
            "provider_type": provider["provider_type"],
            "display_name": provider["display_name"],
            "issuer": provider["issuer"],
            "enabled": provider["enabled"],
            "scopes": provider["scopes"],
        }
        for provider in providers
        if provider.get("enabled")
    ]




@app.get("/security/posture")
def phase1_security_posture(payload: dict = Depends(require_tenant_access_admin)):
    posture = security_posture()
    posture["tenant_id"] = payload["tenant_id"]
    return posture


@app.get("/security/rbac/matrix")
def security_rbac_matrix(payload: dict = Depends(require_tenant_access_admin)):
    from services.rbac_matrix import coverage_report

    report = coverage_report(app)
    report["tenant_id"] = payload["tenant_id"]
    report["enforcement_enabled"] = _rbac_enforcement_enabled()
    return report


@app.get("/security/tenant-isolation")
def security_tenant_isolation(payload: dict = Depends(require_tenant_access_admin)):
    from services.tenant_isolation_report import tenant_isolation_report

    report = tenant_isolation_report()
    report["tenant_id"] = payload["tenant_id"]
    return report


@app.get("/security/secrets/health")
def security_secret_health(payload: dict = Depends(require_tenant_access_admin)):
    from services.production_readiness import secret_management_readiness

    report = secret_management_readiness()
    report["tenant_id"] = payload["tenant_id"]
    return report


@app.get("/security/production-readiness")
def security_production_readiness(payload: dict = Depends(require_tenant_access_admin)):
    from services.production_readiness import production_readiness_report

    report = production_readiness_report(app)
    report["tenant_id"] = payload["tenant_id"]
    return report


def deliver_auth_email(recipient: str, subject: str, body: str, purpose: str) -> None:
    import smtplib
    from email.message import EmailMessage

    smtp_host = env_value("SMTP_HOST")
    smtp_port = int(env_value("SMTP_PORT", "587"))
    smtp_user = env_value("SMTP_USERNAME")
    smtp_password = env_value("SMTP_PASSWORD")
    smtp_from = env_value("SMTP_FROM") or smtp_user
    smtp_tls = env_bool("SMTP_USE_TLS", True)
    if smtp_host and "gmail" in smtp_host.lower() and smtp_password:
        smtp_password = smtp_password.replace(" ", "")

    if skip_email_delivery_for_testing():
        return

    if not smtp_host or not smtp_from:
        raise HTTPException(
            status_code=503,
            detail=f"Email delivery is not configured. Set SMTP_HOST and SMTP_FROM before {purpose}."
        )

    sendgrid_api_key = env_value("SENDGRID_API_KEY") or smtp_password
    use_sendgrid_api = (
        sendgrid_api_key
        and sendgrid_api_key.startswith("SG.")
        and ("sendgrid" in (smtp_host or "").lower() or (smtp_user or "").lower() == "apikey")
    )

    if use_sendgrid_api:
        try:
            import requests
            response = requests.post(
                "https://api.sendgrid.com/v3/mail/send",
                headers={
                    "Authorization": f"Bearer {sendgrid_api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "personalizations": [{"to": [{"email": recipient}]}],
                    "from": {"email": smtp_from},
                    "subject": subject,
                    "content": [{"type": "text/plain", "value": body}],
                },
                timeout=15,
            )
            if response.status_code not in {200, 202}:
                hint = "sendgrid_error"
                if response.status_code in {401, 403}:
                    hint = "sendgrid_authentication_failure"
                elif response.status_code == 400 and "from" in response.text.lower():
                    hint = "sendgrid_invalid_or_unverified_sender"
                logger.error(
                    "%s SendGrid API delivery failed: category=%s status=%s retryable=%s",
                    purpose,
                    hint,
                    response.status_code,
                    response.status_code == 429 or response.status_code >= 500,
                )
                raise HTTPException(
                    status_code=503,
                    detail=(
                        f"{purpose} email could not be delivered by SendGrid. Confirm the API key "
                        "has Mail Send permission and SMTP_FROM is a verified Sender Identity."
                    ),
                )
            return
        except HTTPException:
            raise
        except requests.exceptions.Timeout as exc:
            logger.error("%s SendGrid API delivery timed out.", purpose)
            raise HTTPException(
                status_code=503,
                detail=f"{purpose} email could not be delivered by SendGrid API because the connection timed out.",
            ) from exc
        except Exception as exc:
            logger.error("%s SendGrid API delivery failed: %s", purpose, exc)
            raise HTTPException(
                status_code=503,
                detail=(
                    f"{purpose} email could not be delivered by SendGrid API. Confirm outbound HTTPS "
                    "access, API key, verified Sender Identity, and SMTP_FROM address."
                ),
            ) from exc

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = smtp_from
    message["To"] = recipient
    message.set_content(body)

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as smtp:
            if smtp_tls:
                smtp.starttls()
            if smtp_user and smtp_password:
                smtp.login(smtp_user, smtp_password)
            smtp.send_message(message)
    except smtplib.SMTPAuthenticationError as exc:
        logger.error("%s SMTP authentication failed. Check SMTP_USERNAME and SMTP_PASSWORD.", purpose)
        raise HTTPException(
            status_code=503,
            detail=f"{purpose} email could not be delivered because SMTP authentication failed."
        ) from exc
    except (smtplib.SMTPSenderRefused, smtplib.SMTPRecipientsRefused) as exc:
        logger.error("%s SMTP sender or recipient was refused. Check SMTP_FROM and verified sender identity.", purpose)
        raise HTTPException(
            status_code=503,
            detail=f"{purpose} email could not be delivered because the sender or recipient was refused."
        ) from exc
    except (TimeoutError, OSError) as exc:
        logger.error("%s SMTP connection failed or timed out. host=%s port=%s tls=%s error=%s", purpose, smtp_host, smtp_port, smtp_tls, exc)
        raise HTTPException(
            status_code=503,
            detail=f"{purpose} email could not be delivered because SMTP connection failed or timed out."
        ) from exc
    except smtplib.SMTPException as exc:
        logger.error("%s SMTP delivery failed: %s", purpose, exc)
        raise HTTPException(
            status_code=503,
            detail=(
                f"{purpose} email could not be delivered. Confirm the SMTP credentials, "
                "verified Sender Identity, SMTP_FROM address, and outbound SMTP access."
            )
        ) from exc

def send_verification_email(recipient: str, token: str, organization_name: str) -> None:
    deliver_auth_email(
        recipient,
        "Verify your AuthClaw workspace",
        "\n".join(
            [
                f"Welcome to AuthClaw for {organization_name}.",
                "",
                "Use this verification token to complete email verification:",
                token,
                "",
                "If you did not request this workspace, ignore this message.",
            ]
        ),
        "Verification",
    )

def send_mfa_reset_email(recipient: str, token: str, organization_name: str) -> None:
    deliver_auth_email(
        recipient,
        "Reset your AuthClaw MFA setup",
        "\n".join(
            [
                f"AuthClaw received an MFA reset request for {organization_name}.",
                "",
                "Use this reset token to generate a new authenticator setup key:",
                token,
                "",
                "If you did not request this reset, ignore this message and keep your existing MFA setup.",
            ]
        ),
        "MFA reset",
    )

def send_password_reset_email(recipient: str, token: str, organization_name: str) -> None:
    deliver_auth_email(
        recipient,
        "Reset your AuthClaw password",
        "\n".join(
            [
                f"AuthClaw received a password reset request for {organization_name}.",
                "",
                "Use this one-time reset token to create a new password:",
                token,
                "",
                "This token expires soon and can only be used once.",
                "If you did not request this reset, contact your AuthClaw administrator.",
            ]
        ),
        "Password reset",
    )


def env_value(name: str, default: str = "") -> str:
    if name in SENSITIVE_ENV_NAMES:
        return SecretManager().get_secret(name) or default
    value = os.getenv(name)
    if value is not None:
        return value
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    try:
        with open(env_path, "r", encoding="utf-8") as env_file:
            for line in env_file:
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or "=" not in stripped:
                    continue
                key, raw_value = stripped.split("=", 1)
                if key.strip() == name:
                    return raw_value.strip().strip('"').strip("'")
    except OSError:
        pass
    return default


def env_bool(name: str, default: bool = False) -> bool:
    fallback = "true" if default else "false"
    return env_value(name, fallback).lower() in {"1", "true", "yes", "on"}


def skip_email_delivery_for_testing() -> bool:
    if env_value("AUTHCLAW_ENV", "development").lower() in {"production", "prod"}:
        return False
    return env_bool("SKIP_EMAIL_DELIVERY_FOR_TESTING")


def soft_fail_email_delivery_for_local() -> bool:
    production = env_value("AUTHCLAW_ENV", "development").lower() in {"production", "prod"}
    return (not production) and env_bool("AUTHCLAW_SOFT_FAIL_EMAIL_DELIVERY", True)


def skip_domain_verification_for_testing() -> bool:
    if env_value("AUTHCLAW_ENV", "development").lower() in {"production", "prod"}:
        return False
    return env_bool("SKIP_DOMAIN_VERIFICATION")


def ensure_default_tenant_policies(conn, tenant_id: int) -> None:
    from sqlalchemy import text
    import json

    existing_count = conn.execute(
        text("SELECT COUNT(*) FROM policies WHERE tenant_id = :tenant_id"),
        {"tenant_id": tenant_id},
    ).scalar() or 0
    if existing_count:
        return

    defaults = [
        {
            "name": "PII Protection",
            "type": "Security",
            "rules": {
                "pii_redaction": True,
                "detect": ["email", "phone", "aadhaar", "credit_card"],
                "action": "redact"
            },
        },
        {
            "name": "Prompt Injection Defense",
            "type": "Security",
            "rules": {
                "blocked_keywords": ["ignore previous instructions", "bypass policy", "reveal system prompt"],
                "action": "block_or_review"
            },
        },
        {
            "name": "Secrets Exfiltration Guard",
            "type": "Compliance",
            "rules": {
                "secret_detection": True,
                "detect": ["api_key", "token", "password", "private_key"],
                "action": "block"
            },
        },
    ]
    for policy in defaults:
        conn.execute(
            text("""
                INSERT INTO policies (tenant_id, name, type, rules, enabled, severity_level, version, status, published_at)
                VALUES (:tenant_id, :name, :type, :rules, true, 'HIGH', 1, 'published', NOW())
            """),
            {
                "tenant_id": tenant_id,
                "name": policy["name"],
                "type": policy["type"],
                "rules": json.dumps(policy["rules"]),
            },
        )


def activate_verified_registration(conn, registration) -> int:
    from sqlalchemy import text

    existing_tenant_id = registration._mapping.get("tenant_id")
    if existing_tenant_id:
        return existing_tenant_id

    organization_name = registration._mapping["organization_name"]
    work_email = registration._mapping["work_email"]
    domain = registration._mapping["domain"]
    full_name = registration._mapping["full_name"]
    password_hash = registration._mapping["password_hash"]
    totp_secret = encrypt_secret(decrypt_totp_secret(registration._mapping["totp_secret"]))
    mfa_enabled = True

    tenant_id = conn.execute(
        text("""
            INSERT INTO tenants (
                name, domain, email, email_verified, domain_verified,
                email_verification_token, domain_verification_token, totp_secret,
                subscription_tier, plan, tier, plan_updated_at
            )
            VALUES (
                :name, :domain, :email, true, true, NULL, :domain_token, :totp,
                'free', 'free', 'free', NOW()
            )
            RETURNING id
        """),
        {
            "name": organization_name,
            "domain": domain,
            "email": work_email,
            "domain_token": registration._mapping["domain_verification_token"],
            "totp": totp_secret,
        },
    ).scalar()

    name_parts = (full_name or "").strip().split(" ", 1)
    first_name = name_parts[0] if name_parts else None
    last_name = name_parts[1] if len(name_parts) > 1 else None
    with tenant_context(tenant_id, required=True):
        conn.execute(
            text("""
                INSERT INTO tenant_users (
                    tenant_id, first_name, last_name, email, password_hash,
                    role, permissions, email_verified, mfa_enabled,
                    totp_secret, status
                )
                VALUES (
                    :tenant_id, :first_name, :last_name, :email, :password_hash,
                    'Super Admin', 'all_access', true, :mfa_enabled,
                    :totp_secret, 'active'
                )
            """),
            {
                "tenant_id": tenant_id,
                "first_name": first_name,
                "last_name": last_name,
                "email": work_email,
                "password_hash": password_hash,
                "mfa_enabled": mfa_enabled,
                "totp_secret": totp_secret,
            },
        )
        conn.execute(
            text("UPDATE onboarding_registrations SET tenant_id = :tenant_id, activated_at = NOW() WHERE id = :id"),
            {"tenant_id": tenant_id, "id": registration._mapping["id"]},
        )
        ensure_default_tenant_policies(conn, tenant_id)
    return tenant_id


@app.get("/reports/{type}/{format}")
def get_report_endpoint(type: str, format: str, tenant_id: int = Depends(require_tenant_context)):
    from document_processing.reports import (
        generate_executive_summary_report,
        generate_technical_findings_report,
        generate_auditor_evidence_report
    )
    type = type.lower()
    format = format.lower()
    if format not in {"pdf", "csv", "json"}:
        raise HTTPException(status_code=400, detail="Invalid report format")
    
    if type == "executive":
        content = generate_executive_summary_report(format, tenant_id)
    elif type == "technical":
        content = generate_technical_findings_report(format, tenant_id)
    elif type == "auditor":
        content = generate_auditor_evidence_report(format, tenant_id)
    else:
        raise HTTPException(status_code=400, detail="Invalid report type")

    media_types = {
        "pdf": "application/pdf",
        "csv": "text/csv",
        "json": "application/json"
    }
    media_type = media_types.get(format, "application/octet-stream")
    filename = f"{type}_report.{format}"
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@app.get("/cloud/connectors/status")
def get_cloud_connectors_status():
    from document_processing.connectors import is_real_connectors_enabled, list_cloud_source_files
    from document_processing.monitoring import last_sync_time

    is_real = is_real_connectors_enabled()
    sources = ["s3", "gdrive", "onedrive", "sharepoint", "dropbox"]
    connectors = []
    
    for src in sources:
        status = "healthy" if is_real else "not_applicable"
        try:
            files = list_cloud_source_files(src)
        except Exception:
            files = None
            status = "unavailable"
        
        name_map = {
            "s3": "AWS S3 Bucket",
            "gdrive": "Google Drive",
            "onedrive": "Microsoft OneDrive",
            "sharepoint": "SharePoint Online",
            "dropbox": "Dropbox"
        }
        
        connectors.append({
            "name": name_map.get(src, src),
            "key": src,
            "enabled": is_real,
            "status": status,
            "mode": "real" if is_real else "mock",
            "files_count": len(files) if files is not None else None,
            "files": files
        })
        
    return {
        "connectors": connectors,
        "last_sync": last_sync_time,
        "background_monitor": monitor_status(),
    }

@app.post("/cloud/connectors/sync")
def sync_cloud_connectors(request: Request):
    from document_processing.monitoring import trigger_manual_sync
    requested_by = approval_actor_from_payload(optional_user_from_request(request))
    try:
        return trigger_manual_sync(requested_by)
    except (QuotaExceeded, QuotaUnavailable, HTTPException):
        raise
    except Exception:
        return JSONResponse(status_code=503, content={"status": "unavailable", "error": "Document synchronization incomplete"})

# 10. ONBOARDING & TENANT MANAGEMENT ENDPOINTS


# 11. API KEY LIFECYCLE MANAGEMENT ENDPOINTS

def get_authenticated_tenant(authorization: str = Header(None)) -> int:
    context_tenant_id = get_current_tenant_id()
    if context_tenant_id is not None:
        return int(context_tenant_id)
    return resolve_tenant_from_authorization(authorization)

@app.get("/analytics/governance")
def get_governance_analytics(tenant_id: int = Depends(get_authenticated_tenant)):
    from services.observability_service import ObservabilityService

    return ObservabilityService().governance_analytics(tenant_id)


def _remediation_runtime():
    from services.remediation_runtime import RemediationRuntime
    return RemediationRuntime()


def _remediation_error(exc: Exception):
    message = str(exc)
    status_code = 404 if "not found" in message.lower() else 400
    raise HTTPException(status_code=status_code, detail=message)


@app.get("/remediation/connectors")
def list_remediation_connectors(tenant_id: int = Depends(get_authenticated_tenant)):
    return _remediation_runtime().list_connectors(tenant_id)


@app.post("/remediation/connectors")
def create_remediation_connector(req: RemediationConnectorRequest, tenant_id: int = Depends(get_authenticated_tenant)):
    try:
        return _remediation_runtime().create_connector(tenant_id, req.model_dump())
    except Exception as exc:
        _remediation_error(exc)


@app.post("/remediation/connectors/{connector_id}/test")
def test_remediation_connector(connector_id: int, tenant_id: int = Depends(get_authenticated_tenant)):
    try:
        return _remediation_runtime().test_connector(tenant_id, connector_id)
    except Exception as exc:
        _remediation_error(exc)


@app.post("/remediation/scans")
def run_remediation_scan(req: RemediationScanRequest, tenant_id: int = Depends(get_authenticated_tenant)):
    try:
        return _remediation_runtime().run_scan(tenant_id, req.connector_id)
    except Exception as exc:
        _remediation_error(exc)


@app.get("/remediation/findings")
def list_remediation_findings(tenant_id: int = Depends(get_authenticated_tenant)):
    return _remediation_runtime().list_findings(tenant_id)


@app.post("/remediation/findings/{finding_id}/plan")
def create_remediation_plan(finding_id: int, tenant_id: int = Depends(get_authenticated_tenant)):
    try:
        return _remediation_runtime().create_plan(tenant_id, finding_id)
    except Exception as exc:
        _remediation_error(exc)


@app.post("/remediation/plans/{plan_id}/approval")
def request_remediation_plan_approval(
    plan_id: int,
    request: Request,
    tenant_id: int = Depends(get_authenticated_tenant),
):
    try:
        principal = optional_user_from_request(request)
        requested_by = approval_actor_from_payload(principal)
        return _remediation_runtime().request_plan_approval(tenant_id, plan_id, requested_by=requested_by)
    except Exception as exc:
        _remediation_error(exc)


@app.get("/remediation/workers/{worker_id}")
def get_remediation_worker(worker_id: str, tenant_id: int = Depends(get_authenticated_tenant)):
    try:
        return _remediation_runtime().get_worker(tenant_id, worker_id)
    except Exception as exc:
        _remediation_error(exc)



@app.get("/gateway/requests")
def list_gateway_requests(limit: int = 50, tenant_id: int = Depends(get_authenticated_tenant)):
    from database import engine
    from sqlalchemy import text

    capped_limit = max(1, min(limit, 200))
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                """
                SELECT request_id, tenant_id, route_id, provider, model, risk_level,
                       allowed, status, decision, duration_ms, latency, created_at, timestamp
                FROM gateway_requests
                WHERE tenant_id = :tid
                ORDER BY COALESCE(created_at, timestamp) DESC
                LIMIT :limit
                """
            ),
            {"tid": str(tenant_id), "limit": capped_limit},
        ).fetchall()

    return [dict(row._mapping) for row in rows]


@app.get("/gateway/requests/{request_id}")
def get_gateway_request(request_id: str, tenant_id: int = Depends(get_authenticated_tenant)):
    from database import engine
    from sqlalchemy import text

    with engine.connect() as conn:
        row = conn.execute(
            text(
                """
                SELECT request_id, tenant_id, route_id, provider, model, risk_level,
                       allowed, status, decision, duration_ms, latency, created_at, timestamp
                FROM gateway_requests
                WHERE request_id = :rid AND tenant_id = :tid
                ORDER BY COALESCE(created_at, timestamp) DESC
                LIMIT 1
                """
            ),
            {"rid": request_id, "tid": str(tenant_id)},
        ).fetchone()
        events = conn.execute(
            text(
                """
                SELECT sequence, agent_name, event_type, details, timestamp
                FROM agent_events
                WHERE request_id = :rid AND tenant_id = :tid
                ORDER BY COALESCE(sequence, id), id ASC
                """
            ),
            {"rid": request_id, "tid": tenant_id},
        ).fetchall()

    if row is None:
        raise HTTPException(status_code=404, detail="Gateway request not found.")

    payload = dict(row._mapping)
    payload["trace"] = [dict(event._mapping) for event in events]
    return payload


@app.get("/gateway/approvals")
def list_gateway_approvals(tenant_id: int = Depends(get_authenticated_tenant)):
    return [
        approval_response_record(record, tenant_id=tenant_id)
        for record in get_all_approvals(tenant_id=tenant_id).values()
    ]


@app.get("/gateway/approvals/{approval_id}/history")
def get_gateway_approval_history(approval_id: str, tenant_id: int = Depends(get_authenticated_tenant)):
    record = get_approval(approval_id)
    if record is None or record.get("tenant_id") != tenant_id:
        raise HTTPException(status_code=404, detail="Approval ID not found")
    return get_approval_history(approval_id, tenant_id=tenant_id)

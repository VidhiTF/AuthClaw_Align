"""AuthClaw Backend - FastAPI Application"""
import logging
import os
from dotenv import load_dotenv

# Load environment variables from .env.local
env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env.local")
if os.path.exists(env_path):
    load_dotenv(env_path)
else:
    load_dotenv()

from fastapi import FastAPI, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler, request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.bff_client_ip import validate_bff_client_ip_config
from app.core.startup_checks import validate_database_security, validate_production_environment
from app.services.abuse_controls import validate_abuse_control_config
from app.db.session import engine

validate_production_environment()
validate_abuse_control_config()
validate_bff_client_ip_config()
logger = logging.getLogger("authclaw.backend")

# Initialize FastAPI app
app = FastAPI(
    title="AuthClaw API",
    description="AI Governance & Compliance Platform Control Plane",
    version="0.1.0",
)


@app.exception_handler(HTTPException)
async def sanitized_http_exception(request: Request, exc: HTTPException):
    if exc.status_code < 500:
        return await http_exception_handler(request, exc)
    logger.error("Request failed status=%s path=%s error_type=%s", exc.status_code, request.url.path, type(exc).__name__)
    retry_after = (exc.headers or {}).get("Retry-After")
    headers = {"Retry-After": retry_after} if retry_after and retry_after.isdigit() else None
    return JSONResponse(status_code=exc.status_code, content={"detail": "Internal server error"}, headers=headers)


@app.exception_handler(Exception)
async def sanitized_unhandled_exception(request: Request, exc: Exception):
    logger.error("Unhandled request failure path=%s error_type=%s", request.url.path, type(exc).__name__)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


@app.exception_handler(RequestValidationError)
async def access_request_validation_error(request: Request, exc: RequestValidationError):
    if request.url.path == "/api/public/v1/access-requests":
        return JSONResponse(status_code=422, content={"detail": "Invalid request"})
    return await request_validation_exception_handler(request, exc)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register Authentication & Tenant Context Middleware
from app.core.auth import AuthMiddleware
app.add_middleware(AuthMiddleware)
from app.core.client_ip import ClientIPConfig, TrustedProxyMiddleware
app.add_middleware(TrustedProxyMiddleware, config=ClientIPConfig.from_environment())

# Import & register endpoints
from app.api.v1.endpoints.tenants import router as tenants_router
from app.api.v1.endpoints.gateways import router as gateways_router
from app.api.v1.endpoints.policies import router as policies_router
from app.api.v1.endpoints.redaction import router as redaction_router
from app.api.v1.endpoints.audit import router as audit_router
from app.api.v1.endpoints.workflows import router as workflows_router
from app.api.v1.endpoints.users import router as users_router
from app.api.v1.endpoints.apikeys import router as apikeys_router
from app.api.v1.endpoints.provider_credentials import router as provider_credentials_router
from app.api.v1.endpoints.auth import router as auth_router
from app.api.v1.endpoints.onboarding import router as onboarding_router
from app.api.v1.endpoints.chat import router as chat_router
from app.api.v1.endpoints.rag import router as rag_router
from app.api.v1.endpoints.ephemeral_workers import router as ephemeral_workers_router
from app.api.v1.endpoints.compliance_scores import router as compliance_scores_router
from app.api.v1.endpoints.trust_center import router as trust_center_router
from app.api.v1.endpoints.notifications import router as notifications_router
from app.api.v1.endpoints.aws import router as aws_router
from app.api.v1.endpoints.cloud import router as cloud_router
from app.api.v1.endpoints.usage_limits import router as usage_limits_router
from app.api.v1.endpoints.red_team import router as red_team_router
from app.api.v1.endpoints.access_requests import router as access_requests_router
from app.api.v1.endpoints.data_subject_requests import router as data_subject_requests_router
# Phase 16 — Evidence Repository
from app.api.v1.endpoints.evidence import router as evidence_router
# Phase 17 — Findings Dashboard
from app.api.v1.endpoints.findings import router as findings_router

app.include_router(tenants_router, prefix="/v1/tenants", tags=["tenants"])
app.include_router(gateways_router, prefix="/v1/gateways", tags=["gateways"])
app.include_router(policies_router, prefix="/v1/policies", tags=["policies"])
app.include_router(redaction_router, prefix="/v1/redaction", tags=["redaction"])
app.include_router(audit_router, prefix="/v1/audit-logs", tags=["audit-logs"])
app.include_router(workflows_router, prefix="/v1/workflows", tags=["workflows"])
app.include_router(users_router, prefix="/v1/users", tags=["users"])
app.include_router(apikeys_router, prefix="/v1/api-keys", tags=["api-keys"])
app.include_router(provider_credentials_router, prefix="/v1/provider-credentials", tags=["provider-credentials"])
app.include_router(auth_router, prefix="/v1/auth", tags=["auth"])
app.include_router(onboarding_router, prefix="/v1/onboarding", tags=["onboarding"])
app.include_router(chat_router, prefix="/v1/chat", tags=["chat"])
app.include_router(rag_router, prefix="/v1/rag", tags=["rag"])
app.include_router(ephemeral_workers_router, prefix="/v1/ephemeral-workers", tags=["ephemeral-workers"])
app.include_router(compliance_scores_router, prefix="/v1/compliance-scores", tags=["compliance-scores"])
app.include_router(trust_center_router, prefix="/v1/trust-center", tags=["trust-center"])
app.include_router(notifications_router, prefix="/v1/notifications", tags=["notifications"])
app.include_router(usage_limits_router, prefix="/v1/usage-limits", tags=["usage-limits"])
app.include_router(red_team_router, prefix="/v1/red-team", tags=["red-team"])
# Phase 14 — AWS Connector (gated behind AWS_ENABLED env flag at handler level)
app.include_router(aws_router, prefix="/v1/aws", tags=["aws"])
app.include_router(cloud_router, prefix="/v1/cloud/connectors", tags=["cloud-connectors"])
# Phase 16 — Evidence Repository
app.include_router(evidence_router, prefix="/v1/evidence", tags=["evidence"])
# Phase 17 — Findings Dashboard
app.include_router(findings_router, prefix="/v1/findings", tags=["findings"])
app.include_router(access_requests_router, prefix="/api/public/v1/access-requests", tags=["public-access-requests"])
app.include_router(data_subject_requests_router, prefix="/v1/data-subject-requests", tags=["data-subject-requests"])

# Ravi's imported console and existing client SDKs use `/api/v1`. Keep Kunal's
# `/v1` routes canonical while exposing a compatibility alias during migration.
_compatibility_routers = [
    (tenants_router, "/tenants", "tenants"),
    (gateways_router, "/gateways", "gateways"),
    (policies_router, "/policies", "policies"),
    (redaction_router, "/redaction", "redaction"),
    (audit_router, "/audit-logs", "audit-logs"),
    (workflows_router, "/workflows", "workflows"),
    (users_router, "/users", "users"),
    (apikeys_router, "/api-keys", "api-keys"),
    (provider_credentials_router, "/provider-credentials", "provider-credentials"),
    (auth_router, "/auth", "auth"),
    (onboarding_router, "/onboarding", "onboarding"),
    (chat_router, "/chat", "chat"),
    (rag_router, "/rag", "rag"),
    (ephemeral_workers_router, "/ephemeral-workers", "ephemeral-workers"),
    (compliance_scores_router, "/compliance-scores", "compliance-scores"),
    (trust_center_router, "/trust-center", "trust-center"),
    (notifications_router, "/notifications", "notifications"),
    (usage_limits_router, "/usage-limits", "usage-limits"),
    (red_team_router, "/red-team", "red-team"),
    (aws_router, "/aws", "aws"),
    (cloud_router, "/cloud/connectors", "cloud-connectors"),
    (evidence_router, "/evidence", "evidence"),
    (findings_router, "/findings", "findings"),
    (data_subject_requests_router, "/data-subject-requests", "data-subject-requests"),
]
for _router, _path, _tag in _compatibility_routers:
    app.include_router(_router, prefix=f"/api/v1{_path}", tags=[_tag], include_in_schema=False)



@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "authclaw-backend",
    }


@app.on_event("startup")
async def startup_event():
    """Initialize app only after database security invariants pass."""
    with engine.connect() as connection:
        validate_database_security(connection)
    print("AuthClaw Backend Starting Up...")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    print("AuthClaw Backend Shutting Down...")

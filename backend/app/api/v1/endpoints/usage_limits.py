import os
from datetime import datetime, time, timezone

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.auth import get_tenant_db, require_roles
from app.db.models import AuditLogMetadata, Tenant
from app.services.tier_limits import get_tier_limits

router = APIRouter()


class UsageLimitResponse(BaseModel):
    tenant_id: str
    limits_enabled: bool
    requests_per_minute: int
    burst_10_seconds: int
    daily_requests_limit: int
    max_body_bytes: int
    max_daily_spend_usd: float
    estimated_cost_per_1k_requests_usd: float
    requests_today: int
    blocked_today: int
    allowed_today: int
    bytes_today: int
    estimated_spend_today_usd: float
    requests_remaining_today: int
    spend_remaining_today_usd: float


def _env_bool(name: str, fallback: bool) -> bool:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return fallback
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, fallback: int) -> int:
    try:
        return int(os.getenv(name, str(fallback)))
    except ValueError:
        return fallback


def _env_float(name: str, fallback: float) -> float:
    try:
        return float(os.getenv(name, str(fallback)))
    except ValueError:
        return fallback


@router.get("", response_model=UsageLimitResponse, dependencies=[require_roles(["owner", "admin"])])
def get_usage_limits(request: Request, db: Session = Depends(get_tenant_db)):
    tenant_id = request.state.tenant_id
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    tier_limits = get_tier_limits(tenant.tier if tenant else "starter")
    today_start = datetime.combine(datetime.now(timezone.utc).date(), time.min, tzinfo=timezone.utc)

    total_requests = db.query(func.count(AuditLogMetadata.id)).filter(
        AuditLogMetadata.tenant_id == tenant_id,
        AuditLogMetadata.created_at >= today_start,
    ).scalar() or 0
    blocked_requests = db.query(func.count(AuditLogMetadata.id)).filter(
        AuditLogMetadata.tenant_id == tenant_id,
        AuditLogMetadata.created_at >= today_start,
        AuditLogMetadata.action == "block",
    ).scalar() or 0
    bytes_today = db.query(func.coalesce(func.sum(AuditLogMetadata.request_size), 0)).filter(
        AuditLogMetadata.tenant_id == tenant_id,
        AuditLogMetadata.created_at >= today_start,
    ).scalar() or 0

    daily_limit = _env_int("GATEWAY_RATE_LIMIT_DAILY", tier_limits.daily_requests)
    per_1k_cost = _env_float("GATEWAY_ESTIMATED_COST_PER_1K_REQUESTS_USD", 1.0)
    max_spend = _env_float("GATEWAY_MAX_DAILY_SPEND_USD", tier_limits.max_daily_spend_usd)
    estimated_spend = round((total_requests / 1000.0) * per_1k_cost, 6)

    return UsageLimitResponse(
        tenant_id=str(tenant_id),
        limits_enabled=_env_bool("GATEWAY_RATE_LIMIT_ENABLED", True),
        requests_per_minute=_env_int("GATEWAY_RATE_LIMIT_PER_MINUTE", tier_limits.requests_per_minute),
        burst_10_seconds=_env_int("GATEWAY_RATE_LIMIT_BURST_10S", tier_limits.burst_10_seconds),
        daily_requests_limit=daily_limit,
        max_body_bytes=_env_int("GATEWAY_MAX_BODY_BYTES", tier_limits.max_body_bytes),
        max_daily_spend_usd=max_spend,
        estimated_cost_per_1k_requests_usd=per_1k_cost,
        requests_today=total_requests,
        blocked_today=blocked_requests,
        allowed_today=max(0, total_requests - blocked_requests),
        bytes_today=int(bytes_today),
        estimated_spend_today_usd=estimated_spend,
        requests_remaining_today=max(0, daily_limit - total_requests),
        spend_remaining_today_usd=max(0.0, round(max_spend - estimated_spend, 6)),
    )

import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from database import engine


PLAN_LIMITS = {
    "free": {"requests_per_minute": 30, "monthly_requests": 1000, "background_workers": 1},
    "starter": {"requests_per_minute": 60, "monthly_requests": 10000, "background_workers": 2},
    "professional": {"requests_per_minute": 300, "monthly_requests": 100000, "background_workers": 5},
    "enterprise": {"requests_per_minute": 1200, "monthly_requests": 1000000, "background_workers": 20},
    "unlimited": {"requests_per_minute": 1000000, "monthly_requests": None, "background_workers": 1000},
}


class TenantPlanService:
    def get_plan(self, tenant_id: int) -> Dict[str, Any]:
        self._ensure_columns()
        with engine.connect() as conn:
            tenant = conn.execute(
                text("""
                    SELECT id, name, COALESCE(subscription_tier, plan, tier, 'enterprise') AS plan,
                           usage_count, tokens_used, plan_override, plan_updated_at
                    FROM tenants
                    WHERE id = :tenant_id
                """),
                {"tenant_id": tenant_id},
            ).fetchone()
            try:
                usage = conn.execute(
                    text("""
                        SELECT
                            COUNT(*) AS requests,
                            SUM(CASE WHEN allowed THEN 0 ELSE 1 END) AS blocked,
                            COALESCE(MIN(remaining), 0) AS min_remaining,
                            COALESCE(MAX(limit_count), 0) AS rate_limit
                        FROM rate_limit_events
                        WHERE tenant_id = :tenant_id
                          AND created_at >= date_trunc('month', NOW())
                    """),
                    {"tenant_id": tenant_id},
                ).fetchone()
            except SQLAlchemyError:
                usage = None
            try:
                history = conn.execute(
                    text("""
                        SELECT id, created_at, response
                        FROM audit_logs
                        WHERE tenant_id = :tenant_id
                          AND user_query LIKE 'Tenant plan%'
                        ORDER BY id DESC
                        LIMIT 20
                    """),
                    {"tenant_id": tenant_id},
                ).fetchall()
            except SQLAlchemyError:
                history = []
        if not tenant:
            return {}
        plan = str(tenant.plan or "enterprise").lower()
        if plan == "pro":
            plan = "professional"
        limits = self._limits(plan)
        monthly_limit = limits["monthly_requests"]
        requests_used = int((usage.requests if usage else 0) or tenant.usage_count or 0)
        remaining_quota = None if monthly_limit is None else max(0, int(monthly_limit) - requests_used)
        return {
            "tenant_id": tenant.id,
            "tenant_name": tenant.name,
            "current_plan": plan,
            "supported_plans": list(PLAN_LIMITS.keys()),
            "limits": limits,
            "usage": {
                "requests": requests_used,
                "tokens_used": int(tenant.tokens_used or 0),
                "blocked_requests": int((usage.blocked if usage else 0) or 0),
                "remaining_quota": remaining_quota,
                "rate_limit": int((usage.rate_limit if usage else 0) or limits["requests_per_minute"]),
                "remaining_rate_window": int((usage.min_remaining if usage else 0) or limits["requests_per_minute"]),
            },
            "admin_override": self._decode_override(tenant.plan_override),
            "plan_updated_at": tenant.plan_updated_at.isoformat() if tenant.plan_updated_at else None,
            "upgrade_history": [
                {
                    "id": row.id,
                    "timestamp": row.created_at.isoformat() if row.created_at else None,
                    "event": row.response,
                }
                for row in history
            ],
        }

    def update_plan(self, tenant_id: int, plan: str, actor: str, override_reason: str = "") -> Dict[str, Any]:
        self._ensure_columns()
        normalized = plan.lower().strip()
        aliases = {"pro": "professional"}
        normalized = aliases.get(normalized, normalized)
        if normalized not in PLAN_LIMITS:
            raise ValueError("Unsupported tenant plan.")
        override = {"actor": actor, "reason": override_reason, "updated_at": datetime.now(timezone.utc).isoformat()}
        with engine.connect() as conn:
            conn.execute(
                text("""
                    UPDATE tenants
                    SET subscription_tier = :plan,
                        plan = :plan,
                        tier = :plan,
                        plan_override = :override,
                        plan_updated_at = NOW()
                    WHERE id = :tenant_id
                """),
                {"tenant_id": tenant_id, "plan": normalized, "override": str(override)},
            )
            conn.commit()
        from verify_audit import create_audit_block

        create_audit_block(
            query=f"Tenant plan override to {normalized}",
            response=f"Tenant plan changed to {normalized} by {actor}.",
            allowed=True,
            risk_level="MEDIUM",
            approval_status="N/A",
            tenant_id=tenant_id,
            username=actor,
        )
        return self.get_plan(tenant_id)

    def _limits(self, plan: str) -> Dict[str, Any]:
        limits = dict(PLAN_LIMITS.get(plan, PLAN_LIMITS["enterprise"]))
        env_limit = os.getenv(f"AUTHCLAW_RATE_LIMIT_{plan.upper()}_RPM")
        if env_limit:
            try:
                limits["requests_per_minute"] = max(1, int(env_limit))
            except ValueError:
                pass
        return limits

    def _decode_override(self, raw: Any) -> Dict[str, Any]:
        if not raw:
            return {}
        if isinstance(raw, dict):
            return raw
        try:
            import ast

            parsed = ast.literal_eval(str(raw))
            return parsed if isinstance(parsed, dict) else {"raw": raw}
        except Exception:
            return {"raw": raw}

    def _ensure_columns(self) -> None:
        with engine.connect() as conn:
            conn.execute(text("ALTER TABLE tenants ADD COLUMN IF NOT EXISTS subscription_tier VARCHAR(50) DEFAULT 'enterprise'"))
            conn.execute(text("ALTER TABLE tenants ADD COLUMN IF NOT EXISTS plan VARCHAR(50) DEFAULT 'enterprise'"))
            conn.execute(text("ALTER TABLE tenants ADD COLUMN IF NOT EXISTS tier VARCHAR(50) DEFAULT 'enterprise'"))
            conn.execute(text("ALTER TABLE tenants ADD COLUMN IF NOT EXISTS plan_override TEXT"))
            conn.execute(text("ALTER TABLE tenants ADD COLUMN IF NOT EXISTS plan_updated_at TIMESTAMP"))
            conn.commit()

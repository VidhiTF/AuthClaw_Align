import os
from typing import Tuple

from sqlalchemy import text

from database import engine


def _truthy(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class WorkerThrottle:
    def __init__(self, worker_type: str = "remediation") -> None:
        self.worker_type = worker_type
        self.limit = int(os.getenv(f"AUTHCLAW_{worker_type.upper()}_WORKER_LIMIT", os.getenv("AUTHCLAW_WORKER_LIMIT", "25")))
        self.redis_url = os.getenv("REDIS_URL")

    def check(self, tenant_id: int) -> Tuple[bool, int]:
        active = self._active_count(tenant_id)
        allowed = active < self.limit
        self._record(tenant_id, active, allowed)
        return allowed, active

    def enforce(self, tenant_id: int) -> None:
        allowed, active = self.check(tenant_id)
        if not allowed:
            raise RuntimeError(f"{self.worker_type} worker throttle exceeded: {active}/{self.limit} active")

    def _active_count(self, tenant_id: int) -> int:
        if self.redis_url:
            try:
                import redis

                client = redis.Redis.from_url(self.redis_url)
                key = f"authclaw:workers:{self.worker_type}:{tenant_id}:active"
                return int(client.get(key) or 0)
            except Exception:
                if _truthy("AUTHCLAW_REQUIRE_REDIS_WORKER_THROTTLE", False):
                    raise
        with engine.connect() as conn:
            value = conn.execute(
                text(
                    """
                    SELECT COUNT(*)
                    FROM remediation_worker_runs
                    WHERE tenant_id = :tenant_id
                      AND status IN ('running', 'queued')
                      AND expires_at > NOW()
                    """
                ),
                {"tenant_id": tenant_id},
            ).scalar()
        return int(value or 0)

    def _record(self, tenant_id: int, active: int, allowed: bool) -> None:
        try:
            with engine.connect() as conn:
                conn.execute(
                    text(
                        """
                        INSERT INTO worker_throttle_events (
                            tenant_id, worker_type, throttle_key, limit_count,
                            active_count, allowed, created_at
                        )
                        VALUES (
                            :tenant_id, :worker_type, :throttle_key, :limit_count,
                            :active_count, :allowed, NOW()
                        )
                        """
                    ),
                    {
                        "tenant_id": tenant_id,
                        "worker_type": self.worker_type,
                        "throttle_key": f"{self.worker_type}:{tenant_id}",
                        "limit_count": self.limit,
                        "active_count": active,
                        "allowed": allowed,
                    },
                )
                conn.commit()
        except Exception:
            pass

from abc import ABC, abstractmethod
from typing import List, Dict, Any

from services import quota_service
from services.tenant_context import get_current_tenant_id


def admit_provider_call(provider: str, model: str) -> None:
    """Charge external model attempts separately from authenticated ingress."""
    tenant_id = get_current_tenant_id()
    if not tenant_id:
        raise quota_service.QuotaUnavailable("Verified tenant context is required")
    quota_service.admit(provider_quota_tenant(tenant_id), provider_model=f"{provider}:{model}")


def provider_quota_tenant(tenant_id: str) -> str:
    """Map agent-local IDs to the gateway's verified tenant ledger via stored binding."""
    try:
        from database import engine
        from sqlalchemy import text
        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT control_plane_id FROM tenants WHERE id = :tenant_id"),
                {"tenant_id": tenant_id},
            ).fetchone()
        if row is None:
            raise quota_service.QuotaUnavailable("Tenant binding missing")
        return str(row[0]) if row[0] else f"agent:{tenant_id}"
    except Exception as exc:
        quota_service.record_unavailable()
        raise quota_service.QuotaUnavailable("Tenant quota binding unavailable") from exc


class BaseProvider(ABC):
    @abstractmethod
    def generate(self, prompt: str, system_instruction: str = None, history: List[Dict[str, Any]] = None, **kwargs) -> str:
        """
        Generate a text response from the model provider.
        """
        pass

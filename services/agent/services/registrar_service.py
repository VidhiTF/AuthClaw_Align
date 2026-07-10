from typing import Optional

from verify_audit import log_agent_event, record_gateway_request


class RegistrarService:
    def register_gateway_request(
        self,
        *,
        request_id: str,
        session_id: str,
        tenant_id: int,
        risk_level: str,
        allowed: bool,
        status: str,
        route_id: Optional[str],
        provider: str,
        model: str,
        duration_ms: int,
        decision: Optional[str],
    ) -> None:
        record_gateway_request(
            risk_level=risk_level,
            allowed=allowed,
            status=status,
            request_id=request_id,
            tenant_id=str(tenant_id),
            route_id=route_id,
            provider=provider,
            model=model,
            latency=duration_ms,
            decision=decision,
            duration_ms=duration_ms,
        )
        log_agent_event(
            tenant_id=tenant_id,
            session_id=session_id,
            request_id=request_id,
            sequence=10000,
            agent_name="Registrar Agent",
            event_type="GATEWAY_REQUEST_RECORDED",
            details=(
                f"Recorded gateway request lifecycle metadata. "
                f"Status: {status}; decision: {decision}; provider: {provider}; model: {model}."
            ),
        )

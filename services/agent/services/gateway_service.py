import json
import logging
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from database import engine
from memory import add_message
from sqlalchemy import text
from services.registrar_service import RegistrarService
from verify_audit import (
    clear_agent_event_context,
    log_agent_event,
    set_agent_event_context,
)

logger = logging.getLogger("authclaw.gateway_service")


class GatewayProviderConfigurationError(Exception):
    pass


class GatewayProviderUnavailableError(Exception):
    def __init__(self, message: str, *, request_id: Optional[str] = None, trace: Optional[list] = None):
        super().__init__(message)
        self.request_id = request_id
        self.trace = trace or []


@dataclass
class GatewayExecution:
    request_id: str
    tenant_id: int
    session_id: str
    result: Dict[str, Any]
    trace: list
    provider: str
    model: str
    route_id: Optional[str]
    decision: Optional[str]


class GatewayService:
    def __init__(
        self,
        graph: Any,
        resolve_tenant: Callable[[Optional[str], Optional[str]], int],
        decode_jwt: Callable[[str], Optional[dict]],
    ):
        self.graph = graph
        self.resolve_tenant = resolve_tenant
        self.decode_jwt = decode_jwt

    def execute_chat(
        self,
        *,
        message: str,
        session_id: Optional[str],
        x_api_key: Optional[str],
        authorization: Optional[str],
        username: Optional[str] = None,
        route_id: Optional[str] = None,
        provider: str = "AuthClaw Gateway",
        model: str = "authclaw-gateway",
    ) -> GatewayExecution:
        tenant_id = self.resolve_tenant(x_api_key, authorization)
        request_id = f"req-{uuid.uuid4()}"
        resolved_session_id = session_id or f"session-{uuid.uuid4()}"
        resolved_username = username or self._username_from_authorization(authorization)

        start = time.perf_counter()
        token = set_agent_event_context(request_id)
        try:
            result = self.graph.invoke(
                {
                    "message": message,
                    "session_id": resolved_session_id,
                    "username": resolved_username,
                    "tenant_id": tenant_id,
                    "request_id": request_id,
                    "route_id": route_id,
                    "provider": provider,
                    "model": model,
                }
            )
        except ValueError as e:
            raise GatewayProviderConfigurationError(str(e)) from e
        except Exception as e:
            latency_ms = int((time.perf_counter() - start) * 1000)
            RegistrarService().register_gateway_request(
                risk_level="UNKNOWN",
                allowed=False,
                status="provider_unavailable",
                request_id=request_id,
                session_id=resolved_session_id,
                tenant_id=tenant_id,
                route_id=route_id,
                provider=provider,
                model=model,
                duration_ms=latency_ms,
                decision="PROVIDER_UNAVAILABLE",
            )
            trace = self.get_trace(request_id=request_id, session_id=resolved_session_id, tenant_id=tenant_id)
            self.persist_latest_message_trace(resolved_session_id, trace)
            raise GatewayProviderUnavailableError(str(e), request_id=request_id, trace=trace) from e
        finally:
            clear_agent_event_context(token)

        latency_ms = int((time.perf_counter() - start) * 1000)
        allowed = result.get("allowed", True)
        risk_level = result.get("risk_level", "LOW")
        status = (
            "pending_approval"
            if result.get("approval_status") == "PENDING_APPROVAL"
            else ("allowed" if allowed else "blocked")
        )

        resolved_route_id = result.get("route_id") or route_id
        resolved_provider = result.get("provider") or provider
        resolved_model = result.get("model") or model
        decision = result.get("decision")

        RegistrarService().register_gateway_request(
            risk_level=risk_level,
            allowed=allowed,
            status=status,
            request_id=request_id,
            session_id=resolved_session_id,
            tenant_id=tenant_id,
            route_id=resolved_route_id,
            provider=resolved_provider,
            model=resolved_model,
            duration_ms=latency_ms,
            decision=decision,
        )

        trace = self.get_trace(request_id=request_id, session_id=resolved_session_id, tenant_id=tenant_id)
        self.persist_latest_message_trace(resolved_session_id, trace)

        return GatewayExecution(
            request_id=request_id,
            tenant_id=tenant_id,
            session_id=resolved_session_id,
            result=result,
            trace=trace,
            provider=resolved_provider,
            model=resolved_model,
            route_id=resolved_route_id,
            decision=decision,
        )

    def execute_approval(
        self,
        *,
        approval_record: Dict[str, Any],
        authorization: Optional[str],
        x_api_key: Optional[str],
        username: Optional[str] = None,
        provider: str = "AuthClaw Gateway",
        model: str = "authclaw-gateway",
    ) -> GatewayExecution:
        tenant_id = approval_record.get("tenant_id")
        if tenant_id is None:
            tenant_id = self.resolve_tenant(x_api_key, authorization)
        tenant_id = int(tenant_id)

        request_id = f"req-{uuid.uuid4()}"
        resolved_session_id = approval_record.get("correlation_id") or f"approval-{approval_record['approval_id']}"
        resolved_username = username or self._username_from_authorization(authorization)

        start = time.perf_counter()
        token = set_agent_event_context(request_id)
        try:
            log_agent_event(
                tenant_id=tenant_id,
                session_id=resolved_session_id,
                request_id=request_id,
                agent_name="Approval Execute",
                event_type="APPROVAL_EXECUTION_STARTED",
                details=(
                    f"Executing approved request {approval_record['approval_id']} "
                    f"from original request {approval_record.get('request_id')}."
                ),
            )
            result = self.graph.invoke(
                {
                    "message": approval_record["query"],
                    "session_id": resolved_session_id,
                    "username": resolved_username,
                    "tenant_id": tenant_id,
                    "request_id": request_id,
                    "approval_id": approval_record["approval_id"],
                    "approval_status": "APPROVED",
                    "original_request_id": approval_record.get("request_id"),
                    "provider": provider,
                    "model": model,
                }
            )
        except ValueError as e:
            raise GatewayProviderConfigurationError(str(e)) from e
        except Exception as e:
            latency_ms = int((time.perf_counter() - start) * 1000)
            RegistrarService().register_gateway_request(
                risk_level=approval_record.get("risk_level", "UNKNOWN"),
                allowed=False,
                status="provider_unavailable",
                request_id=request_id,
                session_id=resolved_session_id,
                tenant_id=tenant_id,
                route_id=None,
                provider=provider,
                model=model,
                duration_ms=latency_ms,
                decision="PROVIDER_UNAVAILABLE",
            )
            trace = self.get_trace(request_id=request_id, session_id=resolved_session_id, tenant_id=tenant_id)
            self.persist_latest_message_trace(resolved_session_id, trace)
            raise GatewayProviderUnavailableError(str(e), request_id=request_id, trace=trace) from e
        finally:
            clear_agent_event_context(token)

        latency_ms = int((time.perf_counter() - start) * 1000)
        allowed = result.get("allowed", True)
        risk_level = result.get("risk_level", approval_record.get("risk_level", "LOW"))
        status = "allowed" if allowed else "blocked"
        resolved_route_id = result.get("route_id")
        resolved_provider = result.get("provider") or provider
        resolved_model = result.get("model") or model
        decision = result.get("decision")

        RegistrarService().register_gateway_request(
            risk_level=risk_level,
            allowed=allowed,
            status=status,
            request_id=request_id,
            session_id=resolved_session_id,
            tenant_id=tenant_id,
            route_id=resolved_route_id,
            provider=resolved_provider,
            model=resolved_model,
            duration_ms=latency_ms,
            decision=decision,
        )

        trace = self.get_trace(request_id=request_id, session_id=resolved_session_id, tenant_id=tenant_id)
        self.persist_latest_message_trace(resolved_session_id, trace)

        return GatewayExecution(
            request_id=request_id,
            tenant_id=tenant_id,
            session_id=resolved_session_id,
            result=result,
            trace=trace,
            provider=resolved_provider,
            model=resolved_model,
            route_id=resolved_route_id,
            decision=decision,
        )

    def format_chat_response(self, execution: GatewayExecution) -> Dict[str, Any]:
        result = execution.result
        allowed = result.get("allowed", True)
        risk_level = result.get("risk_level", "LOW")

        if not allowed:
            category = result.get("block_category", "prompt_injection")
            blocked_data = {
                "category": category,
                "reason": "policy_violation",
                "requestId": execution.request_id,
            }
            add_message(execution.session_id, "blocked", json.dumps(blocked_data))
            return {
                "request_id": execution.request_id,
                "status": "blocked",
                "reason": "policy_violation",
                "category": category,
                "decision": execution.decision,
                "trace": execution.trace,
            }

        if result.get("approval_status") == "PENDING_APPROVAL":
            approval_reason = result.get("approval_reason") or "high_risk"
            approval_data = {
                "content": f"Action paused: {approval_reason.replace('_', ' ')} requires human approval.",
                "approvalId": result.get("approval_id"),
                "approvalReason": approval_reason,
                "riskLevel": risk_level,
                "requestId": execution.request_id,
            }
            add_message(execution.session_id, "system", json.dumps(approval_data))
            return {
                "request_id": execution.request_id,
                "status": "approval_required",
                "approval_status": "PENDING_APPROVAL",
                "approval_id": result.get("approval_id"),
                "approval_reason": approval_reason,
                "risk_level": risk_level,
                "decision": execution.decision,
                "trace": execution.trace,
            }

        return {
            "request_id": execution.request_id,
            "response": result.get("response", "No response generated"),
            "risk_level": risk_level,
            "provider": execution.provider,
            "model": execution.model,
            "route_id": execution.route_id,
            "decision": execution.decision,
            "trace": execution.trace,
        }

    def get_trace(self, *, request_id: str, session_id: str, tenant_id: int) -> list:
        try:
            with engine.connect() as conn:
                events = conn.execute(
                    text(
                        """
                        SELECT agent_name, event_type, details, request_id, sequence
                        FROM agent_events
                        WHERE request_id = :rid
                           OR (request_id IS NULL AND session_id = :sid AND tenant_id = :tid)
                        ORDER BY id ASC
                        """
                    ),
                    {"rid": request_id, "sid": session_id, "tid": tenant_id},
                ).fetchall()

            trace = []
            for event in events:
                trace.append(
                    {
                        "agent": event[0],
                        "event": event[1],
                        "details": event[2],
                        "request_id": event[3],
                        "sequence": event[4],
                    }
                )
            return trace
        except Exception as ex:
            logger.error(f"Failed to fetch gateway trace events: {ex}", exc_info=True)
            return []

    def persist_latest_message_trace(self, session_id: str, trace: list) -> None:
        trace_json = json.dumps(trace)
        try:
            with engine.connect() as conn:
                last_msg = conn.execute(
                    text("SELECT id FROM chat_messages WHERE session_id = :sid ORDER BY id DESC LIMIT 1"),
                    {"sid": session_id},
                ).fetchone()
                if last_msg:
                    conn.execute(
                        text("UPDATE chat_messages SET trace = :trace WHERE id = :id"),
                        {"trace": trace_json, "id": last_msg[0]},
                    )
                    conn.commit()
        except Exception as ex:
            logger.error(f"Failed to persist execution trace on chat message: {ex}", exc_info=True)

    def _username_from_authorization(self, authorization: Optional[str]) -> str:
        if not authorization:
            return "admin_user"

        token = authorization[7:] if authorization.startswith("Bearer ") else authorization
        try:
            payload = self.decode_jwt(token)
            if payload and "sub" in payload:
                return payload["sub"]
        except Exception:
            pass
        return "admin_user"

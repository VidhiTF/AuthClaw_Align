"""Shared event-backbone helpers for backend audit publishers."""

from __future__ import annotations

import json
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

AUDIT_EVENTS_TOPIC = "audit.events"
AUDIT_DLQ_TOPIC = "audit.deadletter"
GATEWAY_TRAFFIC_TOPIC = "gateway.traffic"

_EVENT_NAMESPACE = uuid.UUID("3bd78033-64da-4a48-bd4f-9c105da706c7")
_metrics: defaultdict[str, int] = defaultdict(int)


def stable_event_id(*, event_type: str, tenant_id: str, subject_id: str, action: str, trace: list[str] | None = None) -> str:
    identity = {
        "event_type": event_type,
        "tenant_id": tenant_id,
        "subject_id": subject_id,
        "action": action,
        "trace": trace or [],
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return str(uuid.uuid5(_EVENT_NAMESPACE, canonical))


def audit_event(
    *,
    event_type: str,
    tenant_id: str,
    subject_id: str,
    identity_action: str,
    action: str,
    reason: str,
    provider: str,
    request_id: str = "",
    frameworks: list[str] | None = None,
    trace: list[str] | None = None,
) -> dict[str, Any]:
    execution_trace = trace or []
    return {
        "id": stable_event_id(
            event_type=event_type,
            tenant_id=tenant_id,
            subject_id=subject_id,
            action=identity_action,
            trace=execution_trace,
        ),
        "request_id": request_id,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "tenant_id": tenant_id,
        "policy_id": "",
        "action": action,
        "reason": reason,
        "provider": provider,
        "model": "",
        "prompt_count": 0,
        "request_size": 0,
        "response_status": 0,
        "duration_ms": 0,
        "frameworks_affected": frameworks or [],
        "execution_trace": execution_trace,
    }


def increment_metric(name: str, value: int = 1) -> None:
    _metrics[name] += value


def make_kafka_producer() -> Any:
    import os
    from kafka import KafkaProducer  # type: ignore[import-untyped]

    brokers = os.getenv("KAFKA_BROKERS", "localhost:9092").split(",")
    return KafkaProducer(
        bootstrap_servers=brokers,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        key_serializer=lambda k: k.encode("utf-8") if k else b"",
        acks=1,
    )


def publish_audit_event(producer: Any, tenant_id: str, event: dict[str, Any]) -> Exception | None:
    if not producer:
        return None
    try:
        future = producer.send(AUDIT_EVENTS_TOPIC, key=tenant_key(tenant_id), value=event)
        future.get(timeout=5)
    except Exception as exc:
        increment_metric("backend_audit_publish_failures_total")
        return exc
    return None


def metrics_snapshot() -> dict[str, int]:
    return dict(_metrics)


def tenant_key(tenant_id: Any) -> str:
    return str(tenant_id or "")

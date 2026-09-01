"""Transport boundary and topic configuration for backend audit publication."""

from __future__ import annotations

import json
import os
from typing import Any, Protocol

AUDIT_EVENTS_TOPIC = os.getenv("KAFKA_AUDIT_TOPIC", "audit.events")
AUDIT_DLQ_TOPIC = os.getenv("KAFKA_DLQ_TOPIC", "audit.deadletter")
GATEWAY_TRAFFIC_TOPIC = os.getenv("KAFKA_GATEWAY_TRAFFIC_TOPIC", "gateway.traffic")
AUDIT_STREAM_TRANSPORT = os.getenv("AUDIT_STREAM_TRANSPORT", "kafka").strip().lower() or "kafka"
if AUDIT_STREAM_TRANSPORT != "kafka":
    raise RuntimeError(
        f"unsupported AUDIT_STREAM_TRANSPORT {AUDIT_STREAM_TRANSPORT!r}; supported value: kafka"
    )


class AuditPublisher(Protocol):
    def publish(self, tenant_id: str, event: dict[str, Any]) -> None: ...


class KafkaAuditPublisher:
    def __init__(self) -> None:
        from kafka import KafkaProducer  # type: ignore[import-untyped]

        self._producer = KafkaProducer(
            bootstrap_servers=os.getenv("KAFKA_BROKERS", "localhost:9092").split(","),
            value_serializer=lambda value: json.dumps(value).encode("utf-8"),
            key_serializer=lambda key: key.encode("utf-8") if key else b"",
            acks=1,
        )

    def publish(self, tenant_id: str, event: dict[str, Any]) -> None:
        self._producer.send(
            AUDIT_EVENTS_TOPIC,
            key=str(tenant_id or ""),
            value=event,
        ).get(timeout=5)


def make_audit_publisher() -> AuditPublisher:
    return KafkaAuditPublisher()

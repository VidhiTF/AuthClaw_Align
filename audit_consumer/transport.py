"""Transport-neutral consume/ack/retry boundary with the current Kafka adapter."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Callable, Protocol

GATEWAY_TRAFFIC_TOPIC = "gateway.traffic"
AUDIT_EVENTS_TOPIC = "audit.events"
AUDIT_DLQ_TOPIC = "audit.deadletter"
DEFAULT_CONSUMER_TOPICS = [GATEWAY_TRAFFIC_TOPIC, AUDIT_EVENTS_TOPIC]
logger = logging.getLogger("audit_consumer.transport")


@dataclass(frozen=True)
class AuditMessage:
    value: dict[str, Any]
    offset: int
    _position: Any


class AuditConsumer(Protocol):
    group_id: str
    topics: list[str]
    dlq_topic: str

    def poll(self, timeout_ms: int) -> list[list[AuditMessage]]: ...
    def ack(self, message: AuditMessage) -> None: ...
    def retry(self, message: AuditMessage) -> None: ...
    def publish_dlq(self, payload: dict[str, Any], reason: str) -> None: ...
    def close(self) -> None: ...


class KafkaAuditConsumer:
    def __init__(self, observe_lag: Callable[[str, int], None]) -> None:
        from kafka import KafkaConsumer, KafkaProducer

        brokers = os.getenv("KAFKA_BROKERS", "localhost:9092").split(",")
        self.topics = [
            topic.strip()
            for topic in os.getenv("KAFKA_TOPICS", ",".join(DEFAULT_CONSUMER_TOPICS)).split(",")
            if topic.strip()
        ]
        self.group_id = os.getenv("KAFKA_GROUP_ID", "authclaw-audit-consumer")
        self.dlq_topic = os.getenv("KAFKA_DLQ_TOPIC", AUDIT_DLQ_TOPIC)
        self._observe_lag = observe_lag
        self._consumer = KafkaConsumer(
            *self.topics,
            bootstrap_servers=brokers,
            group_id=self.group_id,
            value_deserializer=lambda value: json.loads(value.decode("utf-8")),
            auto_offset_reset="earliest",
            enable_auto_commit=False,
        )
        self._dlq = KafkaProducer(
            bootstrap_servers=brokers,
            value_serializer=lambda value: json.dumps(value).encode("utf-8"),
            key_serializer=lambda key: key.encode("utf-8") if key else b"",
            acks=1,
        )

    def poll(self, timeout_ms: int) -> list[list[AuditMessage]]:
        records = self._consumer.poll(timeout_ms=timeout_ms)
        batches: list[list[AuditMessage]] = []
        for position, batch in records.items():
            if batch:
                try:
                    end = self._consumer.end_offsets([position])[position]
                    self._observe_lag(
                        f"audit_consumer_lag_{position.topic}_{position.partition}",
                        max(0, end - batch[-1].offset - 1),
                    )
                except Exception as exc:
                    logger.warning("Unable to observe Kafka consumer lag: %s", exc)
            batches.append(
                [
                    AuditMessage(value=item.value, offset=item.offset, _position=position)
                    for item in batch
                ]
            )
        return batches

    def ack(self, _message: AuditMessage) -> None:
        self._consumer.commit()

    def retry(self, message: AuditMessage) -> None:
        self._consumer.seek(message._position, message.offset)

    def publish_dlq(self, original_payload: dict[str, Any], reason: str) -> None:
        from datetime import datetime, timezone

        tenant_id = original_payload.get("tenant_id", "")
        envelope = {
            "original_payload": original_payload,
            "error_reason": reason,
            "failed_at": datetime.now(tz=timezone.utc).isoformat(),
            "tenant_id": tenant_id,
            "request_id": original_payload.get("request_id", ""),
        }
        self._dlq.send(
            self.dlq_topic,
            key=tenant_id or None,
            value=envelope,
        ).get(timeout=5)

    def close(self) -> None:
        self._dlq.flush()
        self._dlq.close()
        self._consumer.close()


def make_audit_consumer(observe_lag: Callable[[str, int], None]) -> AuditConsumer:
    transport = os.getenv("AUDIT_STREAM_TRANSPORT", "kafka").strip().lower() or "kafka"
    if transport != "kafka":
        raise RuntimeError(
            f"unsupported AUDIT_STREAM_TRANSPORT {transport!r}; supported value: kafka"
        )
    return KafkaAuditConsumer(observe_lag)

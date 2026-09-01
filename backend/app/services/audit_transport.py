"""Transport boundary and topic configuration for backend audit publication."""

from __future__ import annotations

import json
import os
from typing import Any, Protocol
from urllib.parse import urlparse

AUDIT_EVENTS_TOPIC = os.getenv("KAFKA_AUDIT_TOPIC", "audit.events")
AUDIT_DLQ_TOPIC = os.getenv("KAFKA_DLQ_TOPIC", "audit.deadletter")
GATEWAY_TRAFFIC_TOPIC = os.getenv("KAFKA_GATEWAY_TRAFFIC_TOPIC", "gateway.traffic")
AUDIT_STREAM_TRANSPORT = os.getenv("AUDIT_STREAM_TRANSPORT", "kafka").strip().lower() or "kafka"
if AUDIT_STREAM_TRANSPORT not in {"kafka", "sqs_fifo"}:
    raise RuntimeError(
        f"unsupported AUDIT_STREAM_TRANSPORT {AUDIT_STREAM_TRANSPORT!r}; supported values: kafka, sqs_fifo"
    )


class AuditPublisher(Protocol):
    def publish(
        self,
        tenant_id: str,
        event: dict[str, Any],
        audit_record_id: str | None = None,
    ) -> None: ...


class KafkaAuditPublisher:
    def __init__(self) -> None:
        from kafka import KafkaProducer  # type: ignore[import-untyped]

        self._producer = KafkaProducer(
            bootstrap_servers=os.getenv("KAFKA_BROKERS", "localhost:9092").split(","),
            value_serializer=lambda value: json.dumps(value).encode("utf-8"),
            key_serializer=lambda key: key.encode("utf-8") if key else b"",
            acks=1,
        )

    def publish(
        self,
        tenant_id: str,
        event: dict[str, Any],
        audit_record_id: str | None = None,
    ) -> None:
        self._producer.send(
            AUDIT_EVENTS_TOPIC,
            key=str(tenant_id or ""),
            value=event,
        ).get(timeout=5)


class SQSFIFOAuditPublisher:
    def __init__(self) -> None:
        self._queue_url = os.getenv("SQS_AUDIT_QUEUE_URL", "").strip()
        self._client = None

    def publish(
        self,
        tenant_id: str,
        event: dict[str, Any],
        audit_record_id: str | None = None,
    ) -> None:
        parsed = urlparse(self._queue_url)
        if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
            raise RuntimeError("SQS_AUDIT_QUEUE_URL must be an absolute HTTPS FIFO queue URL")
        if not parsed.path.rsplit("/", 1)[-1].endswith(".fifo"):
            raise RuntimeError("SQS_AUDIT_QUEUE_URL must identify a .fifo queue")
        host = (parsed.hostname or "").lower()
        if not host.endswith((".amazonaws.com", ".amazonaws.com.cn")) or not (
            host.startswith("sqs.") or ".sqs." in host
        ):
            raise RuntimeError("SQS_AUDIT_QUEUE_URL must use an AWS SQS endpoint")
        tenant_key = str(tenant_id or "")
        record_id = str(
            audit_record_id
            or event.get("audit_record_id")
            or event.get("record_id")
            or event.get("id")
            or ""
        )
        if not tenant_key or not record_id:
            raise RuntimeError("SQS FIFO audit publish requires tenant_id and audit_record_id")
        if len(tenant_key) > 128 or len(record_id) > 128:
            raise RuntimeError(
                "SQS FIFO tenant_id and audit_record_id must not exceed 128 characters"
            )
        if self._client is None:
            import boto3

            self._client = boto3.client("sqs")
        self._client.send_message(
            QueueUrl=self._queue_url,
            MessageBody=json.dumps(event),
            MessageGroupId=tenant_key,
            MessageDeduplicationId=record_id,
        )


def make_audit_publisher() -> AuditPublisher:
    if AUDIT_STREAM_TRANSPORT == "sqs_fifo":
        return SQSFIFOAuditPublisher()
    return KafkaAuditPublisher()

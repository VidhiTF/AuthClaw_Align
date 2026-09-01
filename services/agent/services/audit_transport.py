"""Transport boundary for the agent's durable event-delivery pipeline."""

from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Protocol

CANONICAL_AUDIT_EVENTS_TOPIC = "audit.events"
CANONICAL_AUDIT_DLQ_TOPIC = "audit.deadletter"
AGENT_LEGACY_AUDIT_EVENTS_TOPIC = "authclaw-audit-events"
AGENT_LEGACY_AUDIT_DLQ_TOPIC = "authclaw-dead-letter-events"
SQS_MAX_MESSAGE_BYTES = 1_048_576


@dataclass(frozen=True)
class AuditTopics:
    audit: str
    analytics: str
    dlq: str

    @classmethod
    def from_environment(cls) -> "AuditTopics":
        # Preserve deployed agent aliases until live topic ownership is resolved.
        return cls(
            audit=os.getenv(
                "KAFKA_AUDIT_TOPIC",
                os.getenv("AUTHCLAW_AUDIT_TOPIC", AGENT_LEGACY_AUDIT_EVENTS_TOPIC),
            ),
            analytics=os.getenv("KAFKA_ANALYTICS_TOPIC", "authclaw-analytics-events"),
            dlq=os.getenv("KAFKA_DLQ_TOPIC", AGENT_LEGACY_AUDIT_DLQ_TOPIC),
        )


class AuditPublisher(Protocol):
    @property
    def configured(self) -> bool: ...

    def publish(
        self,
        topic: str,
        event: Dict[str, Any],
        *,
        serialized: str | None = None,
    ) -> None: ...


class KafkaRestAuditPublisher:
    def __init__(self, *, timeout: float, required: bool) -> None:
        self._url = os.getenv("KAFKA_REST_URL", "").rstrip("/")
        self._timeout = timeout
        self._required = required

    @property
    def configured(self) -> bool:
        return bool(self._url)

    def publish(
        self,
        topic: str,
        event: Dict[str, Any],
        *,
        serialized: str | None = None,
    ) -> None:
        if not self._url:
            if self._required:
                raise RuntimeError(
                    "Kafka REST/MSK endpoint is required but KAFKA_REST_URL is not configured"
                )
            return
        endpoint = f"{self._url}/topics/{urllib.parse.quote(topic)}"
        body = json.dumps({"records": [{"value": event}]}, default=str).encode("utf-8")
        request = urllib.request.Request(
            endpoint,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/vnd.kafka.json.v2+json",
                "Accept": "application/vnd.kafka.v2+json",
            },
        )
        with urllib.request.urlopen(request, timeout=self._timeout) as response:  # nosec B310
            if response.status < 200 or response.status >= 300:
                raise RuntimeError(f"Kafka REST returned {response.status}")


class SQSFIFOAuditPublisher:
    def __init__(self) -> None:
        self._queue_url = os.getenv("SQS_AUDIT_QUEUE_URL", "").strip()
        self._client = None

    @property
    def configured(self) -> bool:
        return bool(self._queue_url)

    def publish(
        self,
        topic: str,
        event: Dict[str, Any],
        *,
        serialized: str | None = None,
    ) -> None:
        parsed = urllib.parse.urlparse(self._queue_url)
        if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
            raise RuntimeError("SQS_AUDIT_QUEUE_URL must be an absolute HTTPS FIFO queue URL")
        if not parsed.path.rsplit("/", 1)[-1].endswith(".fifo"):
            raise RuntimeError("SQS_AUDIT_QUEUE_URL must identify a .fifo queue")
        host = (parsed.hostname or "").lower()
        labels = host.split(".")
        sqs_index = next(
            (i for i, label in enumerate(labels) if label == "sqs" or label.startswith("sqs-")),
            -1,
        )
        if (
            not host.endswith((".amazonaws.com", ".amazonaws.com.cn"))
            or sqs_index < 0
            or sqs_index + 1 >= len(labels)
        ):
            raise RuntimeError("SQS_AUDIT_QUEUE_URL must use a regional AWS SQS endpoint")
        queue_region = labels[sqs_index + 1]
        tenant_id = str(event.get("tenant_id") or "")
        record_id = str(
            event.get("audit_record_id")
            or event.get("record_id")
            or event.get("id")
            or ""
        )
        if not tenant_id or not record_id:
            raise RuntimeError("SQS FIFO audit publish requires tenant_id and audit_record_id")
        try:
            record_id = str(uuid.UUID(record_id))
        except ValueError as exc:
            raise RuntimeError("SQS FIFO audit_record_id must be a canonical UUID") from exc
        if len(tenant_id) > 128:
            raise RuntimeError("SQS FIFO tenant_id must not exceed 128 characters")
        body = serialized if serialized is not None else json.dumps(event, sort_keys=True, default=str)
        if len(body.encode("utf-8")) > SQS_MAX_MESSAGE_BYTES:
            raise RuntimeError(f"SQS audit message exceeds {SQS_MAX_MESSAGE_BYTES}-byte limit")
        if self._client is None:
            import boto3

            session = boto3.session.Session()
            if session.region_name and session.region_name != queue_region:
                raise RuntimeError(
                    f"SQS queue region {queue_region!r} does not match AWS SDK region {session.region_name!r}"
                )
            self._client = session.client("sqs", region_name=queue_region)
        self._client.send_message(
            QueueUrl=self._queue_url,
            MessageBody=body,
            MessageGroupId=tenant_id,
            MessageDeduplicationId=record_id,
        )


def make_audit_publisher(*, timeout: float, required: bool) -> AuditPublisher:
    transport = os.getenv("AUDIT_STREAM_TRANSPORT", "kafka").strip().lower() or "kafka"
    if transport == "sqs_fifo":
        return SQSFIFOAuditPublisher()
    if transport != "kafka":
        raise RuntimeError(
            f"unsupported AUDIT_STREAM_TRANSPORT {transport!r}; supported values: kafka, sqs_fifo"
        )
    return KafkaRestAuditPublisher(timeout=timeout, required=required)

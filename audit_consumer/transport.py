"""Transport-neutral consume/ack/retry boundary with the current Kafka adapter."""

from __future__ import annotations

import json
import logging
import os
import threading
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Protocol
from urllib.parse import urlparse

from botocore.config import Config

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
    group_id: str = ""
    receive_count: int = 1
    validation_error: Exception | None = None
    _receipt_handle: str = ""
    _visibility_stop: threading.Event | None = None


class AuditConsumer(Protocol):
    redrive_failures: bool
    group_id: str
    topics: list[str]
    dlq_topic: str

    def poll(self, timeout_ms: int) -> list[list[AuditMessage]]: ...
    def begin(self, message: AuditMessage) -> None: ...
    def ack(self, message: AuditMessage) -> None: ...
    def retry(self, message: AuditMessage) -> None: ...
    def publish_dlq(self, payload: dict[str, Any], reason: str) -> None: ...
    def close(self) -> None: ...


class KafkaAuditConsumer:
    redrive_failures = False

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

    def ack(self, message: AuditMessage) -> None:
        from kafka.structs import OffsetAndMetadata

        self._consumer.commit({message._position: OffsetAndMetadata(message.offset + 1, "")})

    def begin(self, _message: AuditMessage) -> None:
        return None

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


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}")
    return value


def _queue_region(queue_url: str) -> str:
    parsed = urlparse(queue_url)
    if os.getenv("AUTHCLAW_ALLOW_LOCAL_AWS_ENDPOINTS", "").lower() in {"1", "true", "yes"}:
        host = (parsed.hostname or "").lower()
        if parsed.scheme == "http" and (
            host in {"localhost", "127.0.0.1", "localstack", "localhost.localstack.cloud"}
            or host.endswith(".localhost.localstack.cloud")
        ) and parsed.path.endswith(".fifo"):
            return os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    labels = (parsed.hostname or "").split(".")
    if (
        parsed.scheme != "https"
        or parsed.query
        or parsed.fragment
        or not parsed.path.endswith(".fifo")
        or len(labels) < 4
        or labels[-2:] != ["amazonaws", "com"]
    ):
        raise RuntimeError("SQS_AUDIT_QUEUE_URL must be an AWS regional HTTPS FIFO queue URL")
    if labels[0] == "sqs":
        return labels[1]
    if labels[0].startswith("sqs-"):
        return labels[0][4:]
    raise RuntimeError("SQS_AUDIT_QUEUE_URL does not contain a signing region")


def _canonical_record_id(payload: dict[str, Any]) -> str:
    value = payload.get("audit_record_id") or payload.get("record_id") or payload.get("id")
    if not isinstance(value, str) or not value:
        raise ValueError("audit envelope is missing its canonical audit-record UUID")
    try:
        return str(uuid.UUID(value))
    except ValueError as exc:
        raise ValueError("canonical audit-record ID must be a UUID") from exc


class SQSFIFOAuditConsumer:
    redrive_failures = True
    group_id = "authclaw-audit-sqs-fifo"
    topics = ["sqs_fifo"]
    dlq_topic = "queue-redrive-policy"

    def __init__(self, observe_lag: Callable[[str, int], None]) -> None:
        try:
            import boto3
        except ImportError as exc:
            raise RuntimeError("sqs_fifo transport requires boto3") from exc

        self._queue_url = os.getenv("SQS_AUDIT_QUEUE_URL", "").strip()
        self._endpoint_url = os.getenv("SQS_ENDPOINT_URL", "").strip()
        if not self._queue_url:
            raise RuntimeError("SQS_AUDIT_QUEUE_URL is required for sqs_fifo transport")
        queue_region = _queue_region(self._queue_url)
        session = boto3.session.Session()
        configured_region = session.region_name
        if configured_region and configured_region != queue_region:
            raise RuntimeError("AWS configured region does not match SQS_AUDIT_QUEUE_URL")
        self._client = session.client(
            "sqs",
            region_name=queue_region,
            endpoint_url=self._endpoint_url or None,
            config=Config(
                connect_timeout=_bounded_int("AWS_CONNECT_TIMEOUT_SECONDS", 3, 1, 30),
                read_timeout=_bounded_int("AWS_READ_TIMEOUT_SECONDS", 25, 2, 60),
                max_pool_connections=_bounded_int("AWS_MAX_POOL_CONNECTIONS", 10, 1, 100),
                retries={
                    "mode": "standard",
                    "total_max_attempts": _bounded_int("AWS_MAX_ATTEMPTS", 3, 1, 5),
                },
            ),
        )
        self._long_poll = _bounded_int("SQS_LONG_POLL_SECONDS", 20, 1, 20)
        self._batch_size = _bounded_int("SQS_MAX_MESSAGES", 10, 1, 10)
        self._visibility = _bounded_int("SQS_VISIBILITY_TIMEOUT_SECONDS", 60, 10, 43200)
        self._renew_interval = max(5, self._visibility // 2)
        self._active: set[threading.Event] = set()
        self._active_lock = threading.Lock()
        self._observe_lag = observe_lag

    def poll(self, timeout_ms: int) -> list[list[AuditMessage]]:
        del timeout_ms
        response = self._client.receive_message(
            QueueUrl=self._queue_url,
            MaxNumberOfMessages=self._batch_size,
            WaitTimeSeconds=self._long_poll,
            VisibilityTimeout=self._visibility,
            MessageSystemAttributeNames=[
                "MessageGroupId",
                "MessageDeduplicationId",
                "ApproximateReceiveCount",
            ],
        )
        groups: dict[str, list[AuditMessage]] = {}
        max_receive_count = 0
        for raw in response.get("Messages", []):
            attributes = raw.get("Attributes") or {}
            group_id = attributes.get("MessageGroupId", "")
            receive_count = 1
            payload: dict[str, Any] = {}
            error: Exception | None = None
            try:
                if not raw.get("ReceiptHandle"):
                    raise ValueError("SQS message is missing ReceiptHandle")
                if not group_id:
                    raise ValueError("SQS message is missing MessageGroupId")
                dedup_id = attributes.get("MessageDeduplicationId")
                if not dedup_id:
                    raise ValueError("SQS message is missing MessageDeduplicationId")
                count_text = attributes.get("ApproximateReceiveCount")
                if count_text is None:
                    raise ValueError("SQS message is missing ApproximateReceiveCount")
                receive_count = int(count_text)
                if receive_count < 1:
                    raise ValueError("ApproximateReceiveCount must be positive")
                payload = json.loads(raw.get("Body", ""))
                if not isinstance(payload, dict):
                    raise ValueError("audit envelope must be a JSON object")
                canonical_id = _canonical_record_id(payload)
                try:
                    canonical_dedup_id = str(uuid.UUID(dedup_id))
                except ValueError as exc:
                    raise ValueError("MessageDeduplicationId must be a UUID") from exc
                if canonical_dedup_id != canonical_id:
                    raise ValueError("MessageDeduplicationId does not match audit-record UUID")
                tenant_id = payload.get("tenant_id")
                if not isinstance(tenant_id, str) or not tenant_id:
                    raise ValueError("audit envelope is missing tenant_id")
                if group_id != tenant_id:
                    raise ValueError("MessageGroupId does not match tenant_id")
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                error = exc

            max_receive_count = max(max_receive_count, receive_count)
            message = AuditMessage(
                value=payload,
                offset=receive_count,
                _position=None,
                group_id=group_id,
                receive_count=receive_count,
                validation_error=error,
                _receipt_handle=raw.get("ReceiptHandle", ""),
                _visibility_stop=threading.Event(),
            )
            groups.setdefault(group_id or "__invalid_message_group__", []).append(message)
        self._observe_lag("audit_consumer_sqs_receive_count", max_receive_count)
        return list(groups.values())

    def begin(self, message: AuditMessage) -> None:
        stop = message._visibility_stop
        if stop is None or not message._receipt_handle:
            return
        with self._active_lock:
            self._active.add(stop)

        def renew() -> None:
            while not stop.wait(self._renew_interval):
                try:
                    self._client.change_message_visibility(
                        QueueUrl=self._queue_url,
                        ReceiptHandle=message._receipt_handle,
                        VisibilityTimeout=self._visibility,
                    )
                except Exception:  # noqa: BLE001
                    logger.warning("Failed to renew SQS audit-message visibility")

        threading.Thread(target=renew, name="audit-sqs-visibility", daemon=True).start()

    def _finish(self, message: AuditMessage) -> None:
        if message._visibility_stop is not None:
            message._visibility_stop.set()
            with self._active_lock:
                self._active.discard(message._visibility_stop)

    def ack(self, message: AuditMessage) -> None:
        self._finish(message)
        self._client.delete_message(
            QueueUrl=self._queue_url,
            ReceiptHandle=message._receipt_handle,
        )

    def retry(self, message: AuditMessage) -> None:
        self._finish(message)

    def publish_dlq(self, original_payload: dict[str, Any], reason: str) -> None:
        del original_payload, reason
        raise RuntimeError("SQS failures must use queue visibility and redrive policy")

    def close(self) -> None:
        with self._active_lock:
            active = list(self._active)
            self._active.clear()
        for stop in active:
            stop.set()
        close = getattr(self._client, "close", None)
        if close:
            close()


def make_audit_consumer(observe_lag: Callable[[str, int], None]) -> AuditConsumer:
    transport = os.getenv("AUDIT_STREAM_TRANSPORT", "kafka").strip().lower() or "kafka"
    if transport == "kafka":
        return KafkaAuditConsumer(observe_lag)
    if transport == "sqs_fifo":
        return SQSFIFOAuditConsumer(observe_lag)
    raise RuntimeError(
        f"unsupported AUDIT_STREAM_TRANSPORT {transport!r}; supported values: kafka, sqs_fifo"
    )

"""Transport boundary for the agent's durable event-delivery pipeline."""

from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Protocol

CANONICAL_AUDIT_EVENTS_TOPIC = "audit.events"
CANONICAL_AUDIT_DLQ_TOPIC = "audit.deadletter"
AGENT_LEGACY_AUDIT_EVENTS_TOPIC = "authclaw-audit-events"
AGENT_LEGACY_AUDIT_DLQ_TOPIC = "authclaw-dead-letter-events"


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


def make_audit_publisher(*, timeout: float, required: bool) -> AuditPublisher:
    transport = os.getenv("AGENT_AUDIT_STREAM_TRANSPORT", "kafka").strip().lower() or "kafka"
    if transport == "sqs_fifo":
        raise RuntimeError(
            "agent legacy audit events must remain on Kafka until they emit canonical committed audit records"
        )
    if transport != "kafka":
        raise RuntimeError(
            f"unsupported AGENT_AUDIT_STREAM_TRANSPORT {transport!r}; supported values: kafka"
        )
    return KafkaRestAuditPublisher(timeout=timeout, required=required)

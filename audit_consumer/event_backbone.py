"""Event backbone topic contract for AuthClaw audit ingestion."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TopicSpec:
    name: str
    partitions: int
    retention_ms: int
    cleanup_policy: str
    replay_policy: str
    key_field: str


GATEWAY_TRAFFIC_TOPIC = "gateway.traffic"
AUDIT_EVENTS_TOPIC = "audit.events"
AUDIT_DLQ_TOPIC = "audit.deadletter"

TOPICS = {
    GATEWAY_TRAFFIC_TOPIC: TopicSpec(
        name=GATEWAY_TRAFFIC_TOPIC,
        partitions=12,
        retention_ms=7 * 24 * 60 * 60 * 1000,
        cleanup_policy="delete",
        replay_policy="Replay by resetting the authclaw-audit-consumer group offset; idempotency is enforced by record_id.",
        key_field="tenant_id",
    ),
    AUDIT_EVENTS_TOPIC: TopicSpec(
        name=AUDIT_EVENTS_TOPIC,
        partitions=12,
        retention_ms=30 * 24 * 60 * 60 * 1000,
        cleanup_policy="delete",
        replay_policy="Replay by consumer-group offset reset or Postgres-to-ClickHouse backfill for audit-chain recovery.",
        key_field="tenant_id",
    ),
    AUDIT_DLQ_TOPIC: TopicSpec(
        name=AUDIT_DLQ_TOPIC,
        partitions=6,
        retention_ms=90 * 24 * 60 * 60 * 1000,
        cleanup_policy="delete",
        replay_policy="Reprocess manually after fixing the error; original_payload is preserved.",
        key_field="tenant_id",
    ),
}


DEFAULT_CONSUMER_TOPICS = [GATEWAY_TRAFFIC_TOPIC, AUDIT_EVENTS_TOPIC]

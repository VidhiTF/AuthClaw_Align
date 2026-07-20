"""Validate PostgreSQL audit events and mirror them to ClickHouse."""

import hashlib
import json
import logging
import os
import signal
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from dotenv import load_dotenv
from kafka import KafkaConsumer, KafkaProducer

from clickhouse_writer import audit_event_exists, get_client, get_tenant_tail, insert_audit_event
from event_backbone import AUDIT_DLQ_TOPIC, DEFAULT_CONSUMER_TOPICS
from hash_chain import standardize_uuid, standardize_timestamp
from metrics import metrics

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("audit_consumer")

KAFKA_BROKERS = os.getenv("KAFKA_BROKERS", "localhost:9092").split(",")
KAFKA_TOPICS = [
    topic.strip()
    for topic in os.getenv("KAFKA_TOPICS", ",".join(DEFAULT_CONSUMER_TOPICS)).split(",")
    if topic.strip()
]
# Consumer group — all replicas of this service share offset progress.
KAFKA_GROUP_ID = os.getenv("KAFKA_GROUP_ID", "authclaw-audit-consumer")
KAFKA_DLQ_TOPIC = os.getenv("KAFKA_DLQ_TOPIC", AUDIT_DLQ_TOPIC)
METRICS_PORT = int(os.getenv("AUDIT_CONSUMER_METRICS_PORT", "9108"))

CLICKHOUSE_HOST = os.getenv("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.getenv("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_DB = os.getenv("CLICKHOUSE_DB", "authclaw")
CLICKHOUSE_USER = os.getenv("CLICKHOUSE_USER", "authclaw")
CLICKHOUSE_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "authclaw")

class SequenceGapError(RuntimeError):
    """The mirror must wait for an earlier tenant sequence."""


class RetryableMirrorError(RuntimeError):
    """Kafka offset must remain uncommitted until infrastructure recovers."""


class InvalidAuditEvent(ValueError):
    """The immutable PostgreSQL proof is malformed or inconsistent."""


class _MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_response(404)
            self.end_headers()
            return
        body = metrics.render_prometheus().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


def _start_metrics_server() -> ThreadingHTTPServer | None:
    if METRICS_PORT <= 0:
        return None
    server = ThreadingHTTPServer(("0.0.0.0", METRICS_PORT), _MetricsHandler)
    thread = threading.Thread(target=server.serve_forever, name="audit-consumer-metrics", daemon=True)
    thread.start()
    logger.info("Audit consumer metrics listening on :%s/metrics", METRICS_PORT)
    return server


_running = True


def _handle_signal(signum, _frame):
    global _running
    logger.info("Received signal %s — shutting down", signum)
    _running = False


signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT, _handle_signal)

def _make_dlq_producer() -> KafkaProducer:
    """Create a synchronous Kafka producer for DLQ writes."""
    return KafkaProducer(
        bootstrap_servers=KAFKA_BROKERS,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        key_serializer=lambda k: k.encode("utf-8") if k else b"",
        acks=1,
    )


def publish_to_dlq(
    producer: KafkaProducer,
    original_payload: dict,
    error_reason: str,
) -> None:
    """
    Publish a failed message to audit.deadletter.

    Envelope schema:
      original_payload  — the raw dict that failed processing
      error_reason      — human-readable exception/description
      failed_at         — ISO-8601 UTC timestamp
      tenant_id         — extracted from payload if available
      request_id        — extracted from payload if available
    """
    tenant_id = original_payload.get("tenant_id", "")
    request_id = original_payload.get("request_id", "")

    envelope = {
        "original_payload": original_payload,
        "error_reason": error_reason,
        "failed_at": datetime.now(tz=timezone.utc).isoformat(),
        "tenant_id": tenant_id,
        "request_id": request_id,
    }
    try:
        future = producer.send(
            KAFKA_DLQ_TOPIC,
            key=tenant_id or None,
            value=envelope,
        )
        future.get(timeout=5)  # synchronous confirm for reliability
        logger.warning(
            "[DLQ] Published failed event to %s (tenant=%s reason=%s)",
            KAFKA_DLQ_TOPIC,
            tenant_id,
            error_reason,
        )
        metrics.increment("audit_consumer_dlq_published_total")
    except Exception as dlq_exc:  # noqa: BLE001
        # DLQ publish itself failed — log and continue; never swallow original error silently.
        logger.error(
            "[DLQ] Failed to publish to %s: %s (original reason: %s)",
            KAFKA_DLQ_TOPIC,
            dlq_exc,
            error_reason,
        )
        metrics.increment("audit_consumer_dlq_publish_failures_total")


def _parse_timestamp(raw) -> datetime:
    """Parse ISO-8601 or epoch timestamp into a UTC-aware datetime."""
    if isinstance(raw, (int, float)):
        return datetime.fromtimestamp(raw, tz=timezone.utc)
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(tz=timezone.utc)


def stable_record_id(payload: dict) -> str:
    """Return the provided event id or a deterministic UUID for replayed payloads."""
    if payload.get("id"):
        return str(payload["id"])
    identity = {
        "tenant_id": payload.get("tenant_id", ""),
        "request_id": payload.get("request_id", ""),
        "timestamp": payload.get("timestamp", ""),
        "action": payload.get("action", ""),
        "provider": payload.get("provider", ""),
        "model": payload.get("model", ""),
        "reason": payload.get("reason", ""),
        "execution_trace": payload.get("execution_trace") or [],
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"authclaw:audit-event:{canonical}"))


def normalise_event(payload: dict) -> dict:
    """
    Map a raw Kafka message payload (AuditEvent from Go gateway) to the
    ClickHouse row schema, including request_id.
    """
    return {
        "record_id": stable_record_id(payload),
        "tenant_id": payload.get("tenant_id", ""),
        "tenant_sequence": int(payload.get("tenant_sequence", 0)),
        "idempotency_key": payload.get("idempotency_key", ""),
        "chain_version": int(payload.get("chain_version", 0)),
        "canonical_payload": payload.get("canonical_payload", ""),
        "timestamp": _parse_timestamp(payload.get("timestamp")),
        "actor_id": payload.get("actor_id", ""),
        "actor_type": payload.get("actor_type", "gateway"),
        "action": payload.get("action", ""),
        "policy_id": payload.get("policy_id", ""),
        "provider": payload.get("provider", ""),
        "model": payload.get("model", ""),
        "reason": payload.get("reason", ""),
        "prompt_count": int(payload.get("prompt_count", 0)),
        "request_size": int(payload.get("request_size", 0)),
        "response_status": int(payload.get("response_status", 0)),
        "duration_ms": int(payload.get("duration_ms", 0)),
        "frameworks_affected": payload.get("frameworks_affected") or [],
        "execution_trace": (
            payload.get("execution_trace")
            if isinstance(payload.get("execution_trace"), str)
            else json.dumps(payload.get("execution_trace") or [])
        ),
        "request_id": payload.get("request_id", ""),
        "prior_hash": payload.get("prior_hash", ""),
        "integrity_hash": payload.get("integrity_hash", ""),
    }

def _observe_consumer_lag(consumer: KafkaConsumer, records) -> None:
    try:
        for topic_partition, messages in records.items():
            if not messages:
                continue
            end_offset = consumer.end_offsets([topic_partition])[topic_partition]
            lag = max(0, end_offset - messages[-1].offset - 1)
            metrics.set_gauge(
                f"audit_consumer_lag_{topic_partition.topic}_{topic_partition.partition}",
                lag,
            )
    except Exception as exc:
        logger.warning("Unable to observe Kafka consumer lag: %s", exc)


def main():
    logger.info(
        "Connecting to Kafka brokers=%s topics=%s group=%s",
        KAFKA_BROKERS,
        KAFKA_TOPICS,
        KAFKA_GROUP_ID,
    )
    consumer = KafkaConsumer(
        *KAFKA_TOPICS,
        bootstrap_servers=KAFKA_BROKERS,
        group_id=KAFKA_GROUP_ID,
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        auto_offset_reset="earliest",
        enable_auto_commit=False,
    )
    metrics_server = _start_metrics_server()

    dlq_producer = _make_dlq_producer()

    logger.info(
        "Connecting to ClickHouse host=%s port=%s db=%s",
        CLICKHOUSE_HOST,
        CLICKHOUSE_PORT,
        CLICKHOUSE_DB,
    )
    ch_client = get_client(
        host=CLICKHOUSE_HOST,
        port=CLICKHOUSE_PORT,
        database=CLICKHOUSE_DB,
        username=CLICKHOUSE_USER,
        password=CLICKHOUSE_PASSWORD,
    )

    logger.info(
        "Audit consumer started — group=%s DLQ=%s",
        KAFKA_GROUP_ID,
        KAFKA_DLQ_TOPIC,
    )

    while _running:
        # Poll with a 1-second timeout so SIGTERM is handled promptly.
        records = consumer.poll(timeout_ms=1000)
        _observe_consumer_lag(consumer, records)
        for topic_partition, messages in records.items():
            for message in messages:
                try:
                    _process_message(ch_client, message.value)
                    consumer.commit()
                except (SequenceGapError, RetryableMirrorError) as exc:
                    logger.warning("Deferring audit mirror offset %s: %s", message.offset, exc)
                    consumer.seek(topic_partition, message.offset)
                    metrics.increment("audit_consumer_retries_total")
                    time.sleep(0.25)
                    break
                except Exception as exc:  # noqa: BLE001
                    logger.error("Failed to process message: %s", exc)
                    publish_to_dlq(dlq_producer, message.value or {}, str(exc))
                    consumer.commit()

    logger.info("Audit consumer stopped")
    dlq_producer.flush()
    dlq_producer.close()
    consumer.close()
    if metrics_server:
        metrics_server.shutdown()


def _process_message(ch_client, payload: dict) -> None:
    """Validate PostgreSQL proof data and insert a deterministic mirror row."""
    metrics.increment("audit_consumer_messages_seen_total")
    row = normalise_event(payload)
    row["record_id"] = standardize_uuid(row["record_id"])
    row["tenant_id"] = standardize_uuid(row["tenant_id"])
    row["timestamp"] = standardize_timestamp(row["timestamp"])
    record_id = row["record_id"]
    tenant_id = row["tenant_id"]

    if not tenant_id or not record_id:
        raise InvalidAuditEvent("tenant_id and record_id are required")
    if row["chain_version"] != 2 or row["tenant_sequence"] <= 0:
        raise InvalidAuditEvent("chain_version=2 and a positive tenant_sequence are required")
    if not row["canonical_payload"] or not row["prior_hash"] or not row["integrity_hash"]:
        raise InvalidAuditEvent("canonical payload and PostgreSQL proof hashes are required")

    try:
        canonical = json.loads(row["canonical_payload"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise InvalidAuditEvent("canonical_payload is not valid JSON") from exc
    if (
        canonical.get("tenant_id") != tenant_id
        or canonical.get("record_id") != record_id
        or int(canonical.get("tenant_sequence", 0)) != row["tenant_sequence"]
    ):
        raise InvalidAuditEvent("canonical payload identity does not match its envelope")
    expected = hashlib.sha256(
        (row["canonical_payload"] + row["prior_hash"]).encode("utf-8")
    ).hexdigest()
    if expected != row["integrity_hash"]:
        metrics.increment("audit_consumer_verification_failures_total")
        raise InvalidAuditEvent("PostgreSQL supplied an invalid audit integrity hash")

    try:
        exists = audit_event_exists(ch_client, record_id)
    except Exception as exc:
        raise RetryableMirrorError(f"ClickHouse duplicate check failed: {exc}") from exc
    if exists:
        metrics.increment("audit_consumer_duplicate_events_total")
        logger.info("Skipping duplicate audit event already in ClickHouse: record_id=%s", record_id)
        return

    try:
        tail_sequence, tail_hash = get_tenant_tail(ch_client, tenant_id)
    except Exception as exc:
        raise RetryableMirrorError(f"ClickHouse tail query failed: {exc}") from exc
    if row["tenant_sequence"] > tail_sequence + 1:
        metrics.increment("audit_consumer_sequence_gaps_total")
        raise SequenceGapError(
            f"tenant {tenant_id} expects sequence {tail_sequence + 1}, "
            f"received {row['tenant_sequence']}"
        )
    if row["tenant_sequence"] <= tail_sequence:
        raise InvalidAuditEvent("duplicate sequence has a different record_id")
    if row["prior_hash"] != tail_hash:
        metrics.increment("audit_consumer_mirror_drift_total")
        raise InvalidAuditEvent("PostgreSQL and ClickHouse audit chain tails differ")

    try:
        inserted = insert_audit_event(ch_client, row)
        if not inserted:
            metrics.increment("audit_consumer_duplicate_events_total")
            return

        metrics.increment("audit_consumer_clickhouse_inserts_total")
    except Exception as exc:
        metrics.increment("audit_consumer_clickhouse_insert_failures_total")
        raise RetryableMirrorError(f"ClickHouse insert failed: {exc}") from exc

    logger.info(
        "Audit event persisted: record_id=%s tenant=%s action=%s request_id=%s integrity=%s prior=%s",
        row["record_id"],
        tenant_id,
        row["action"],
        row.get("request_id", ""),
        row["integrity_hash"],
        row["prior_hash"],
    )


if __name__ == "__main__":
    main()

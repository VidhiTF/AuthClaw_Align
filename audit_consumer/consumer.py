"""Kafka consumer for audit events, hash-chain integrity, ClickHouse, and DLQ writes."""

import json
import logging
import os
import redis
import signal
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from dotenv import load_dotenv
from kafka import KafkaConsumer, KafkaProducer

from clickhouse_writer import audit_event_exists, get_client, get_prior_hash, insert_audit_event
from event_backbone import AUDIT_DLQ_TOPIC, DEFAULT_CONSUMER_TOPICS
from hash_chain import GENESIS_HASH, compute_integrity_hash, standardize_uuid, standardize_timestamp
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
IDEMPOTENCY_TTL_SECONDS = int(os.getenv("AUDIT_IDEMPOTENCY_TTL_SECONDS", str(30 * 24 * 60 * 60)))
METRICS_PORT = int(os.getenv("AUDIT_CONSUMER_METRICS_PORT", "9108"))

CLICKHOUSE_HOST = os.getenv("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.getenv("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_DB = os.getenv("CLICKHOUSE_DB", "authclaw")
CLICKHOUSE_USER = os.getenv("CLICKHOUSE_USER", "authclaw")
CLICKHOUSE_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "authclaw")

REDIS_HOST = os.getenv("REDIS_HOST")
if not REDIS_HOST:
    if CLICKHOUSE_HOST == "clickhouse":
        REDIS_HOST = "redis"
    else:
        REDIS_HOST = "localhost"
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

logger.info("Initializing Redis tail-hash cache at %s:%s", REDIS_HOST, REDIS_PORT)
redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)


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
        "execution_trace": json.dumps(payload.get("execution_trace") or []),
        "request_id": payload.get("request_id", ""),
        "prior_hash": "",     # filled in by _process_message
        "integrity_hash": "", # filled in by _process_message
    }


def _event_idempotency_key(record_id: str) -> str:
    return f"audit_event:{record_id}"


def _claim_event(record_id: str) -> bool:
    """Claim an event before insert. False means another consumer already owns it."""
    try:
        claimed = redis_client.set(
            _event_idempotency_key(record_id),
            "processing",
            nx=True,
            ex=IDEMPOTENCY_TTL_SECONDS,
        )
        return bool(claimed)
    except Exception as redis_exc:
        logger.warning("Redis idempotency claim failed, continuing with ClickHouse guard: %s", redis_exc)
        return True


def _mark_event_persisted(record_id: str) -> None:
    try:
        redis_client.set(
            _event_idempotency_key(record_id),
            "persisted",
            ex=IDEMPOTENCY_TTL_SECONDS,
        )
    except Exception as redis_exc:
        logger.warning("Redis idempotency mark failed: %s", redis_exc)


def _release_event_claim(record_id: str) -> None:
    try:
        redis_client.delete(_event_idempotency_key(record_id))
    except Exception as redis_exc:
        logger.warning("Redis idempotency release failed: %s", redis_exc)


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
        for _tp, messages in records.items():
            for message in messages:
                try:
                    _process_message(ch_client, message.value)
                    consumer.commit()
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
    """Normalise, chain-hash, and insert a single audit event."""
    metrics.increment("audit_consumer_messages_seen_total")
    row = normalise_event(payload)
    row["record_id"] = standardize_uuid(row["record_id"])
    row["tenant_id"] = standardize_uuid(row["tenant_id"])
    row["timestamp"] = standardize_timestamp(row["timestamp"])
    record_id = row["record_id"]
    tenant_id = row["tenant_id"]

    if not tenant_id:
        logger.warning("Skipping event with empty tenant_id: %s", payload.get("id"))
        metrics.increment("audit_consumer_events_skipped_total")
        return

    if audit_event_exists(ch_client, record_id):
        _mark_event_persisted(record_id)
        metrics.increment("audit_consumer_duplicate_events_total")
        logger.info("Skipping duplicate audit event already in ClickHouse: record_id=%s", record_id)
        return

    if not _claim_event(record_id):
        metrics.increment("audit_consumer_duplicate_events_total")
        logger.info("Skipping duplicate audit event already claimed: record_id=%s", record_id)
        return

    try:
        # Check Redis cache first to avoid ClickHouse consistency issues.
        redis_key = f"audit_chain:{tenant_id}"
        prior_hash = None
        try:
            prior_hash = redis_client.get(redis_key)
        except Exception as redis_exc:
            logger.warning("Redis lookup failed, falling back to ClickHouse: %s", redis_exc)

        # Fallback to ClickHouse if cache miss or Redis error.
        if not prior_hash:
            prior_hash = get_prior_hash(ch_client, tenant_id)
            logger.debug("Cache miss for tenant %s. Fetched prior_hash from ClickHouse: %s", tenant_id, prior_hash)

        row["prior_hash"] = prior_hash

        # Compute integrity hash over data fields + prior hash.
        row["integrity_hash"] = compute_integrity_hash(row, prior_hash)

        inserted = insert_audit_event(ch_client, row)
        if not inserted:
            _mark_event_persisted(record_id)
            metrics.increment("audit_consumer_duplicate_events_total")
            return

        # Update Redis cache with the new tail hash.
        try:
            redis_client.set(redis_key, row["integrity_hash"])
        except Exception as redis_exc:
            logger.warning("Failed to update Redis cache: %s", redis_exc)
        _mark_event_persisted(record_id)
        metrics.increment("audit_consumer_clickhouse_inserts_total")
    except Exception:
        _release_event_claim(record_id)
        metrics.increment("audit_consumer_clickhouse_insert_failures_total")
        raise

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

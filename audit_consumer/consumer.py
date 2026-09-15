"""Validate PostgreSQL audit events and mirror them to ClickHouse."""

import hashlib
import json
import logging
import os
import signal
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from dotenv import load_dotenv
from clickhouse_writer import audit_event_exists, get_client, get_tenant_tail, insert_audit_event
from hash_chain import standardize_uuid, standardize_timestamp
from metrics import metrics
from transport import make_audit_consumer
from urllib.parse import parse_qs, urlparse

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("audit_consumer")

METRICS_PORT = int(os.getenv("AUDIT_CONSUMER_METRICS_PORT", "9108"))

CLICKHOUSE_HOST = os.getenv("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.getenv("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_DB = os.getenv("CLICKHOUSE_DB", "authclaw")
CLICKHOUSE_USER = os.getenv("CLICKHOUSE_USER", "authclaw")
CLICKHOUSE_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "")

class SequenceGapError(RuntimeError):
    """The mirror must wait for an earlier tenant sequence."""


class RetryableMirrorError(RuntimeError):
    """Transport position must remain unacknowledged until infrastructure recovers."""


class InvalidAuditEvent(ValueError):
    """The immutable PostgreSQL proof is malformed or inconsistent."""


def validate_runtime_environment() -> None:
    environment = os.getenv("AUTHCLAW_ENV", "local").strip().lower()
    valid_environments = {
        "local", "development", "dev", "test", "ci", "shared-test",
        "staging", "stage", "production", "prod",
    }
    if environment not in valid_environments:
        raise RuntimeError(
            f"AUTHCLAW_ENV {environment!r} is unsupported; configure an explicit local, test, staging, or production environment"
        )
    if environment not in {"ci", "shared-test", "staging", "stage", "production", "prod"}:
        return
    password = os.getenv("CLICKHOUSE_PASSWORD", "").strip()
    normalized_password = password.lower()
    if not password or normalized_password == "authclaw" or "change-me" in normalized_password:
        raise RuntimeError(
            "CLICKHOUSE_PASSWORD must be set to a non-default secret in shared environments"
        )
    if os.getenv("CLICKHOUSE_SECURE", "false").lower() != "true":
        raise RuntimeError("CLICKHOUSE_SECURE=true is required in shared environments")
    dsn = os.getenv("AUDIT_POSTGRES_URL", "")
    if not dsn or parse_qs(urlparse(dsn).query).get("sslmode") != ["verify-full"]:
        raise RuntimeError("AUDIT_POSTGRES_URL with sslmode=verify-full is required in shared environments")


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


def _metrics_bind_host() -> str:
    return os.getenv("AUDIT_CONSUMER_METRICS_HOST", "127.0.0.1").strip()


def _start_metrics_server() -> ThreadingHTTPServer | None:
    if METRICS_PORT <= 0:
        return None
    metrics_host = _metrics_bind_host()
    server = ThreadingHTTPServer((metrics_host, METRICS_PORT), _MetricsHandler)
    thread = threading.Thread(target=server.serve_forever, name="audit-consumer-metrics", daemon=True)
    thread.start()
    logger.info("Audit consumer metrics listening on %s:%s/metrics", metrics_host, METRICS_PORT)
    return server


_running = True


def _handle_signal(signum, _frame):
    global _running
    logger.info("Received signal %s — shutting down", signum)
    _running = False


signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT, _handle_signal)

def _parse_timestamp(raw) -> datetime:
    """Parse ISO-8601 or epoch timestamp into a UTC-aware datetime."""
    if isinstance(raw, (int, float)):
        return datetime.fromtimestamp(raw, tz=timezone.utc)
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise InvalidAuditEvent("canonical timestamp is not valid ISO-8601") from exc


_CANONICAL_FIELDS = {
    "record_id", "tenant_id", "tenant_sequence", "chain_version", "timestamp",
    "actor_id", "actor_type", "action", "policy_id", "provider", "model",
    "reason", "prompt_count", "request_size", "response_status", "duration_ms",
    "frameworks_affected", "execution_trace", "request_id",
}
_INTEGER_FIELDS = {
    "tenant_sequence", "chain_version", "prompt_count", "request_size",
    "response_status", "duration_ms",
}


def _comparable(field: str, value):
    if field in _INTEGER_FIELDS:
        if isinstance(value, bool) or not isinstance(value, int):
            raise InvalidAuditEvent(f"canonical {field} must be an integer")
        return value
    if field == "frameworks_affected":
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise InvalidAuditEvent("canonical frameworks_affected must be a string array")
        return value
    if not isinstance(value, str):
        raise InvalidAuditEvent(f"canonical {field} must be a string")
    return value


def _verified_canonical(payload: dict) -> tuple[dict, str, str, str]:
    canonical_payload = payload.get("canonical_payload")
    prior_hash = payload.get("prior_hash")
    integrity_hash = payload.get("integrity_hash")
    if not isinstance(canonical_payload, str) or not canonical_payload or not prior_hash or not integrity_hash:
        raise InvalidAuditEvent("canonical payload and PostgreSQL proof hashes are required")

    expected = hashlib.sha256((canonical_payload + str(prior_hash)).encode("utf-8")).hexdigest()
    if expected != str(integrity_hash):
        metrics.increment("audit_consumer_verification_failures_total")
        raise InvalidAuditEvent("PostgreSQL supplied an invalid audit integrity hash")

    try:
        canonical = json.loads(canonical_payload)
    except (TypeError, json.JSONDecodeError) as exc:
        raise InvalidAuditEvent("canonical_payload is not valid JSON") from exc
    if not isinstance(canonical, dict):
        raise InvalidAuditEvent("canonical_payload must be a JSON object")
    missing = sorted(_CANONICAL_FIELDS - canonical.keys())
    if missing:
        raise InvalidAuditEvent(f"canonical_payload is missing fields: {', '.join(missing)}")

    for field in _CANONICAL_FIELDS:
        canonical[field] = _comparable(field, canonical[field])
    if canonical["chain_version"] != 2 or canonical["tenant_sequence"] <= 0:
        raise InvalidAuditEvent("chain_version=2 and a positive tenant_sequence are required")

    aliases = {"id": "record_id", "record_id": "record_id", "audit_record_id": "record_id"}
    aliases.update({field: field for field in _CANONICAL_FIELDS if field != "record_id"})
    for envelope_field, canonical_field in aliases.items():
        if envelope_field not in payload:
            continue
        envelope_value = _comparable(canonical_field, payload[envelope_field])
        if envelope_value != canonical[canonical_field]:
            raise InvalidAuditEvent(
                f"canonical payload identity/envelope mismatch for {envelope_field}"
            )
    return canonical, canonical_payload, str(prior_hash), str(integrity_hash)


def normalise_event(payload: dict) -> dict:
    """
    Map a raw audit-stream payload (AuditEvent from Go gateway) to the
    ClickHouse row schema, including request_id.
    """
    canonical, canonical_payload, prior_hash, integrity_hash = _verified_canonical(payload)
    return {
        "record_id": canonical["record_id"],
        "tenant_id": canonical["tenant_id"],
        "tenant_sequence": canonical["tenant_sequence"],
        # Canonical v2 does not bind the transport idempotency key. Use its
        # immutable record identity for ClickHouse deduplication.
        "idempotency_key": canonical["record_id"],
        "chain_version": canonical["chain_version"],
        "canonical_payload": canonical_payload,
        "timestamp": _parse_timestamp(canonical["timestamp"]),
        "actor_id": canonical["actor_id"],
        "actor_type": canonical["actor_type"],
        "action": canonical["action"],
        "policy_id": canonical["policy_id"],
        "provider": canonical["provider"],
        "model": canonical["model"],
        "reason": canonical["reason"],
        "prompt_count": canonical["prompt_count"],
        "request_size": canonical["request_size"],
        "response_status": canonical["response_status"],
        "duration_ms": canonical["duration_ms"],
        "frameworks_affected": canonical["frameworks_affected"],
        "execution_trace": canonical["execution_trace"],
        "request_id": canonical["request_id"],
        "prior_hash": prior_hash,
        "integrity_hash": integrity_hash,
    }

def main():
    validate_runtime_environment()
    consumer = make_audit_consumer(metrics.set_gauge)
    logger.info(
        "Connecting audit transport topics=%s group=%s",
        consumer.topics,
        consumer.group_id,
    )
    metrics_server = _start_metrics_server()

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
        consumer.group_id,
        consumer.dlq_topic,
    )

    while _running:
        # Poll with a 1-second timeout so SIGTERM is handled promptly.
        for batch in consumer.poll(timeout_ms=1000):
            for message in batch:
                try:
                    consumer.begin(message)
                    if message.validation_error is not None:
                        raise message.validation_error
                    _process_message(ch_client, message.value)
                    consumer.ack(message)
                except (SequenceGapError, RetryableMirrorError) as exc:
                    logger.warning("Deferring audit mirror offset %s: %s", message.offset, exc)
                    consumer.retry(message)
                    metrics.increment("audit_consumer_retries_total")
                    time.sleep(0.25)
                    break
                except Exception as exc:  # noqa: BLE001
                    logger.error("Failed to process message: %s", exc)
                    if consumer.redrive_failures:
                        consumer.retry(message)
                        metrics.increment("audit_consumer_retries_total")
                        break
                    try:
                        consumer.publish_dlq(message.value or {}, str(exc))
                        metrics.increment("audit_consumer_dlq_published_total")
                    except Exception as dlq_exc:  # noqa: BLE001
                        logger.error("DLQ publish failed: %s", dlq_exc)
                        metrics.increment("audit_consumer_dlq_publish_failures_total")
                        consumer.retry(message)
                        metrics.increment("audit_consumer_retries_total")
                        break
                    consumer.ack(message)

    logger.info("Audit consumer stopped")
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
    dsn = os.getenv("AUDIT_POSTGRES_URL", "")
    if dsn:
        # Read authoritative evidence before even accepting a duplicate replay.
        # This credential must have SELECT only; no append or mutation privileges.
        try:
            import psycopg

            with psycopg.connect(dsn, connect_timeout=5) as connection:
                connection.execute("SET TRANSACTION READ ONLY")
                connection.execute("SELECT set_config('app.current_tenant_id', %s, true)", (tenant_id,))
                proof = connection.execute(
                    "SELECT canonical_payload, prior_hash, integrity_hash FROM public.audit_log_metadata "
                    "WHERE tenant_id = %s::uuid AND record_id = %s::uuid",
                    (tenant_id, record_id),
                ).fetchone()
        except Exception as exc:
            raise RetryableMirrorError("PostgreSQL origin verification unavailable") from exc
        if proof is None or tuple(proof) != (row["canonical_payload"], row["prior_hash"], row["integrity_hash"]):
            raise InvalidAuditEvent("event does not match authoritative PostgreSQL evidence")
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

import json
import os
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import text

from database import engine


def _truthy(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class EventPipeline:
    def __init__(self) -> None:
        self.kafka_rest_url = os.getenv("KAFKA_REST_URL", "").rstrip("/")
        self.kafka_audit_topic = os.getenv("KAFKA_AUDIT_TOPIC", os.getenv("AUTHCLAW_AUDIT_TOPIC", "authclaw-audit-events"))
        self.kafka_analytics_topic = os.getenv("KAFKA_ANALYTICS_TOPIC", "authclaw-analytics-events")
        self.kafka_dlq_topic = os.getenv("KAFKA_DLQ_TOPIC", "authclaw-dead-letter-events")
        self.clickhouse_enabled = _truthy("AUTHCLAW_CLICKHOUSE_ENABLED", True)
        self.max_attempts = int(os.getenv("AUTHCLAW_EVENT_DELIVERY_ATTEMPTS", "3"))
        self.timeout = float(os.getenv("AUTHCLAW_EVENT_DELIVERY_TIMEOUT_SECONDS", "1.5"))

    def record_and_deliver(self, event: Dict[str, Any], stream: str = "audit") -> Dict[str, Any]:
        topic = self.kafka_audit_topic if stream == "audit" else self.kafka_analytics_topic
        event_id = self._event_id(event)
        tenant_id = self._event_tenant(event)
        payload = json.dumps(event, sort_keys=True, default=str)
        with engine.connect() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO event_delivery_records (
                        event_id, tenant_id, stream, topic, source, status,
                        attempts, payload, created_at, updated_at
                    )
                    VALUES (
                        :event_id, :tenant_id, :stream, :topic, :source, 'queued',
                        0, :payload, NOW(), NOW()
                    )
                    ON CONFLICT (event_id) DO UPDATE SET
                        payload = EXCLUDED.payload,
                        updated_at = NOW()
                    """
                ),
                {
                    "event_id": event_id,
                    "tenant_id": tenant_id,
                    "stream": stream,
                    "topic": topic,
                    "source": str(event.get("event_type") or "event"),
                    "payload": payload,
                },
            )
            conn.commit()
        return self.deliver_event(event_id)

    def deliver_event(self, event_id: str) -> Dict[str, Any]:
        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT * FROM event_delivery_records WHERE event_id = :event_id"),
                {"event_id": event_id},
            ).fetchone()
        if not row:
            return {"status": "missing", "event_id": event_id}
        record = dict(row._mapping)
        event = json.loads(record["payload"])
        attempts = int(record["attempts"] or 0)
        errors = []
        delivered = False

        for attempt in range(attempts + 1, self.max_attempts + 1):
            try:
                self._publish_kafka_rest(record["topic"], event)
                if self.clickhouse_enabled:
                    self._write_clickhouse(event)
                delivered = True
                attempts = attempt
                break
            except Exception as exc:
                attempts = attempt
                errors.append(str(exc))
                time.sleep(min(0.05 * attempt, 0.25))

        status = "delivered" if delivered else "dead_letter"
        error_message = "; ".join(errors[-3:]) if errors else None
        with engine.connect() as conn:
            conn.execute(
                text(
                    """
                    UPDATE event_delivery_records
                    SET status = :status,
                        attempts = :attempts,
                        delivered_at = CASE WHEN :status = 'delivered' THEN NOW() ELSE delivered_at END,
                        error_message = :error_message,
                        next_retry_at = CASE WHEN :status = 'dead_letter' THEN NULL ELSE NOW() END,
                        updated_at = NOW()
                    WHERE event_id = :event_id
                    """
                ),
                {
                    "event_id": event_id,
                    "status": status,
                    "attempts": attempts,
                    "error_message": error_message,
                },
            )
            if status == "dead_letter":
                conn.execute(
                    text(
                        """
                        INSERT INTO event_dead_letters (
                            event_id, tenant_id, stream, topic, payload, error_message,
                            attempts, created_at
                        )
                        VALUES (
                            :event_id, :tenant_id, :stream, :topic, :payload, :error_message,
                            :attempts, NOW()
                        )
                        ON CONFLICT (event_id) DO UPDATE SET
                            error_message = EXCLUDED.error_message,
                            attempts = EXCLUDED.attempts
                        """
                    ),
                    {
                        "event_id": event_id,
                        "tenant_id": record["tenant_id"],
                        "stream": record["stream"],
                        "topic": self.kafka_dlq_topic,
                        "payload": record["payload"],
                        "error_message": error_message,
                        "attempts": attempts,
                    },
                )
            conn.commit()
        self.refresh_checkpoint(record["stream"])
        return {"status": status, "event_id": event_id, "attempts": attempts, "error_message": error_message}

    def retry_dead_letters(self, limit: int = 100) -> Dict[str, Any]:
        with engine.connect() as conn:
            rows = conn.execute(
                text(
                    """
                    SELECT event_id
                    FROM event_delivery_records
                    WHERE status = 'dead_letter'
                    ORDER BY updated_at ASC
                    LIMIT :limit
                    """
                ),
                {"limit": limit},
            ).fetchall()
        delivered = 0
        failed = 0
        for row in rows:
            with engine.connect() as conn:
                conn.execute(
                    text("UPDATE event_delivery_records SET status = 'queued', attempts = 0 WHERE event_id = :event_id"),
                    {"event_id": row.event_id},
                )
                conn.commit()
            result = self.deliver_event(row.event_id)
            if result["status"] == "delivered":
                delivered += 1
            else:
                failed += 1
        return {"retried": len(rows), "delivered": delivered, "failed": failed}

    def refresh_checkpoint(self, stream: str) -> None:
        with engine.connect() as conn:
            row = conn.execute(
                text(
                    """
                    SELECT
                        SUM(CASE WHEN status IN ('queued', 'dead_letter') THEN 1 ELSE 0 END) AS pending,
                        SUM(CASE WHEN status = 'dead_letter' THEN 1 ELSE 0 END) AS dead_letters,
                        EXTRACT(EPOCH FROM (
                            NOW() - MIN(CASE WHEN status IN ('queued', 'dead_letter') THEN created_at ELSE NULL END)
                        )) AS lag_seconds,
                        MAX(delivered_at) AS last_delivered_at
                    FROM event_delivery_records
                    WHERE stream = :stream
                    """
                ),
                {"stream": stream},
            ).fetchone()
            conn.execute(
                text(
                    """
                    INSERT INTO event_consumer_checkpoints (
                        stream, consumer_group, pending_events, dead_letter_count,
                        lag_seconds, last_delivered_at, updated_at
                    )
                    VALUES (
                        :stream, :consumer_group, :pending_events, :dead_letter_count,
                        :lag_seconds, :last_delivered_at, NOW()
                    )
                    ON CONFLICT (stream, consumer_group) DO UPDATE SET
                        pending_events = EXCLUDED.pending_events,
                        dead_letter_count = EXCLUDED.dead_letter_count,
                        lag_seconds = EXCLUDED.lag_seconds,
                        last_delivered_at = EXCLUDED.last_delivered_at,
                        updated_at = NOW()
                    """
                ),
                {
                    "stream": stream,
                    "consumer_group": "authclaw-analytics-ingestor",
                    "pending_events": int(row.pending or 0),
                    "dead_letter_count": int(row.dead_letters or 0),
                    "lag_seconds": int(row.lag_seconds or 0),
                    "last_delivered_at": row.last_delivered_at,
                },
            )
            conn.commit()

    def delivery_metrics(self) -> Dict[str, Any]:
        with engine.connect() as conn:
            rows = conn.execute(
                text(
                    """
                    SELECT stream, status, COUNT(*), COALESCE(MAX(attempts), 0)
                    FROM event_delivery_records
                    GROUP BY stream, status
                    """
                )
            ).fetchall()
            checkpoints = conn.execute(text("SELECT * FROM event_consumer_checkpoints ORDER BY stream")).fetchall()
        by_stream: Dict[str, Dict[str, Any]] = {}
        for stream, status, count, attempts in rows:
            by_stream.setdefault(stream, {"queued": 0, "delivered": 0, "dead_letter": 0, "max_attempts": 0})
            by_stream[stream][status] = int(count or 0)
            by_stream[stream]["max_attempts"] = max(by_stream[stream]["max_attempts"], int(attempts or 0))
        return {
            "kafka_rest_configured": bool(self.kafka_rest_url),
            "clickhouse_enabled": self.clickhouse_enabled,
            "streams": by_stream,
            "checkpoints": [dict(row._mapping) for row in checkpoints],
        }

    def _publish_kafka_rest(self, topic: str, event: Dict[str, Any]) -> None:
        if not self.kafka_rest_url:
            if _truthy("AUTHCLAW_REQUIRE_KAFKA", False):
                raise RuntimeError("Kafka REST/MSK endpoint is required but KAFKA_REST_URL is not configured")
            return
        endpoint = f"{self.kafka_rest_url}/topics/{urllib.parse.quote(topic)}"
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
        with urllib.request.urlopen(request, timeout=self.timeout) as response:  # nosec B310
            if response.status < 200 or response.status >= 300:
                raise RuntimeError(f"Kafka REST returned {response.status}")

    def _write_clickhouse(self, event: Dict[str, Any]) -> None:
        base_url = os.getenv("CLICKHOUSE_HTTP_URL")
        if not base_url:
            if _truthy("AUTHCLAW_REQUIRE_CLICKHOUSE", False):
                raise RuntimeError("ClickHouse endpoint is required but CLICKHOUSE_HTTP_URL is not configured")
            return
        database = os.getenv("CLICKHOUSE_DATABASE", "authclaw")
        table = os.getenv("CLICKHOUSE_AUDIT_TABLE", "audit_events")
        query = f"INSERT INTO {database}.{table} FORMAT JSONEachRow"
        params = {
            "query": query,
            "date_time_input_format": "best_effort",
            "input_format_skip_unknown_fields": "1",
        }
        request = urllib.request.Request(
            f"{base_url.rstrip('/')}/?{urllib.parse.urlencode(params)}",
            data=json.dumps(event, default=str).encode("utf-8") + b"\n",
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:  # nosec B310
            if response.status < 200 or response.status >= 300:
                raise RuntimeError(f"ClickHouse returned {response.status}")

    def _event_id(self, event: Dict[str, Any]) -> str:
        explicit = event.get("event_id") or event.get("request_id") or event.get("record_id")
        event_type = event.get("event_type") or "event"
        if explicit:
            return f"{event_type}:{explicit}"
        payload = json.dumps(event, sort_keys=True, default=str)
        import hashlib

        return f"{event_type}:sha256-{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:32]}"

    def _event_tenant(self, event: Dict[str, Any]) -> Optional[int]:
        try:
            value = event.get("tenant_id")
            return int(value) if value not in (None, "") else None
        except (TypeError, ValueError):
            return None

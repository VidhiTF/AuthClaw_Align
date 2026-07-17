"""Shared event-backbone helpers for backend audit publishers."""

from __future__ import annotations

import json
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

AUDIT_EVENTS_TOPIC = "audit.events"
AUDIT_DLQ_TOPIC = "audit.deadletter"
GATEWAY_TRAFFIC_TOPIC = "gateway.traffic"

_EVENT_NAMESPACE = uuid.UUID("3bd78033-64da-4a48-bd4f-9c105da706c7")
_metrics: defaultdict[str, int] = defaultdict(int)


def stable_event_id(*, event_type: str, tenant_id: str, subject_id: str, action: str, trace: list[str] | None = None) -> str:
    identity = {
        "event_type": event_type,
        "tenant_id": tenant_id,
        "subject_id": subject_id,
        "action": action,
        "trace": trace or [],
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return str(uuid.uuid5(_EVENT_NAMESPACE, canonical))


def audit_event(
    *,
    event_type: str,
    tenant_id: str,
    subject_id: str,
    identity_action: str,
    action: str,
    reason: str,
    provider: str,
    request_id: str = "",
    frameworks: list[str] | None = None,
    trace: list[str] | None = None,
) -> dict[str, Any]:
    execution_trace = trace or []
    return {
        "id": stable_event_id(
            event_type=event_type,
            tenant_id=tenant_id,
            subject_id=subject_id,
            action=identity_action,
            trace=execution_trace,
        ),
        "request_id": request_id,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "tenant_id": tenant_id,
        "policy_id": "",
        "action": action,
        "reason": reason,
        "provider": provider,
        "model": "",
        "prompt_count": 0,
        "request_size": 0,
        "response_status": 0,
        "duration_ms": 0,
        "frameworks_affected": frameworks or [],
        "execution_trace": execution_trace,
    }


def increment_metric(name: str, value: int = 1) -> None:
    _metrics[name] += value


def make_kafka_producer() -> Any:
    import os
    from kafka import KafkaProducer  # type: ignore[import-untyped]

    brokers = os.getenv("KAFKA_BROKERS", "localhost:9092").split(",")
    return KafkaProducer(
        bootstrap_servers=brokers,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        key_serializer=lambda k: k.encode("utf-8") if k else b"",
        acks=1,
    )


def publish_audit_event(producer: Any, tenant_id: str, event: dict[str, Any]) -> Exception | None:
    if exc := persist_audit_event(event):
        increment_metric("backend_audit_postgres_failures_total")
        return exc
    if not producer:
        return None
    try:
        future = producer.send(AUDIT_EVENTS_TOPIC, key=tenant_key(tenant_id), value=event)
        future.get(timeout=5)
    except Exception as exc:
        increment_metric("backend_audit_publish_failures_total")
        return exc
    return None


def persist_audit_event(event: dict[str, Any]) -> Exception | None:
    """Persist the authoritative hash-chained row before publishing analytics."""
    from sqlalchemy import text

    from app.db.models import AuditLogMetadata
    from app.db.session import SessionLocal
    from app.services.audit_store import GENESIS_HASH, compute_integrity_hash

    db = SessionLocal()
    try:
        tenant_id = str(event["tenant_id"])
        record_id = uuid.UUID(str(event["id"]))
        db.info["tenant_id"] = tenant_id
        db.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:tenant_id, 0))"),
            {"tenant_id": tenant_id},
        )
        existing = (
            db.query(AuditLogMetadata)
            .filter(AuditLogMetadata.record_id == record_id)
            .first()
        )
        if existing:
            event["prior_hash"] = existing.prior_hash or GENESIS_HASH
            event["integrity_hash"] = existing.integrity_hash or ""
            return None

        last = (
            db.query(AuditLogMetadata)
            .filter(AuditLogMetadata.tenant_id == uuid.UUID(tenant_id))
            .order_by(AuditLogMetadata.created_at.desc(), AuditLogMetadata.record_id.desc())
            .first()
        )
        prior_hash = last.integrity_hash if last and last.integrity_hash else GENESIS_HASH
        timestamp = datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00"))
        if last and last.created_at and timestamp <= last.created_at:
            timestamp = last.created_at + timedelta(milliseconds=1)
            event["timestamp"] = timestamp.isoformat()
        execution_trace = json.dumps(event.get("execution_trace") or [])
        actor_type = str(event.get("actor_type") or "backend")
        record = {
            "record_id": str(record_id),
            "tenant_id": tenant_id,
            "timestamp": timestamp,
            "actor_id": str(event.get("actor_id") or ""),
            "actor_type": actor_type,
            "action": str(event.get("action") or ""),
            "policy_id": str(event.get("policy_id") or ""),
            "provider": str(event.get("provider") or ""),
            "model": str(event.get("model") or ""),
            "reason": str(event.get("reason") or ""),
            "prompt_count": int(event.get("prompt_count") or 0),
            "request_size": int(event.get("request_size") or 0),
            "response_status": int(event.get("response_status") or 0),
            "duration_ms": int(event.get("duration_ms") or 0),
            "frameworks_affected": event.get("frameworks_affected") or [],
            "execution_trace": execution_trace,
            "request_id": str(event.get("request_id") or ""),
        }
        integrity_hash = compute_integrity_hash(record, prior_hash)
        db.add(
            AuditLogMetadata(
                tenant_id=uuid.UUID(tenant_id),
                record_id=record_id,
                actor_id=uuid.UUID(record["actor_id"]) if record["actor_id"] else None,
                actor_type=actor_type,
                action=record["action"],
                request_id=record["request_id"],
                policy_id=uuid.UUID(record["policy_id"]) if record["policy_id"] else None,
                provider=record["provider"],
                model=record["model"],
                reason=record["reason"],
                prompt_count=record["prompt_count"],
                request_size=record["request_size"],
                response_status=record["response_status"],
                duration_ms=record["duration_ms"],
                frameworks_affected=record["frameworks_affected"],
                execution_trace=execution_trace,
                prior_hash=prior_hash,
                integrity_hash=integrity_hash,
                created_at=timestamp,
            )
        )
        db.commit()
        event["actor_type"] = actor_type
        event["prior_hash"] = prior_hash
        event["integrity_hash"] = integrity_hash
        return None
    except Exception as exc:
        db.rollback()
        return exc
    finally:
        db.close()


def metrics_snapshot() -> dict[str, int]:
    return dict(_metrics)


def tenant_key(tenant_id: Any) -> str:
    return str(tenant_id or "")

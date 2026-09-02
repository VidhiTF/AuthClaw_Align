"""Shared event-backbone helpers for backend audit publishers."""

from __future__ import annotations

import json
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from app.services.audit_transport import (
    AUDIT_DLQ_TOPIC,
    AUDIT_EVENTS_TOPIC,
    GATEWAY_TRAFFIC_TOPIC,
    AuditPublisher,
    make_audit_publisher,
)

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


def make_kafka_producer() -> AuditPublisher:
    """Backward-compatible constructor; returns the configured audit publisher."""
    return make_audit_publisher()


def publish_audit_event(producer: AuditPublisher | None, tenant_id: str, event: dict[str, Any]) -> Exception | None:
    if exc := persist_audit_event(event):
        increment_metric("backend_audit_postgres_failures_total")
        return exc
    if not producer:
        return None
    return publish_pending_audit_events(producer, tenant_id)


def publish_pending_audit_events(
    producer: AuditPublisher,
    tenant_id: str,
    *,
    limit: int = 100,
) -> Exception | None:
    """Publish committed outbox rows in tenant sequence order."""
    from app.db.models import AuditOutbox
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        db.info["tenant_id"] = tenant_id
        pending = (
            db.query(AuditOutbox)
            .filter(
                AuditOutbox.tenant_id == uuid.UUID(tenant_id),
                AuditOutbox.published_at.is_(None),
            )
            .order_by(AuditOutbox.tenant_sequence.asc())
            .with_for_update(skip_locked=True)
            .limit(limit)
            .all()
        )
        _metrics["backend_audit_outbox_backlog"] = len(pending)
        _metrics["backend_audit_outbox_oldest_age_seconds"] = (
            max(
                0,
                int(
                    (
                        datetime.now(tz=timezone.utc)
                        - pending[0].created_at.replace(tzinfo=timezone.utc)
                        if pending[0].created_at.tzinfo is None
                        else datetime.now(tz=timezone.utc) - pending[0].created_at
                    ).total_seconds()
                ),
            )
            if pending
            else 0
        )
        for row in pending:
            try:
                producer.publish(
                    tenant_key(tenant_id),
                    row.event_payload,
                    audit_record_id=str(row.record_id),
                )
                row.published_at = datetime.now(tz=timezone.utc)
                row.publish_attempts += 1
                row.last_error = None
            except Exception as exc:
                row.publish_attempts += 1
                row.last_error = str(exc)[:2000]
                db.commit()
                increment_metric("backend_audit_publish_failures_total")
                return exc
        db.commit()
        _metrics["backend_audit_outbox_published_total"] += len(pending)
        return None
    except Exception as exc:
        db.rollback()
        increment_metric("backend_audit_publish_failures_total")
        return exc
    finally:
        db.close()


def persist_audit_event(event: dict[str, Any]) -> Exception | None:
    """Append through PostgreSQL and commit its transactional outbox row."""
    from app.db.session import SessionLocal
    from app.services.audit_store import append_audit_event

    db = SessionLocal()
    try:
        append_audit_event(db, event)
        db.commit()
        return None
    except Exception as exc:
        db.rollback()
        if "idempotency-key collision" in str(exc):
            increment_metric("backend_audit_idempotency_collisions_total")
        return exc
    finally:
        db.close()


def metrics_snapshot() -> dict[str, int]:
    return dict(_metrics)


def tenant_key(tenant_id: Any) -> str:
    return str(tenant_id or "")

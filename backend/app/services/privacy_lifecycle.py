"""Tenant-aware privacy retention and deletion operations."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session

from app.db.models import (
    AccessRequest,
    AccessRequestHistory,
    AuditLogMetadata,
    RedactionToken,
)
from app.services import event_backbone
from app.services.audit_store import append_audit_event

PURGE_ACTION = "privacy:purge_expired"
PURGE_DATA_CLASS = "redaction_token_mapping"


@dataclass(frozen=True)
class PrivacyPurgeResult:
    tenant_id: str
    deleted_count: int
    audit_record_id: str
    request_id: str
    duration_ms: int
    status: str


def _now_utc() -> datetime:
    return datetime.now(tz=timezone.utc)


def _add_purge_audit_record(
    db: Session,
    *,
    tenant_id: Any,
    request_id: str,
    actor_id: Any | None,
    deleted_count: int,
    duration_ms: int,
) -> AuditLogMetadata:
    created_at = _now_utc()
    record_id = uuid.uuid4()
    trace_items = [
        f"data_class={PURGE_DATA_CLASS}",
        f"deleted_count={deleted_count}",
        "retention_state=expired",
    ]

    event = {
        "id": str(record_id),
        "idempotency_key": f"privacy-purge:{request_id or record_id}",
        "tenant_id": str(tenant_id),
        "timestamp": created_at,
        "actor_id": str(actor_id) if actor_id else "",
        "actor_type": "privacy_lifecycle",
        "action": PURGE_ACTION,
        "policy_id": "",
        "provider": "control-plane",
        "model": "",
        "reason": f"Purged {deleted_count} expired redaction mappings",
        "prompt_count": 0,
        "request_size": 0,
        "response_status": 200,
        "duration_ms": duration_ms,
        "frameworks_affected": ["GDPR"],
        "execution_trace": trace_items,
        "request_id": request_id,
    }
    appended = append_audit_event(db, event)
    return AuditLogMetadata(
        tenant_id=tenant_id,
        record_id=appended["record_id"],
        tenant_sequence=appended["tenant_sequence"],
        idempotency_key=event["idempotency_key"],
        chain_version=2,
        canonical_payload=appended["canonical_payload"],
        actor_id=actor_id,
        actor_type="privacy_lifecycle",
        action=PURGE_ACTION,
        request_id=request_id,
        provider="control-plane",
        model="",
        reason=event["reason"],
        prompt_count=0,
        request_size=0,
        response_status=200,
        duration_ms=duration_ms,
        frameworks_affected=["GDPR"],
        execution_trace=json.dumps(trace_items),
        prior_hash=appended["prior_hash"],
        integrity_hash=appended["integrity_hash"],
        created_at=created_at,
    )


def purge_expired_redaction_mappings(
    db: Session,
    *,
    tenant_id: Any,
    request_id: str = "",
    actor_id: Any | None = None,
) -> PrivacyPurgeResult:
    safe_request_id = str(request_id or "")[:255]
    started = time.perf_counter()

    try:
        deleted_count = int(
            db.query(RedactionToken)
            .filter(RedactionToken.tenant_id == tenant_id)
            .filter(RedactionToken.expires_at.isnot(None))
            .filter(RedactionToken.expires_at <= func.now())
            .delete(synchronize_session=False)
        )

        duration_ms = max(
            0,
            int((time.perf_counter() - started) * 1000),
        )
        audit_log = _add_purge_audit_record(
            db,
            tenant_id=tenant_id,
            request_id=safe_request_id,
            actor_id=actor_id,
            deleted_count=deleted_count,
            duration_ms=duration_ms,
        )

        db.commit()

        event_backbone.increment_metric("privacy_purge_operations_total")
        event_backbone.increment_metric(
            "privacy_purged_records_total",
            deleted_count,
        )

        return PrivacyPurgeResult(
            tenant_id=str(tenant_id),
            deleted_count=deleted_count,
            audit_record_id=str(audit_log.record_id),
            request_id=safe_request_id,
            duration_ms=duration_ms,
            status="completed",
        )
    except Exception:
        db.rollback()
        event_backbone.increment_metric("privacy_purge_failures_total")
        raise


def purge_expired_access_requests(
    db: Session,
    *,
    now: datetime | None = None,
) -> int:
    """Delete expired public intake records under the approved ACL-15 policy."""
    evaluated_at = now or _now_utc()
    onboarding_started = func.access_request_onboarding_started(
        AccessRequest.business_email,
        AccessRequest.updated_at,
    )
    expired = (
        db.query(AccessRequest)
        .filter(
            or_(
                and_(
                    AccessRequest.status == "PENDING",
                    AccessRequest.created_at <= evaluated_at - timedelta(days=90),
                ),
                and_(
                    AccessRequest.status == "REJECTED",
                    AccessRequest.updated_at <= evaluated_at - timedelta(days=30),
                ),
                and_(
                    AccessRequest.status == "INVITED",
                    AccessRequest.updated_at <= evaluated_at - timedelta(days=30),
                    onboarding_started.is_(False),
                ),
            )
        )
        .all()
    )
    try:
        for request in expired:
            db.add(
                AccessRequestHistory(
                    access_request_id=request.id,
                    event_type="DELETED",
                    old_status=request.status,
                    new_status=None,
                    event_metadata={"policy": "ACL-15"},
                )
            )
            db.delete(request)
        db.commit()
    except Exception:
        db.rollback()
        event_backbone.increment_metric("access_request_deletion_failures_total")
        raise

    event_backbone.increment_metric("access_request_deletion_completed_total")
    event_backbone.increment_metric(
        "access_request_records_deleted_total",
        len(expired),
    )
    return len(expired)

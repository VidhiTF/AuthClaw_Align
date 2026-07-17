"""Tenant-aware privacy retention and deletion operations."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.models import AuditLogMetadata, RedactionToken
from app.services import event_backbone
from app.services.audit_store import GENESIS_HASH, compute_integrity_hash


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
    last = (
        db.query(AuditLogMetadata)
        .filter(AuditLogMetadata.tenant_id == tenant_id)
        .order_by(
            AuditLogMetadata.created_at.desc(),
            AuditLogMetadata.record_id.desc(),
        )
        .first()
    )
    prior_hash = (
        last.integrity_hash
        if last and last.integrity_hash
        else GENESIS_HASH
    )

    created_at = _now_utc()
    record_id = uuid.uuid4()
    trace_items = [
        f"data_class={PURGE_DATA_CLASS}",
        f"deleted_count={deleted_count}",
        "retention_state=expired",
    ]

    log = AuditLogMetadata(
        tenant_id=tenant_id,
        record_id=record_id,
        actor_id=actor_id,
        actor_type="privacy_lifecycle",
        action=PURGE_ACTION,
        request_id=request_id,
        provider="control-plane",
        model="",
        reason=f"Purged {deleted_count} expired redaction mappings",
        prompt_count=0,
        request_size=0,
        response_status=200,
        duration_ms=duration_ms,
        frameworks_affected=["GDPR"],
        execution_trace=json.dumps(trace_items),
        prior_hash=prior_hash,
        created_at=created_at,
    )

    hash_record = {
        "record_id": str(record_id),
        "tenant_id": str(tenant_id),
        "timestamp": created_at,
        "actor_id": str(actor_id) if actor_id else "",
        "actor_type": "privacy_lifecycle",
        "action": PURGE_ACTION,
        "policy_id": "",
        "provider": "control-plane",
        "model": "",
        "reason": log.reason,
        "prompt_count": 0,
        "request_size": 0,
        "response_status": 200,
        "duration_ms": duration_ms,
        "frameworks_affected": ["GDPR"],
        "execution_trace": log.execution_trace,
        "request_id": request_id,
    }
    log.integrity_hash = compute_integrity_hash(hash_record, prior_hash)
    db.add(log)
    return log


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

        event_backbone.increment_metric(
            "privacy_purge_operations_total"
        )
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
        event_backbone.increment_metric(
            "privacy_purge_failures_total"
        )
        raise
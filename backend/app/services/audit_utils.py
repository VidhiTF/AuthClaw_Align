"""Shared audit canonicalization helpers."""

import uuid
from datetime import datetime, timezone
from typing import Any

__all__ = ["canonical_audit_record", "standardize_timestamp", "standardize_uuid"]


def standardize_uuid(val: Any) -> str:
    if not val:
        return ""
    try:
        return str(uuid.UUID(str(val)))
    except ValueError:
        return str(val)


def standardize_timestamp(ts: Any) -> str:
    if isinstance(ts, (int, float)):
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    elif isinstance(ts, str):
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    elif isinstance(ts, datetime):
        dt = ts
    else:
        dt = datetime.now(tz=timezone.utc)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)

    ms = dt.microsecond // 1000
    return f"{dt.strftime('%Y-%m-%dT%H:%M:%S')}.{ms:03d}Z"


def canonical_audit_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_id": standardize_uuid(record.get("record_id")),
        "tenant_id": standardize_uuid(record.get("tenant_id")),
        "timestamp": standardize_timestamp(record.get("timestamp")),
        "actor_id": str(record.get("actor_id", "")),
        "actor_type": str(record.get("actor_type", "")),
        "action": str(record.get("action", "")),
        "policy_id": str(record.get("policy_id", "")),
        "provider": str(record.get("provider", "")),
        "model": str(record.get("model", "")),
        "reason": str(record.get("reason", "")),
        "prompt_count": int(record.get("prompt_count", 0)),
        "request_size": int(record.get("request_size", 0)),
        "response_status": int(record.get("response_status", 0)),
        "duration_ms": int(record.get("duration_ms", 0)),
        "frameworks_affected": sorted(list(record.get("frameworks_affected") or [])),
        "execution_trace": str(record.get("execution_trace", "[]")),
        "request_id": str(record.get("request_id", "")),
    }

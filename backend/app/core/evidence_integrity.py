"""Canonical integrity metadata for tenant-scoped compliance evidence."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any


INTEGRITY_ALGORITHM = "sha256"
INTEGRITY_VERSION = 1


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def canonical_evidence_payload(
    *,
    evidence_id: Any,
    tenant_id: Any,
    workflow_id: str | None,
    framework: str,
    source_type: str,
    source_reference: str | None,
    evidence_type: str,
    evidence_data: dict[str, Any],
    severity: str,
    created_at: datetime,
) -> str:
    payload = {
        "created_at": _timestamp(created_at),
        "evidence_data": evidence_data or {},
        "evidence_type": evidence_type,
        "framework": framework.upper(),
        "id": str(evidence_id),
        "severity": severity.lower(),
        "source_reference": source_reference or "",
        "source_type": source_type,
        "tenant_id": str(tenant_id),
        "workflow_id": workflow_id or "",
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def compute_evidence_integrity_hash(**values: Any) -> str:
    canonical = canonical_evidence_payload(**values)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_evidence_integrity(record: Any) -> bool:
    expected = compute_evidence_integrity_hash(
        evidence_id=record.id,
        tenant_id=record.tenant_id,
        workflow_id=record.workflow_id,
        framework=record.framework,
        source_type=record.source_type,
        source_reference=record.source_reference,
        evidence_type=record.evidence_type,
        evidence_data=record.evidence_data or {},
        severity=record.severity,
        created_at=record.created_at,
    )
    return bool(record.integrity_hash) and expected == record.integrity_hash

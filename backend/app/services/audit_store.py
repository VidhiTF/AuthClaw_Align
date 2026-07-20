"""Audit store hardening helpers.

PostgreSQL remains the tenant-scoped chain of record. ClickHouse is the
high-volume analytics copy, populated either by the Kafka consumer or by replay
from Postgres. Replay preserves Postgres prior_hash/integrity_hash values.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from typing import Any, Iterable

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.models import AuditLogMetadata
from app.services.audit_utils import (
    canonical_audit_record,
    standardize_timestamp,
    standardize_uuid,
)

GENESIS_HASH = "GENESIS"

CLICKHOUSE_COLUMNS = [
    "record_id",
    "tenant_id",
    "tenant_sequence",
    "idempotency_key",
    "chain_version",
    "canonical_payload",
    "timestamp",
    "actor_id",
    "actor_type",
    "action",
    "policy_id",
    "provider",
    "model",
    "reason",
    "prompt_count",
    "request_size",
    "response_status",
    "duration_ms",
    "frameworks_affected",
    "execution_trace",
    "request_id",
    "prior_hash",
    "integrity_hash",
]


@dataclass(frozen=True)
class AuditConsistencyReport:
    tenant_id: str
    postgres_count: int
    clickhouse_count: int
    missing_in_clickhouse: list[str]
    extra_in_clickhouse: list[str]
    hash_mismatches: list[dict[str, str]]
    postgres_chain_valid: bool
    clickhouse_chain_valid: bool

    @property
    def consistent(self) -> bool:
        return (
            self.postgres_count == self.clickhouse_count
            and not self.missing_in_clickhouse
            and not self.extra_in_clickhouse
            and not self.hash_mismatches
            and self.postgres_chain_valid
            and self.clickhouse_chain_valid
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "consistent": self.consistent,
            "postgres_count": self.postgres_count,
            "clickhouse_count": self.clickhouse_count,
            "missing_in_clickhouse": self.missing_in_clickhouse,
            "extra_in_clickhouse": self.extra_in_clickhouse,
            "hash_mismatches": self.hash_mismatches,
            "postgres_chain_valid": self.postgres_chain_valid,
            "clickhouse_chain_valid": self.clickhouse_chain_valid,
        }


def canonical_json(record: dict[str, Any]) -> str:
    return json.dumps(canonical_audit_record(record), sort_keys=True, separators=(",", ":"))


def compute_integrity_hash(record: dict[str, Any], prior_hash: str) -> str:
    payload = (
        record.get("canonical_payload")
        if int(record.get("chain_version") or 1) >= 2
        else None
    ) or canonical_json(record)
    return hashlib.sha256((str(payload) + prior_hash).encode("utf-8")).hexdigest()


def append_audit_event(db: Session, event: dict[str, Any]) -> dict[str, Any]:
    """Call the only authoritative audit append implementation."""
    tenant_id = str(event["tenant_id"])
    record_id = str(event.get("id") or event.get("record_id") or uuid.uuid4())
    idempotency_key = str(event.get("idempotency_key") or record_id)
    db.info["tenant_id"] = tenant_id
    trace = event.get("execution_trace") or []
    if isinstance(trace, str):
        trace = json.loads(trace)
    timestamp = event.get("timestamp")
    if not timestamp:
        raise ValueError("audit event timestamp is required")

    result = db.execute(
        text(
            """
            SELECT *
            FROM append_audit_event_v2(
                CAST(:tenant_id AS uuid),
                CAST(:record_id AS uuid),
                :idempotency_key,
                CAST(:occurred_at AS timestamptz),
                CAST(NULLIF(:actor_id, '') AS uuid),
                :actor_type,
                :action,
                :request_id,
                CAST(NULLIF(:policy_id, '') AS uuid),
                :provider,
                :model,
                :reason,
                :prompt_count,
                :request_size,
                :response_status,
                :duration_ms,
                CAST(:frameworks AS text[]),
                CAST(:execution_trace AS jsonb)
            )
            """
        ),
        {
            "tenant_id": tenant_id,
            "record_id": record_id,
            "idempotency_key": idempotency_key,
            "occurred_at": timestamp,
            "actor_id": str(event.get("actor_id") or ""),
            "actor_type": str(event.get("actor_type") or "backend"),
            "action": str(event.get("action") or ""),
            "request_id": str(event.get("request_id") or ""),
            "policy_id": str(event.get("policy_id") or ""),
            "provider": str(event.get("provider") or ""),
            "model": str(event.get("model") or ""),
            "reason": str(event.get("reason") or ""),
            "prompt_count": int(event.get("prompt_count") or 0),
            "request_size": int(event.get("request_size") or 0),
            "response_status": int(event.get("response_status") or 0),
            "duration_ms": int(event.get("duration_ms") or 0),
            "frameworks": list(event.get("frameworks_affected") or []),
            "execution_trace": json.dumps(trace, sort_keys=True, separators=(",", ":")),
        },
    ).mappings().one()
    appended = dict(result)
    event.update(
        {
            "id": str(appended["record_id"]),
            "idempotency_key": idempotency_key,
            "tenant_sequence": int(appended["tenant_sequence"]),
            "chain_version": 2,
            "prior_hash": appended["prior_hash"],
            "integrity_hash": appended["integrity_hash"],
            "canonical_payload": appended["canonical_payload"],
        }
    )
    return appended


def postgres_audit_row(log: AuditLogMetadata) -> dict[str, Any]:
    actor_type = getattr(log, "actor_type", None) or "gateway"
    execution_trace = getattr(log, "execution_trace", None) or "[]"
    if isinstance(execution_trace, (list, dict)):
        execution_trace = json.dumps(execution_trace)
    return {
        "record_id": str(log.record_id),
        "tenant_id": str(log.tenant_id),
        "tenant_sequence": int(getattr(log, "tenant_sequence", 0) or 0),
        "idempotency_key": str(getattr(log, "idempotency_key", "") or ""),
        "chain_version": int(getattr(log, "chain_version", 1) or 1),
        "canonical_payload": str(getattr(log, "canonical_payload", "") or ""),
        "timestamp": log.created_at,
        "actor_id": str(log.actor_id) if log.actor_id else "",
        "actor_type": actor_type,
        "action": log.action,
        "policy_id": str(log.policy_id) if log.policy_id else "",
        "provider": log.provider or "",
        "model": log.model or "",
        "reason": log.reason or "",
        "prompt_count": log.prompt_count or 0,
        "request_size": log.request_size or 0,
        "response_status": log.response_status or 0,
        "duration_ms": log.duration_ms or 0,
        "frameworks_affected": log.frameworks_affected or [],
        "execution_trace": execution_trace,
        "request_id": log.request_id or "",
        "prior_hash": log.prior_hash or GENESIS_HASH,
        "integrity_hash": log.integrity_hash or "",
    }


def normalize_clickhouse_row(row: dict[str, Any]) -> dict[str, Any]:
    normalized = {key: row.get(key) for key in CLICKHOUSE_COLUMNS}
    normalized["record_id"] = standardize_uuid(normalized.get("record_id"))
    normalized["tenant_id"] = standardize_uuid(normalized.get("tenant_id"))
    normalized["tenant_sequence"] = int(normalized.get("tenant_sequence") or 0)
    normalized["idempotency_key"] = str(normalized.get("idempotency_key") or "")
    normalized["chain_version"] = int(normalized.get("chain_version") or 1)
    normalized["canonical_payload"] = str(normalized.get("canonical_payload") or "")
    normalized["actor_id"] = str(normalized.get("actor_id") or "")
    normalized["actor_type"] = str(normalized.get("actor_type") or "")
    normalized["policy_id"] = str(normalized.get("policy_id") or "")
    normalized["provider"] = str(normalized.get("provider") or "")
    normalized["model"] = str(normalized.get("model") or "")
    normalized["reason"] = str(normalized.get("reason") or "")
    normalized["action"] = str(normalized.get("action") or "")
    normalized["prompt_count"] = int(normalized.get("prompt_count") or 0)
    normalized["request_size"] = int(normalized.get("request_size") or 0)
    normalized["response_status"] = int(normalized.get("response_status") or 0)
    normalized["duration_ms"] = int(normalized.get("duration_ms") or 0)
    normalized["frameworks_affected"] = list(normalized.get("frameworks_affected") or [])
    normalized["execution_trace"] = str(normalized.get("execution_trace") or "[]")
    normalized["request_id"] = str(normalized.get("request_id") or "")
    normalized["prior_hash"] = str(normalized.get("prior_hash") or GENESIS_HASH)
    normalized["integrity_hash"] = str(normalized.get("integrity_hash") or "")
    return normalized


def _chain_valid(records: Iterable[dict[str, Any]]) -> bool:
    prior_hash = GENESIS_HASH
    prior_sequence = 0
    for record in records:
        sequence = int(record.get("tenant_sequence") or prior_sequence + 1)
        if prior_sequence and sequence != prior_sequence + 1:
            return False
        expected = compute_integrity_hash(record, record.get("prior_hash") or GENESIS_HASH)
        if record.get("prior_hash") != prior_hash:
            return False
        if record.get("integrity_hash") != expected:
            return False
        prior_hash = record.get("integrity_hash") or expected
        prior_sequence = sequence
    return True


def get_postgres_records(db: Session, tenant_id: str) -> list[dict[str, Any]]:
    logs = (
        db.query(AuditLogMetadata)
        .filter(AuditLogMetadata.tenant_id == tenant_id)
        .order_by(AuditLogMetadata.tenant_sequence.asc())
        .all()
    )
    return [postgres_audit_row(log) for log in logs]


def fetch_clickhouse_records(ch: Any, tenant_id: str) -> list[dict[str, Any]]:
    result = ch.query(
        """
        SELECT
            toString(record_id) AS record_id,
            toString(tenant_id) AS tenant_id,
            tenant_sequence,
            idempotency_key,
            chain_version,
            canonical_payload,
            timestamp,
            actor_id,
            actor_type,
            action,
            policy_id,
            provider,
            model,
            reason,
            prompt_count,
            request_size,
            response_status,
            duration_ms,
            frameworks_affected,
            execution_trace,
            request_id,
            prior_hash,
            integrity_hash
        FROM authclaw.audit_events AS ae
        WHERE ae.tenant_id = {tenant_id:UUID}
        ORDER BY tenant_sequence ASC
        """,
        parameters={"tenant_id": tenant_id},
    )
    return [normalize_clickhouse_row(dict(zip(result.column_names, row))) for row in result.result_rows]


def build_consistency_report(db: Session, ch: Any, tenant_id: str) -> AuditConsistencyReport:
    postgres_records = get_postgres_records(db, tenant_id)
    clickhouse_records = fetch_clickhouse_records(ch, tenant_id)
    postgres_by_id = {record["record_id"]: record for record in postgres_records}
    clickhouse_by_id = {record["record_id"]: record for record in clickhouse_records}

    missing = sorted(set(postgres_by_id) - set(clickhouse_by_id))
    extra = sorted(set(clickhouse_by_id) - set(postgres_by_id))
    mismatches: list[dict[str, str]] = []
    for record_id in sorted(set(postgres_by_id) & set(clickhouse_by_id)):
        pg = postgres_by_id[record_id]
        ch_record = clickhouse_by_id[record_id]
        if pg.get("prior_hash") != ch_record.get("prior_hash") or pg.get("integrity_hash") != ch_record.get("integrity_hash"):
            mismatches.append(
                {
                    "record_id": record_id,
                    "postgres_prior_hash": pg.get("prior_hash", ""),
                    "clickhouse_prior_hash": ch_record.get("prior_hash", ""),
                    "postgres_integrity_hash": pg.get("integrity_hash", ""),
                    "clickhouse_integrity_hash": ch_record.get("integrity_hash", ""),
                }
            )

    return AuditConsistencyReport(
        tenant_id=tenant_id,
        postgres_count=len(postgres_records),
        clickhouse_count=len(clickhouse_records),
        missing_in_clickhouse=missing,
        extra_in_clickhouse=extra,
        hash_mismatches=mismatches,
        postgres_chain_valid=_chain_valid(postgres_records),
        clickhouse_chain_valid=_chain_valid(clickhouse_records),
    )


def replay_postgres_to_clickhouse(db: Session, ch: Any, tenant_id: str, *, dry_run: bool = False) -> dict[str, Any]:
    postgres_records = get_postgres_records(db, tenant_id)
    clickhouse_existing = {record["record_id"] for record in fetch_clickhouse_records(ch, tenant_id)}
    rows = [record for record in postgres_records if record["record_id"] not in clickhouse_existing]

    if not dry_run and rows:
        ch.insert(
            table="authclaw.audit_events",
            data=[[row.get(column) for column in CLICKHOUSE_COLUMNS] for row in rows],
            column_names=CLICKHOUSE_COLUMNS,
        )

    return {
        "tenant_id": tenant_id,
        "source": "postgres",
        "target": "clickhouse",
        "dry_run": dry_run,
        "postgres_count": len(postgres_records),
        "already_present": len(clickhouse_existing),
        "skipped": len(clickhouse_existing),
        "inserted": 0 if dry_run else len(rows),
        "would_insert": len(rows),
        "record_ids": [row["record_id"] for row in rows],
    }


def recover_clickhouse_to_postgres(db: Session, ch: Any, tenant_id: str, *, dry_run: bool = True) -> dict[str, Any]:
    """Reject reverse recovery: ClickHouse is never an audit authority."""
    del db, ch, tenant_id, dry_run
    raise RuntimeError(
        "ClickHouse-to-PostgreSQL recovery is disabled; replay PostgreSQL to ClickHouse"
    )


def clickhouse_configured() -> bool:
    return bool(os.getenv("CLICKHOUSE_HOST"))

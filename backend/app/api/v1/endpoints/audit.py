"""
GET /audit-logs — Paginated audit log retrieval with optional ClickHouse backend
and hash-chain integrity verification.

Primary backend: ClickHouse (when CLICKHOUSE_HOST is configured).
Fallback: PostgreSQL audit_log_metadata table (Phase 6 compatibility preserved).
"""

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.auth import get_tenant_db, require_roles, require_scopes
from app.db.models import AuditLogMetadata
from app.services.audit_store import (
    build_consistency_report,
    clickhouse_configured,
    replay_postgres_to_clickhouse,
)
from app.services.audit_export import (
    build_signed_audit_export,
    signing_key_metadata,
    verify_signed_audit_export,
)
from app.services.audit_utils import (
    canonical_audit_record,
    standardize_timestamp,
    standardize_uuid,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# ──────────────────────────────────────────────────────────────────────────────
# Response schemas
# ──────────────────────────────────────────────────────────────────────────────


class ClickHouseAuditEvent(BaseModel):
    record_id: str
    tenant_id: str
    timestamp: datetime
    actor_id: str
    actor_type: str
    action: str
    policy_id: str
    provider: str
    model: str
    reason: str
    prompt_count: int
    request_size: int
    response_status: int
    duration_ms: int
    frameworks_affected: List[str]
    execution_trace: str = "[]"
    request_id: str = ""  # propagated from X-Request-ID gateway header
    prior_hash: str
    integrity_hash: str
    # Populated when integrity_check=true
    chain_valid: Optional[bool] = None


class AuditLogsResponse(BaseModel):
    source: str  # "clickhouse" | "postgres"
    total: int
    records: List[Any]
    integrity_checked: bool = False


class AuditStoreStatusResponse(BaseModel):
    analytics_store: str
    chain_of_record: str
    clickhouse_configured: bool
    clickhouse_available: bool
    detail: str


class AuditReplayRequest(BaseModel):
    dry_run: bool = False


class SignedAuditExportRequest(BaseModel):
    action: Optional[str] = None
    framework: Optional[str] = None
    start: Optional[datetime] = None
    end: Optional[datetime] = None


class SignedAuditVerifyRequest(BaseModel):
    artifact: Dict[str, Any]


class SignedAuditVerifyResponse(BaseModel):
    verified: bool
    signature_valid: bool
    digest_valid: bool
    chain_valid: bool
    record_count: int
    tenant_id: str
    key_id: str
    errors: List[str]
    first_record_id: str
    last_record_id: str
    first_hash: str
    last_hash: str


# ──────────────────────────────────────────────────────────────────────────────
# ClickHouse client factory
# ──────────────────────────────────────────────────────────────────────────────


def _get_clickhouse_client() -> Optional[Any]:
    """Return a ClickHouse client, or None if CLICKHOUSE_HOST is not configured.
    Bubbles up exceptions if host is configured but connection fails.
    """
    host = os.getenv("CLICKHOUSE_HOST")
    if not host:
        return None
    try:
        import clickhouse_connect
    except ImportError as exc:
        raise RuntimeError(
            "clickhouse_connect is required when CLICKHOUSE_HOST is configured"
        ) from exc
    return clickhouse_connect.get_client(
        host=host,
        port=int(os.getenv("CLICKHOUSE_PORT", "8123")),
        database=os.getenv("CLICKHOUSE_DB", "authclaw"),
        username=os.getenv("CLICKHOUSE_USER", "authclaw"),
        password=os.getenv("CLICKHOUSE_PASSWORD", ""),
    )


# ──────────────────────────────────────────────────────────────────────────────
# Hash-chain verification
# ──────────────────────────────────────────────────────────────────────────────

_GENESIS_HASH = "GENESIS"


def _canonical_json(record: dict) -> str:
    return json.dumps(canonical_audit_record(record), sort_keys=True, separators=(",", ":"))


def _verify_chain(records: List[dict]) -> List[dict]:
    """Annotate each record with chain_valid=True/False (verifying chronologically)."""
    # Reverse records to go oldest -> newest for rolling verification
    asc_records = list(reversed(records))
    last_hash_by_tenant: Dict[str, str] = {}
    last_sequence_by_tenant: Dict[str, int] = {}

    for record in asc_records:
        tenant_id = record.get("tenant_id", "")
        prior_hash = record.get("prior_hash") or _GENESIS_HASH
        canonical = (
            record.get("canonical_payload")
            if int(record.get("chain_version") or 1) >= 2
            else None
        ) or _canonical_json(record)
        data = str(canonical) + prior_hash
        expected = hashlib.sha256(data.encode("utf-8")).hexdigest()
        actual = record.get("integrity_hash", "")
        previous_hash = last_hash_by_tenant.get(tenant_id)
        sequence = int(record.get("tenant_sequence") or 0)
        previous_sequence = last_sequence_by_tenant.get(tenant_id)
        link_valid = (
            (previous_hash is None or prior_hash == previous_hash)
            and (
                previous_sequence is None
                or not sequence
                or sequence == previous_sequence + 1
            )
        )
        record["chain_valid"] = bool(actual) and expected == actual and link_valid
        if actual:
            last_hash_by_tenant[tenant_id] = actual
        if sequence:
            last_sequence_by_tenant[tenant_id] = sequence

    # Reverse back to keep original order (newest first)
    return list(reversed(asc_records))


# ──────────────────────────────────────────────────────────────────────────────
# Endpoint
# ──────────────────────────────────────────────────────────────────────────────


@router.get(
    "",
    response_model=AuditLogsResponse,
    dependencies=[require_scopes(["read"])],
)
def get_audit_logs(
    request: Request,
    db: Session = Depends(get_tenant_db),
    limit: int = Query(default=100, le=1000, ge=1),
    offset: int = Query(default=0, ge=0),
    action: Optional[str] = Query(default=None, description="Filter by action: allow|block"),
    integrity_check: bool = Query(
        default=False,
        description="If true, verify SHA-256 hash chain and annotate each record with chain_valid",
    ),
):
    """
    Retrieve audit log records, tenant-scoped.

    - Primary source: ClickHouse (if CLICKHOUSE_HOST env var is set).
    - Fallback: PostgreSQL audit_log_metadata table.
    - Set integrity_check=true to verify the SHA-256 hash chain.
    """
    tenant_id: str = str(request.state.tenant_id)
    # ── ClickHouse path ────────────────────────────────────────────────────────
    host = os.getenv("CLICKHOUSE_HOST")
    if host:
        try:
            ch = _get_clickhouse_client()
            if ch is not None:
                return _query_clickhouse(ch, tenant_id, limit, offset, action, integrity_check)
        except Exception as exc:
            logger.error("ClickHouse connection or query failed: %s", exc)
            raise HTTPException(
                status_code=503,
                detail=f"ClickHouse audit storage configured but unavailable: {str(exc)}"
            )

    # ── PostgreSQL fallback ────────────────────────────────────────────────────
    return _query_postgres(db, tenant_id, limit, offset, action, integrity_check)


@router.get(
    "/export/signing-key",
    dependencies=[require_scopes(["read"])],
)
def get_audit_export_signing_key():
    try:
        return signing_key_metadata()
    except Exception as exc:
        logger.error("Audit export signing key metadata failed: %s", exc)
        raise HTTPException(status_code=500, detail="Audit export signing key is not configured") from exc


@router.post(
    "/export",
    dependencies=[require_scopes(["read"])],
)
def create_signed_audit_export(
    request: Request,
    export_request: SignedAuditExportRequest,
    db: Session = Depends(get_tenant_db),
):
    try:
        return build_signed_audit_export(
            db,
            tenant_id=str(request.state.tenant_id),
            requested_by=str(getattr(request.state, "user_id", "")),
            action=export_request.action,
            framework=export_request.framework,
            start=export_request.start.astimezone(timezone.utc) if export_request.start else None,
            end=export_request.end.astimezone(timezone.utc) if export_request.end else None,
        )
    except Exception as exc:
        logger.error("Signed audit export failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Signed audit export failed: {str(exc)}") from exc


@router.post(
    "/export/verify",
    response_model=SignedAuditVerifyResponse,
    dependencies=[require_scopes(["read"])],
)
def verify_audit_export(verify_request: SignedAuditVerifyRequest):
    return verify_signed_audit_export(verify_request.artifact).as_dict()


@router.get(
    "/store/status",
    response_model=AuditStoreStatusResponse,
    dependencies=[require_scopes(["read"])],
)
def get_audit_store_status():
    if not clickhouse_configured():
        return AuditStoreStatusResponse(
            analytics_store="postgres_fallback",
            chain_of_record="postgres",
            clickhouse_configured=False,
            clickhouse_available=False,
            detail="CLICKHOUSE_HOST is not configured; audit reads use Postgres fallback.",
        )
    try:
        ch = _get_clickhouse_client()
        ch.query("SELECT 1")
    except Exception:
        return AuditStoreStatusResponse(
            analytics_store="clickhouse",
            chain_of_record="postgres",
            clickhouse_configured=True,
            clickhouse_available=False,
            detail="ClickHouse configured but unavailable.",
        )
    return AuditStoreStatusResponse(
        analytics_store="clickhouse",
        chain_of_record="postgres",
        clickhouse_configured=True,
        clickhouse_available=True,
        detail="ClickHouse is configured and reachable; Postgres remains chain-of-record.",
    )


@router.get(
    "/store/consistency",
    dependencies=[require_scopes(["read"])],
)
def get_audit_store_consistency(
    request: Request,
    db: Session = Depends(get_tenant_db),
):
    ch = _get_clickhouse_client()
    if ch is None:
        raise HTTPException(status_code=503, detail="ClickHouse is not configured")
    tenant_id = str(request.state.tenant_id)
    return build_consistency_report(db, ch, tenant_id).as_dict()


@router.post(
    "/store/replay",
    dependencies=[require_roles(["owner", "admin"]), require_scopes(["write"])],
)
def replay_audit_store(
    request: Request,
    replay: AuditReplayRequest,
    db: Session = Depends(get_tenant_db),
):
    ch = _get_clickhouse_client()
    if ch is None:
        raise HTTPException(status_code=503, detail="ClickHouse is not configured")
    tenant_id = str(request.state.tenant_id)
    return replay_postgres_to_clickhouse(db, ch, tenant_id, dry_run=replay.dry_run)


# ──────────────────────────────────────────────────────────────────────────────
# ClickHouse query
# ──────────────────────────────────────────────────────────────────────────────


def _query_clickhouse(
    ch: Any,
    tenant_id: str,
    limit: int,
    offset: int,
    action: Optional[str],
    integrity_check: bool,
) -> AuditLogsResponse:
    action_filter = "AND action = {action:String}" if action else ""
    params: dict = {"tenant_id": tenant_id, "limit": limit, "offset": offset}
    if action:
        params["action"] = action

    query = f"""
        SELECT
            toString(ae.record_id)    AS record_id,
            toString(ae.tenant_id)    AS tenant_id,
            ae.tenant_sequence        AS tenant_sequence,
            ae.idempotency_key        AS idempotency_key,
            ae.chain_version          AS chain_version,
            ae.canonical_payload      AS canonical_payload,
            ae.timestamp              AS timestamp,
            ae.actor_id               AS actor_id,
            ae.actor_type             AS actor_type,
            ae.action                 AS action,
            ae.policy_id              AS policy_id,
            ae.provider               AS provider,
            ae.model                  AS model,
            ae.reason                 AS reason,
            ae.prompt_count           AS prompt_count,
            ae.request_size           AS request_size,
            ae.response_status        AS response_status,
            ae.duration_ms            AS duration_ms,
            ae.frameworks_affected    AS frameworks_affected,
            ae.execution_trace        AS execution_trace,
            ae.request_id             AS request_id,
            ae.prior_hash             AS prior_hash,
            ae.integrity_hash         AS integrity_hash
        FROM authclaw.audit_events AS ae
        WHERE ae.tenant_id = {{tenant_id:UUID}}
        {action_filter}
        ORDER BY ae.tenant_sequence DESC
        LIMIT {{limit:UInt32}}
        OFFSET {{offset:UInt32}}
    """

    try:
        count_query = f"SELECT count(*) FROM authclaw.audit_events AS ae WHERE ae.tenant_id = {{tenant_id:UUID}} {action_filter}"
        count_result = ch.query(count_query, parameters=params)
        total_count = count_result.result_rows[0][0] if count_result.result_rows else 0

        result = ch.query(query, parameters=params)
    except Exception as exc:
        logger.error("ClickHouse query failed: %s", exc)
        raise HTTPException(status_code=503, detail="Audit storage temporarily unavailable")

    columns = result.column_names
    records = [dict(zip(columns, row)) for row in result.result_rows]

    # Normalise datetime objects to ISO strings for Pydantic
    for rec in records:
        if isinstance(rec.get("timestamp"), datetime):
            rec["timestamp"] = rec["timestamp"].isoformat()

    if integrity_check:
        records = _verify_chain(records)

    return AuditLogsResponse(
        source="clickhouse",
        total=total_count,
        records=records,
        integrity_checked=integrity_check,
    )


# ──────────────────────────────────────────────────────────────────────────────
# PostgreSQL fallback
# ──────────────────────────────────────────────────────────────────────────────


def _query_postgres(
    db: Session,
    tenant_id: str,
    limit: int,
    offset: int,
    action: Optional[str],
    integrity_check: bool,
) -> AuditLogsResponse:
    """Fallback: query PostgreSQL audit_log_metadata for Phase 6 compatibility."""
    try:
        q = db.query(AuditLogMetadata).filter(
            AuditLogMetadata.tenant_id == tenant_id
        )
        if action:
            q = q.filter(AuditLogMetadata.action == action)
        
        total_count = q.count()
        logs = q.order_by(AuditLogMetadata.tenant_sequence.desc()).offset(offset).limit(limit).all()

        records = [
            {
                "id": str(log.id),
                "record_id": str(log.record_id),
                "tenant_id": str(log.tenant_id),
                "tenant_sequence": log.tenant_sequence,
                "idempotency_key": log.idempotency_key,
                "chain_version": log.chain_version,
                "canonical_payload": log.canonical_payload,
                "timestamp": log.created_at.isoformat() if log.created_at else None,
                "actor_id": str(log.actor_id) if log.actor_id else "",
                "actor_type": getattr(log, "actor_type", None) or "gateway",
                "action": log.action,
                "policy_id": str(log.policy_id) if log.policy_id else "",
                "provider": log.provider or "",
                "model": log.model or "",
                "reason": log.reason or "",
                "prompt_count": log.prompt_count or 0,
                "request_size": log.request_size or 0,
                "response_status": log.response_status or 0,
                "duration_ms": log.duration_ms or 0,
                "frameworks_affected": log.frameworks_affected,
                "execution_trace": getattr(log, "execution_trace", "[]") or "[]",
                "created_at": log.created_at.isoformat() if log.created_at else None,
                "request_id": log.request_id or "",
                "prior_hash": log.prior_hash or "",
                "integrity_hash": log.integrity_hash or "",
            }
            for log in logs
        ]
        if integrity_check:
            records = _verify_chain(records)
        return AuditLogsResponse(
            source="postgres",
            total=total_count,
            records=records,
            integrity_checked=integrity_check,
        )
    except Exception as exc:
        logger.error("PostgreSQL audit query failed: %s", exc)
        raise HTTPException(status_code=500, detail="Audit log query failed")

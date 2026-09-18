"""
approval_store.py — In-memory approval store for the HITL workflow.

Stores rich approval metadata including status, timestamps, MFA tracking,
correlation IDs, and expiry windows. Expiration is checked lazily on every
read/list access so no background thread is needed.

Backward-compatible: `pending_approvals` and `approved_results` aliases are
kept so existing imports in main.py continue to work during the transition.
"""

import json
import uuid
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from sqlalchemy import text

from database import engine


# ── Internal store ──────────────────────────────────────────────────────────
# Single source of truth for ALL approvals regardless of status.
_approvals: Dict[str, dict] = {}

# Default expiry window (minutes). Overridden at runtime by policy.
DEFAULT_EXPIRY_MINUTES: int = 30


class PersistentApprovalRecord(dict):
    def __init__(self, *args, persist_enabled: bool = True, **kwargs):
        super().__init__(*args, **kwargs)
        self._persist_enabled = persist_enabled

    def __setitem__(self, key, value):
        if key == "requested_by" and key in self and self[key] != value:
            raise ValueError("Approval requester identity is immutable.")
        existed = key in self
        previous = self.get(key)
        super().__setitem__(key, value)
        if getattr(self, "_persist_enabled", False):
            try:
                _persist_record(self)
            except Exception:
                if existed:
                    super().__setitem__(key, previous)
                else:
                    super().__delitem__(key)
                raise

    def __delitem__(self, key):
        if key == "requested_by":
            raise ValueError("Approval requester identity is immutable.")
        super().__delitem__(key)

    def update(self, *args, **kwargs):
        changes = dict(*args, **kwargs)
        if "requested_by" in changes and self.get("requested_by") != changes["requested_by"]:
            raise ValueError("Approval requester identity is immutable.")
        for key, value in changes.items():
            self[key] = value

    def pop(self, key, *args):
        if key == "requested_by":
            raise ValueError("Approval requester identity is immutable.")
        return super().pop(key, *args)

    def popitem(self):
        if self and next(reversed(self)) == "requested_by":
            raise ValueError("Approval requester identity is immutable.")
        return super().popitem()

    def clear(self):
        if "requested_by" in self:
            raise ValueError("Approval requester identity is immutable.")
        super().clear()

    def __ior__(self, other):
        self.update(other)
        return self


# ── Helpers ──────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_optional_dt(value):
    """Bind UTC wall time to the existing TIMESTAMP WITHOUT TIME ZONE columns.

    Passing an aware datetime lets PostgreSQL shift it into the session timezone
    before dropping the offset, corrupting expiry and audit timestamps.
    """
    if not value:
        return None
    try:
        parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
        return parsed.astimezone(timezone.utc).replace(tzinfo=None) if parsed.tzinfo else parsed
    except Exception:
        return None


def _expiry_minutes() -> int:
    """Pull expiry_minutes from the live policy cache; fall back to default."""
    try:
        from policy import get_policy
        return get_policy().get("approval", {}).get("expiry_minutes", DEFAULT_EXPIRY_MINUTES)
    except Exception:
        return DEFAULT_EXPIRY_MINUTES


def _check_expiry(record: dict) -> dict:
    """
    If a 'pending' record has passed its expires_at, mutate status to 'expired'
    in-place and return the (now-mutated) record.
    """
    if record["status"] == "pending":
        raw_expires_at = record.get("expires_at")
        if not raw_expires_at:
            return record
        if isinstance(raw_expires_at, datetime):
            expires_at = raw_expires_at
        else:
            expires_at = datetime.fromisoformat(str(raw_expires_at))
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        if now >= expires_at:
            record, transitioned = expire_approval_atomic(record, expired_at=now)
            # Emit audit event lazily — import here to avoid circular deps
            if transitioned:
                try:
                    from startup.audit import log_approval_event
                    log_approval_event(
                        event="approval_expired",
                        approval_id=record["approval_id"],
                        request_id=record["request_id"],
                        correlation_id=record["correlation_id"],
                        extra={"expires_at": record["expires_at"]},
                    )
                except Exception:
                    pass
    return record


class ApprovalPersistenceError(RuntimeError):
    """Raised when required approval state or audit evidence is not durable."""


class ApprovalStateConflict(RuntimeError):
    """Raised when a single-use approval transition loses its state race."""

    def __init__(self, current_status: str):
        self.current_status = current_status
        super().__init__(f"Approval is not pending (status={current_status})")


def _persist_record(record: dict, connection=None) -> None:
    try:
        context = nullcontext(connection) if connection is not None else engine.begin()
        with context as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO gateway_approvals (
                        approval_id, request_id, correlation_id, tenant_id, status,
                        requested_by,
                        created_at, expires_at, approved_at, rejected_at, executed_at,
                        requested_action, query, risk_level, audit_id, reason, comments,
                        approved_by, rejected_by, executed_by, mfa_verified, last_action_at,
                        metadata, approval_mfa_verified, execution_mfa_verified,
                        approval_mfa_binding_hash, execution_mfa_binding_hash,
                        approval_mfa_counter, execution_mfa_counter,
                        execution_token_hash, execution_token_used_at, execution_expires_at
                    )
                    VALUES (
                        :approval_id, :request_id, :correlation_id, :tenant_id, :status,
                        :requested_by,
                        :created_at, :expires_at, :approved_at, :rejected_at, :executed_at,
                        :requested_action, :query, :risk_level, :audit_id, :reason, :comments,
                        :approved_by, :rejected_by, :executed_by, :mfa_verified, :last_action_at,
                        :metadata, :approval_mfa_verified, :execution_mfa_verified,
                        :approval_mfa_binding_hash, :execution_mfa_binding_hash,
                        :approval_mfa_counter, :execution_mfa_counter,
                        :execution_token_hash, :execution_token_used_at, :execution_expires_at
                    )
                    ON CONFLICT (approval_id) DO UPDATE SET
                        request_id = EXCLUDED.request_id,
                        correlation_id = EXCLUDED.correlation_id,
                        tenant_id = EXCLUDED.tenant_id,
                        status = EXCLUDED.status,
                        expires_at = EXCLUDED.expires_at,
                        approved_at = EXCLUDED.approved_at,
                        rejected_at = EXCLUDED.rejected_at,
                        executed_at = EXCLUDED.executed_at,
                        requested_action = EXCLUDED.requested_action,
                        query = EXCLUDED.query,
                        risk_level = EXCLUDED.risk_level,
                        audit_id = EXCLUDED.audit_id,
                        reason = EXCLUDED.reason,
                        comments = EXCLUDED.comments,
                        approved_by = EXCLUDED.approved_by,
                        rejected_by = EXCLUDED.rejected_by,
                        executed_by = EXCLUDED.executed_by,
                        mfa_verified = EXCLUDED.mfa_verified,
                        last_action_at = EXCLUDED.last_action_at,
                        metadata = EXCLUDED.metadata,
                        approval_mfa_verified = EXCLUDED.approval_mfa_verified,
                        execution_mfa_verified = EXCLUDED.execution_mfa_verified,
                        approval_mfa_binding_hash = EXCLUDED.approval_mfa_binding_hash,
                        execution_mfa_binding_hash = EXCLUDED.execution_mfa_binding_hash,
                        approval_mfa_counter = EXCLUDED.approval_mfa_counter,
                        execution_mfa_counter = EXCLUDED.execution_mfa_counter,
                        execution_token_hash = EXCLUDED.execution_token_hash,
                        execution_token_used_at = EXCLUDED.execution_token_used_at,
                        execution_expires_at = EXCLUDED.execution_expires_at
                    """
                ),
                {
                    "approval_id": record.get("approval_id"),
                    "request_id": record.get("request_id"),
                    "correlation_id": record.get("correlation_id"),
                    "tenant_id": record.get("tenant_id"),
                    "status": record.get("status"),
                    "requested_by": record.get("requested_by"),
                    "created_at": _parse_optional_dt(record.get("created_at")),
                    "expires_at": _parse_optional_dt(record.get("expires_at")),
                    "approved_at": _parse_optional_dt(record.get("approved_at")),
                    "rejected_at": _parse_optional_dt(record.get("rejected_at")),
                    "executed_at": _parse_optional_dt(record.get("executed_at")),
                    "requested_action": record.get("requested_action"),
                    "query": record.get("query"),
                    "risk_level": record.get("risk_level"),
                    "audit_id": record.get("audit_id"),
                    "reason": record.get("reason"),
                    "comments": json.dumps(record.get("comments", [])),
                    "approved_by": record.get("approved_by"),
                    "rejected_by": record.get("rejected_by"),
                    "executed_by": record.get("executed_by"),
                    "mfa_verified": bool(record.get("mfa_verified", False)),
                    "last_action_at": _parse_optional_dt(record.get("last_action_at")),
                    "metadata": json.dumps(record.get("metadata", {})),
                    "approval_mfa_verified": bool(record.get("approval_mfa_verified", record.get("mfa_verified", False))),
                    "execution_mfa_verified": bool(record.get("execution_mfa_verified", False)),
                    "approval_mfa_binding_hash": record.get("approval_mfa_binding_hash"),
                    "execution_mfa_binding_hash": record.get("execution_mfa_binding_hash"),
                    "approval_mfa_counter": record.get("approval_mfa_counter"),
                    "execution_mfa_counter": record.get("execution_mfa_counter"),
                    "execution_token_hash": record.get("execution_token_hash"),
                    "execution_token_used_at": _parse_optional_dt(record.get("execution_token_used_at")),
                    "execution_expires_at": _parse_optional_dt(record.get("execution_expires_at")),
                },
            )
    except ApprovalPersistenceError:
        raise
    except Exception as exc:
        raise ApprovalPersistenceError("Approval state persistence failed") from exc


def _row_to_record(row) -> PersistentApprovalRecord:
    mapping = dict(row._mapping)

    def as_iso(value):
        if value is None:
            return None
        return value.isoformat() if hasattr(value, "isoformat") else str(value)

    try:
        comments = json.loads(mapping.get("comments") or "[]")
    except Exception:
        comments = []

    return PersistentApprovalRecord(
        {
            "approval_id": mapping.get("approval_id"),
            "request_id": mapping.get("request_id"),
            "correlation_id": mapping.get("correlation_id"),
            "tenant_id": mapping.get("tenant_id"),
            "status": mapping.get("status"),
            "requested_by": mapping.get("requested_by"),
            "created_at": as_iso(mapping.get("created_at")),
            "expires_at": as_iso(mapping.get("expires_at")),
            "approved_at": as_iso(mapping.get("approved_at")),
            "rejected_at": as_iso(mapping.get("rejected_at")),
            "executed_at": as_iso(mapping.get("executed_at")),
            "requested_action": mapping.get("requested_action"),
            "query": mapping.get("query"),
            "risk_level": mapping.get("risk_level"),
            "audit_id": mapping.get("audit_id"),
            "reason": mapping.get("reason"),
            "comments": comments,
            "approved_by": mapping.get("approved_by"),
            "rejected_by": mapping.get("rejected_by"),
            "executed_by": mapping.get("executed_by"),
            "mfa_verified": bool(mapping.get("mfa_verified")),
            "approval_mfa_verified": bool(mapping.get("approval_mfa_verified", mapping.get("mfa_verified"))),
            "execution_mfa_verified": bool(mapping.get("execution_mfa_verified")),
            "approval_mfa_binding_hash": mapping.get("approval_mfa_binding_hash"),
            "execution_mfa_binding_hash": mapping.get("execution_mfa_binding_hash"),
            "approval_mfa_counter": mapping.get("approval_mfa_counter"),
            "execution_mfa_counter": mapping.get("execution_mfa_counter"),
            "execution_token_hash": mapping.get("execution_token_hash"),
            "execution_token_used_at": as_iso(mapping.get("execution_token_used_at")),
            "execution_expires_at": as_iso(mapping.get("execution_expires_at")),
            "last_action_at": as_iso(mapping.get("last_action_at")),
            "metadata": json.loads(mapping.get("metadata") or "{}"),
        }
    )


def _load_record(approval_id: str) -> Optional[PersistentApprovalRecord]:
    try:
        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT * FROM gateway_approvals WHERE approval_id = :approval_id"),
                {"approval_id": approval_id},
            ).fetchone()
        return _row_to_record(row) if row else None
    except Exception as exc:
        raise ApprovalPersistenceError("Approval state read failed") from exc


def _load_all_records(tenant_id: int = None) -> None:
    try:
        with engine.connect() as conn:
            if tenant_id is None:
                rows = conn.execute(text("SELECT * FROM gateway_approvals ORDER BY created_at DESC")).fetchall()
            else:
                rows = conn.execute(
                    text("SELECT * FROM gateway_approvals WHERE tenant_id = :tenant_id ORDER BY created_at DESC"),
                    {"tenant_id": tenant_id},
                ).fetchall()
        for row in rows:
            record = _row_to_record(row)
            _approvals[record["approval_id"]] = record
    except Exception:
        pass


# ── Public API ────────────────────────────────────────────────────────────────

class ApprovalCreationError(ValueError):
    """Raised when an approval cannot be bound to an authenticated request."""


def create_approval(
    query: str,
    risk_level: str,
    session_id: str = "",
    tenant_id: int = None,
    request_id: str = None,
    reason: str = None,
    metadata: dict = None,
    requested_by: str = None,
) -> dict:
    """
    Creates a new approval record, stores it, and returns it.
    Emits an approval_created audit event.
    """
    requester_id = str(requested_by or "").strip()
    request_context = str(request_id or "").strip()
    if not requester_id:
        raise ApprovalCreationError("Approval requester identity is required.")
    if tenant_id is None:
        raise ApprovalCreationError("Approval tenant context is required.")
    if not request_context:
        raise ApprovalCreationError("Approval request context is required.")

    approval_id = str(uuid.uuid4())
    request_id = request_context
    correlation_id = session_id or str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=_expiry_minutes())

    approval_metadata = dict(metadata or {})
    approval_metadata["requested_by"] = requester_id

    record = PersistentApprovalRecord({
        "approval_id":       approval_id,
        "request_id":        request_id,
        "correlation_id":    correlation_id,
        "tenant_id":         tenant_id,
        "status":            "pending",
        "requested_by":      requester_id,
        "created_at":        now.isoformat(),
        "expires_at":        expires_at.isoformat(),
        "approved_at":       None,
        "rejected_at":       None,
        "executed_at":       None,
        "requested_action":  query,
        "query":             query,
        "risk_level":        risk_level,
        "audit_id":          None,
        "reason":            reason or "high_risk",
        "comments":          [],
        "approved_by":       None,
        "rejected_by":       None,
        "executed_by":       None,
        "mfa_verified":      False,
        "approval_mfa_verified": False,
        "execution_mfa_verified": False,
        "approval_mfa_binding_hash": None,
        "execution_mfa_binding_hash": None,
        "approval_mfa_counter": None,
        "execution_mfa_counter": None,
        "execution_token_hash": None,
        "execution_token_used_at": None,
        "execution_expires_at": None,
        "last_action_at":    now.isoformat(),
        "metadata":          approval_metadata,
    }, persist_enabled=False)
    try:
        with engine.begin() as conn:
            _persist_record(record, connection=conn)
            append_approval_audit(
                record,
                action="created",
                actor=requester_id,
                comment=f"Approval created for reason: {record['reason']}",
                metadata={"risk_level": risk_level, "expires_at": expires_at.isoformat()},
                connection=conn,
            )
    except ApprovalPersistenceError:
        raise
    except Exception as exc:
        raise ApprovalPersistenceError("Approval creation persistence failed") from exc
    record._persist_enabled = True
    _approvals[approval_id] = record

    try:
        from startup.audit import log_approval_event
        log_approval_event(
            event="approval_created",
            approval_id=approval_id,
            request_id=request_id,
            correlation_id=correlation_id,
            extra={"risk_level": risk_level, "expires_at": expires_at.isoformat()},
        )
    except Exception:
        pass



    return record


def get_approval(approval_id: str, *, fresh: bool = False) -> Optional[dict]:
    """
    Returns the approval record (or None if not found).
    Lazily marks pending records as expired.
    """
    record = None if fresh else _approvals.get(approval_id)
    if record is None:
        record = _load_record(approval_id)
        if record is None:
            if fresh:
                _approvals.pop(approval_id, None)
            return None
        _approvals[approval_id] = record
    return _check_expiry(record)


def get_all_approvals(tenant_id: int = None) -> Dict[str, dict]:
    """
    Returns all approval records as a dict keyed by approval_id.
    Lazily marks any expired pending records.
    """
    _load_all_records(tenant_id=tenant_id)
    records = list(_approvals.values())
    if tenant_id is not None:
        records = [record for record in records if record.get("tenant_id") == tenant_id]
    for record in records:
        _check_expiry(record)
    if tenant_id is None:
        return _approvals
    return {record["approval_id"]: record for record in records}


def append_approval_audit(
    record: dict,
    action: str,
    actor: str = "system",
    comment: str = None,
    mfa_verified: bool = False,
    metadata: dict = None,
    connection=None,
) -> None:
    event = {
        "action": action,
        "actor": actor,
        "comment": comment,
        "mfa_verified": bool(mfa_verified),
        "reason": record.get("reason"),
        "created_at": _now_iso(),
        "metadata": metadata or {},
    }
    comments = list(record.get("comments") or [])
    if comment:
        comments.append(event)
    try:
        context = nullcontext(connection) if connection is not None else engine.begin()
        with context as conn:
            if comment:
                updated = conn.execute(
                    text(
                        """
                        UPDATE gateway_approvals
                        SET comments = :comments
                        WHERE approval_id = :approval_id AND tenant_id = :tenant_id
                        """
                    ),
                    {
                        "comments": json.dumps(comments),
                        "approval_id": record.get("approval_id"),
                        "tenant_id": record.get("tenant_id"),
                    },
                )
                if updated.rowcount != 1:
                    raise ApprovalPersistenceError("Approval audit target is not durable")
            conn.execute(
                text(
                    """
                    INSERT INTO approval_audit_events (
                        tenant_id, approval_id, request_id, action, actor,
                        comment, mfa_verified, reason, metadata, created_at
                    )
                    VALUES (
                        :tenant_id, :approval_id, :request_id, :action, :actor,
                        :comment, :mfa_verified, :reason, :metadata, :created_at
                    )
                    """
                ),
                {
                    "tenant_id": record.get("tenant_id"),
                    "approval_id": record.get("approval_id"),
                    "request_id": record.get("request_id"),
                    "action": action,
                    "actor": actor,
                    "comment": comment,
                    "mfa_verified": bool(mfa_verified),
                    "reason": record.get("reason"),
                    "metadata": json.dumps(metadata or {}),
                    "created_at": _parse_optional_dt(event["created_at"]),
                },
            )
    except ApprovalPersistenceError:
        raise
    except Exception as exc:
        raise ApprovalPersistenceError("Approval audit persistence failed") from exc
    if comment:
        dict.__setitem__(record, "comments", comments)


def expire_approval_atomic(
    record: dict,
    *,
    expired_at: datetime,
) -> tuple[PersistentApprovalRecord, bool]:
    """Expire one pending approval and write its canonical audit in one transaction."""
    approval_id = record.get("approval_id")
    tenant_id = record.get("tenant_id")
    transitioned = False
    try:
        with engine.begin() as conn:
            row = conn.execute(
                text(
                    """
                    UPDATE gateway_approvals
                    SET status = 'expired',
                        last_action_at = :expired_at
                    WHERE approval_id = :approval_id
                      AND tenant_id = :tenant_id
                      AND status = 'pending'
                      AND expires_at <= :expired_at
                    RETURNING *
                    """
                ),
                {
                    "approval_id": approval_id,
                    "tenant_id": tenant_id,
                    "expired_at": _parse_optional_dt(expired_at),
                },
            ).fetchone()
            if row is None:
                row = conn.execute(
                    text(
                        """
                        SELECT * FROM gateway_approvals
                        WHERE approval_id = :approval_id AND tenant_id = :tenant_id
                        """
                    ),
                    {"approval_id": approval_id, "tenant_id": tenant_id},
                ).fetchone()
                if row is None:
                    raise ApprovalStateConflict("missing")
            else:
                transitioned = True

            updated_record = _row_to_record(row)
            if transitioned:
                append_approval_audit(
                    updated_record,
                    action="expired",
                    actor="system",
                    comment="Approval expired before a human decision.",
                    metadata={"expires_at": updated_record.get("expires_at")},
                    connection=conn,
                )
    except (ApprovalPersistenceError, ApprovalStateConflict):
        raise
    except Exception as exc:
        raise ApprovalPersistenceError("Atomic approval expiry failed") from exc

    _approvals[approval_id] = updated_record
    return updated_record, transitioned


def expire_approved_execution_atomic(
    record: dict,
    *,
    expired_at: datetime,
) -> tuple[PersistentApprovalRecord, bool]:
    """Expire an approved execution window and its audit atomically."""
    approval_id = record.get("approval_id")
    tenant_id = record.get("tenant_id")
    transitioned = False
    try:
        with engine.begin() as conn:
            row = conn.execute(
                text(
                    """
                    UPDATE gateway_approvals
                    SET status = 'expired',
                        last_action_at = :expired_at
                    WHERE approval_id = :approval_id
                      AND tenant_id = :tenant_id
                      AND status = 'approved'
                      AND (
                          expires_at <= :expired_at
                          OR execution_expires_at IS NULL
                          OR execution_expires_at <= :expired_at
                      )
                    RETURNING *
                    """
                ),
                {
                    "approval_id": approval_id,
                    "tenant_id": tenant_id,
                    "expired_at": _parse_optional_dt(expired_at),
                },
            ).fetchone()
            if row is None:
                row = conn.execute(
                    text(
                        """
                        SELECT * FROM gateway_approvals
                        WHERE approval_id = :approval_id AND tenant_id = :tenant_id
                        """
                    ),
                    {"approval_id": approval_id, "tenant_id": tenant_id},
                ).fetchone()
                if row is None:
                    raise ApprovalStateConflict("missing")
            else:
                transitioned = True

            updated_record = _row_to_record(row)
            if transitioned:
                append_approval_audit(
                    updated_record,
                    action="expired",
                    actor="system",
                    comment="Approval execution window expired.",
                    metadata={
                        "expires_at": updated_record.get("expires_at"),
                        "execution_expires_at": updated_record.get("execution_expires_at"),
                    },
                    connection=conn,
                )
    except (ApprovalPersistenceError, ApprovalStateConflict):
        raise
    except Exception as exc:
        raise ApprovalPersistenceError("Atomic approval execution expiry failed") from exc

    _approvals[approval_id] = updated_record
    return updated_record, transitioned


def approve_approval_atomic(
    record: dict,
    *,
    approver: str,
    approved_at: datetime,
    mfa_verified: bool,
    mfa_binding_hash: str,
    mfa_counter: int,
    execution_expires_at: datetime,
    comment: str = None,
    audit_metadata: dict = None,
) -> PersistentApprovalRecord:
    """Commit the single-use pending-to-approved decision and audit atomically."""
    approval_id = record.get("approval_id")
    tenant_id = record.get("tenant_id")
    conflict_status = None
    updated_record = None
    try:
        with engine.begin() as conn:
            row = conn.execute(
                text(
                    """
                    UPDATE gateway_approvals
                    SET status = 'approved',
                        approved_at = :approved_at,
                        approved_by = :approved_by,
                        mfa_verified = :mfa_verified,
                        approval_mfa_verified = :mfa_verified,
                        approval_mfa_binding_hash = :binding_hash,
                        approval_mfa_counter = :counter,
                        execution_expires_at = :execution_expires_at,
                        last_action_at = :approved_at
                    WHERE approval_id = :approval_id
                      AND tenant_id = :tenant_id
                      AND status = 'pending'
                      AND expires_at > :approved_at
                    RETURNING *
                    """
                ),
                {
                    "approval_id": approval_id,
                    "tenant_id": tenant_id,
                    "approved_at": _parse_optional_dt(approved_at),
                    "approved_by": approver,
                    "mfa_verified": bool(mfa_verified),
                    "binding_hash": mfa_binding_hash,
                    "counter": mfa_counter,
                    "execution_expires_at": _parse_optional_dt(execution_expires_at),
                },
            ).fetchone()
            if row is None:
                expired_row = conn.execute(
                    text(
                        """
                        UPDATE gateway_approvals
                        SET status = 'expired',
                            last_action_at = :approved_at
                        WHERE approval_id = :approval_id AND tenant_id = :tenant_id
                          AND status = 'pending'
                          AND expires_at <= :approved_at
                        RETURNING *
                        """
                    ),
                    {
                        "approval_id": approval_id,
                        "tenant_id": tenant_id,
                        "approved_at": _parse_optional_dt(approved_at),
                    },
                ).fetchone()
                if expired_row is not None:
                    updated_record = _row_to_record(expired_row)
                    append_approval_audit(
                        updated_record,
                        action="expired",
                        actor="system",
                        comment="Approval expired before the approval decision completed.",
                        metadata={"expires_at": updated_record.get("expires_at")},
                        connection=conn,
                    )
                    conflict_status = "expired"
                else:
                    current_status = conn.execute(
                        text(
                            """
                            SELECT status FROM gateway_approvals
                            WHERE approval_id = :approval_id AND tenant_id = :tenant_id
                            """
                        ),
                        {"approval_id": approval_id, "tenant_id": tenant_id},
                    ).scalar()
                    conflict_status = str(current_status or "missing")
            else:
                updated_record = _row_to_record(row)
                append_approval_audit(
                    updated_record,
                    action="approved",
                    actor=approver,
                    comment=comment,
                    mfa_verified=mfa_verified,
                    metadata=audit_metadata,
                    connection=conn,
                )
    except (ApprovalPersistenceError, ApprovalStateConflict):
        raise
    except Exception as exc:
        raise ApprovalPersistenceError("Atomic approval transition failed") from exc

    if updated_record is not None:
        _approvals[approval_id] = updated_record
    if conflict_status is not None:
        raise ApprovalStateConflict(conflict_status)
    return updated_record


def reject_approval_atomic(
    record: dict,
    *,
    actor: str,
    rejected_at: datetime,
    comment: str = None,
    audit_metadata: dict = None,
) -> PersistentApprovalRecord:
    """Commit the single-use pending-to-rejected decision and audit atomically."""
    approval_id = record.get("approval_id")
    tenant_id = record.get("tenant_id")
    try:
        with engine.begin() as conn:
            row = conn.execute(
                text(
                    """
                    UPDATE gateway_approvals
                    SET status = 'rejected',
                        rejected_at = :rejected_at,
                        rejected_by = :rejected_by,
                        last_action_at = :rejected_at
                    WHERE approval_id = :approval_id
                      AND tenant_id = :tenant_id
                      AND status = 'pending'
                    RETURNING *
                    """
                ),
                {
                    "approval_id": approval_id,
                    "tenant_id": tenant_id,
                    "rejected_at": _parse_optional_dt(rejected_at),
                    "rejected_by": actor,
                },
            ).fetchone()
            if row is None:
                current_status = conn.execute(
                    text(
                        """
                        SELECT status FROM gateway_approvals
                        WHERE approval_id = :approval_id AND tenant_id = :tenant_id
                        """
                    ),
                    {"approval_id": approval_id, "tenant_id": tenant_id},
                ).scalar()
                raise ApprovalStateConflict(str(current_status or "missing"))

            updated_record = _row_to_record(row)
            append_approval_audit(
                updated_record,
                action="rejected",
                actor=actor,
                comment=comment,
                metadata=audit_metadata,
                connection=conn,
            )
    except (ApprovalPersistenceError, ApprovalStateConflict):
        raise
    except Exception as exc:
        raise ApprovalPersistenceError("Atomic rejection transition failed") from exc

    _approvals[approval_id] = updated_record
    return updated_record


def begin_approval_execution_atomic(
    record: dict,
    *,
    actor: str,
    transition_at: datetime,
    execution_token_hash: str,
    mfa_binding_hash: str,
    mfa_counter: int,
    comment: str = None,
    audit_metadata: dict = None,
) -> PersistentApprovalRecord:
    """Consume one approved execution and persist its audit in one transaction."""
    approval_id = record.get("approval_id")
    tenant_id = record.get("tenant_id")
    conflict_status = None
    updated_record = None
    try:
        with engine.begin() as conn:
            row = conn.execute(
                text(
                    """
                    UPDATE gateway_approvals
                    SET status = 'executing',
                        execution_token_hash = :token_hash,
                        execution_token_used_at = :transition_at,
                        execution_mfa_verified = TRUE,
                        execution_mfa_binding_hash = :binding_hash,
                        execution_mfa_counter = :counter,
                        executed_by = :actor,
                        last_action_at = :transition_at
                    WHERE approval_id = :approval_id
                      AND tenant_id = :tenant_id
                      AND status = 'approved'
                      AND approved_by = :actor
                      AND execution_token_used_at IS NULL
                      AND expires_at > :transition_at
                      AND execution_expires_at > :transition_at
                    RETURNING *
                    """
                ),
                {
                    "approval_id": approval_id,
                    "tenant_id": tenant_id,
                    "actor": actor,
                    "transition_at": _parse_optional_dt(transition_at),
                    "token_hash": execution_token_hash,
                    "binding_hash": mfa_binding_hash,
                    "counter": mfa_counter,
                },
            ).fetchone()
            if row is None:
                expired_row = conn.execute(
                    text(
                        """
                        UPDATE gateway_approvals
                        SET status = 'expired',
                            last_action_at = :transition_at
                        WHERE approval_id = :approval_id
                          AND tenant_id = :tenant_id
                          AND status = 'approved'
                          AND (
                              expires_at <= :transition_at
                              OR execution_expires_at IS NULL
                              OR execution_expires_at <= :transition_at
                          )
                        RETURNING *
                        """
                    ),
                    {
                        "approval_id": approval_id,
                        "tenant_id": tenant_id,
                        "transition_at": _parse_optional_dt(transition_at),
                    },
                ).fetchone()
                if expired_row is not None:
                    updated_record = _row_to_record(expired_row)
                    append_approval_audit(
                        updated_record,
                        action="expired",
                        actor="system",
                        comment="Approval execution window expired.",
                        metadata={
                            "expires_at": updated_record.get("expires_at"),
                            "execution_expires_at": updated_record.get("execution_expires_at"),
                        },
                        connection=conn,
                    )
                    conflict_status = "expired"
                else:
                    current_status = conn.execute(
                        text(
                            """
                            SELECT status FROM gateway_approvals
                            WHERE approval_id = :approval_id AND tenant_id = :tenant_id
                            """
                        ),
                        {"approval_id": approval_id, "tenant_id": tenant_id},
                    ).scalar()
                    conflict_status = str(current_status or "missing")
            else:
                updated_record = _row_to_record(row)
                append_approval_audit(
                    updated_record,
                    action="executing",
                    actor=actor,
                    comment=comment,
                    mfa_verified=True,
                    metadata=audit_metadata,
                    connection=conn,
                )
    except (ApprovalPersistenceError, ApprovalStateConflict):
        raise
    except Exception as exc:
        raise ApprovalPersistenceError("Atomic approval execution transition failed") from exc

    if updated_record is not None:
        _approvals[approval_id] = updated_record
    if conflict_status is not None:
        raise ApprovalStateConflict(conflict_status)
    return updated_record


def finish_approval_execution_atomic(
    record: dict,
    *,
    actor: str,
    final_status: str,
    transition_at: datetime,
    comment: str = None,
    mfa_verified: bool = False,
    audit_metadata: dict = None,
) -> PersistentApprovalRecord:
    """Finalize an executing approval and its canonical audit atomically."""
    if final_status not in {"executed", "execution_failed"}:
        raise ValueError("Unsupported approval execution terminal status")
    approval_id = record.get("approval_id")
    tenant_id = record.get("tenant_id")
    try:
        with engine.begin() as conn:
            row = conn.execute(
                text(
                    """
                    UPDATE gateway_approvals
                    SET status = CAST(:final_status AS VARCHAR),
                        executed_at = CASE
                            WHEN CAST(:final_status AS VARCHAR) = 'executed' THEN :transition_at
                            ELSE executed_at
                        END,
                        last_action_at = :transition_at
                    WHERE approval_id = :approval_id
                      AND tenant_id = :tenant_id
                      AND status = 'executing'
                      AND executed_by = :actor
                      AND execution_token_hash = :execution_token_hash
                    RETURNING *
                    """
                ),
                {
                    "approval_id": approval_id,
                    "tenant_id": tenant_id,
                    "actor": actor,
                    "final_status": final_status,
                    "transition_at": _parse_optional_dt(transition_at),
                    "execution_token_hash": record.get("execution_token_hash"),
                },
            ).fetchone()
            if row is None:
                current_status = conn.execute(
                    text(
                        """
                        SELECT status FROM gateway_approvals
                        WHERE approval_id = :approval_id AND tenant_id = :tenant_id
                        """
                    ),
                    {"approval_id": approval_id, "tenant_id": tenant_id},
                ).scalar()
                raise ApprovalStateConflict(str(current_status or "missing"))

            updated_record = _row_to_record(row)
            append_approval_audit(
                updated_record,
                action=final_status,
                actor=actor,
                comment=comment,
                mfa_verified=mfa_verified,
                metadata=audit_metadata,
                connection=conn,
            )
    except (ApprovalPersistenceError, ApprovalStateConflict):
        raise
    except Exception as exc:
        raise ApprovalPersistenceError("Atomic approval execution finalization failed") from exc

    _approvals[approval_id] = updated_record
    return updated_record


def get_approval_history(approval_id: str, tenant_id: int = None) -> List[dict]:
    try:
        with engine.connect() as conn:
            if tenant_id is None:
                rows = conn.execute(
                    text("SELECT * FROM approval_audit_events WHERE approval_id = :approval_id ORDER BY created_at ASC, id ASC"),
                    {"approval_id": approval_id},
                ).fetchall()
            else:
                rows = conn.execute(
                    text(
                        """
                        SELECT * FROM approval_audit_events
                        WHERE approval_id = :approval_id AND tenant_id = :tenant_id
                        ORDER BY created_at ASC, id ASC
                        """
                    ),
                    {"approval_id": approval_id, "tenant_id": tenant_id},
                ).fetchall()
        history = []
        for row in rows:
            mapping = dict(row._mapping)
            created_at = mapping.get("created_at")
            try:
                metadata = json.loads(mapping.get("metadata") or "{}")
            except Exception:
                metadata = {}
            history.append({
                "action": mapping.get("action"),
                "actor": mapping.get("actor"),
                "comment": mapping.get("comment"),
                "mfa_verified": bool(mapping.get("mfa_verified")),
                "reason": mapping.get("reason"),
                "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at),
                "metadata": metadata,
            })
        return history
    except Exception:
        return []


def remaining_seconds(record: dict) -> int:
    """Returns seconds left before expiry (0 if already expired/approved/rejected)."""
    if record["status"] != "pending":
        return 0
    expires_at = datetime.fromisoformat(record["expires_at"])
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    delta = (expires_at - datetime.now(timezone.utc)).total_seconds()
    return max(0, int(delta))


# ── Backward-compatible aliases ───────────────────────────────────────────────
# These provide dict-like read access to the underlying store so that any
# existing code using `pending_approvals[id]` or `approved_results[id]` keeps
# working without modification.

class _PendingView:
    """Read-only dict-like view of pending approvals (lazy expiry applied)."""

    def __contains__(self, approval_id):
        record = get_approval(approval_id)
        return record is not None and record["status"] == "pending"

    def __getitem__(self, approval_id):
        record = get_approval(approval_id)
        if record is None or record["status"] != "pending":
            raise KeyError(approval_id)
        return record

    def __iter__(self):
        return (
            aid for aid, r in get_all_approvals().items()
            if r["status"] == "pending"
        )

    def items(self):
        return [
            (aid, r) for aid, r in get_all_approvals().items()
            if r["status"] == "pending"
        ]


class _ApprovedView:
    """Read-only dict-like view of approved approvals."""

    def __contains__(self, approval_id):
        record = get_approval(approval_id)
        return record is not None and record["status"] == "approved"

    def __getitem__(self, approval_id):
        record = get_approval(approval_id)
        if record is None or record["status"] != "approved":
            raise KeyError(approval_id)
        return record

    def __iter__(self):
        return (
            aid for aid, r in get_all_approvals().items()
            if r["status"] == "approved"
        )

    def items(self):
        return [
            (aid, r) for aid, r in get_all_approvals().items()
            if r["status"] == "approved"
        ]


pending_approvals = _PendingView()
approved_results  = _ApprovedView()

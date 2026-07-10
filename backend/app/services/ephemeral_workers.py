"""Ephemeral worker token and connector-boundary service."""

from __future__ import annotations

import hashlib
import json
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import AuditLogMetadata, EphemeralWorkerRun, EphemeralWorkerToken
from app.services import event_backbone
from app.services.audit_store import GENESIS_HASH, compute_integrity_hash

DEFAULT_TTL_SECONDS = 900
MAX_TTL_SECONDS = 1800
TOKEN_PREFIX = "ewt"

CONNECTOR_REGISTRY: dict[str, dict[str, Any]] = {
    "aws": {
        "display_name": "AWS",
        "status": "active",
        "credential_source": "environment",
        "scopes": [
            "aws:s3:read",
            "aws:bedrock:read",
            "aws:iam:read",
            "aws:remediation:write",
            "aws:destructive:explicit",
        ],
        "actions": {
            "s3.sync": {"scope": "aws:s3:read", "destructive": False},
            "s3.head_object": {"scope": "aws:s3:read", "destructive": False},
            "bedrock.usage.read": {"scope": "aws:bedrock:read", "destructive": False},
            "iam.scan": {"scope": "aws:iam:read", "destructive": False},
            "s3.put_public_access_block": {"scope": "aws:remediation:write", "destructive": False},
            "s3.delete_object": {"scope": "aws:destructive:explicit", "destructive": True},
            "iam.detach_policy": {"scope": "aws:destructive:explicit", "destructive": True},
        },
    },
    "github": {
        "display_name": "GitHub",
        "status": "foundation",
        "credential_source": "secret-provider",
        "scopes": [
            "github:repo:read",
            "github:security:read",
            "github:pull_request:write",
            "github:destructive:explicit",
        ],
        "actions": {
            "repo.scan": {"scope": "github:repo:read", "destructive": False},
            "code_scanning.alerts.read": {"scope": "github:security:read", "destructive": False},
            "pull_request.open": {"scope": "github:pull_request:write", "destructive": False},
            "branch.delete": {"scope": "github:destructive:explicit", "destructive": True},
        },
    },
    "gcp": {
        "display_name": "Google Cloud",
        "status": "foundation",
        "credential_source": "workload-identity",
        "scopes": [
            "gcp:asset:read",
            "gcp:iam:read",
            "gcp:remediation:write",
            "gcp:destructive:explicit",
        ],
        "actions": {
            "asset.inventory": {"scope": "gcp:asset:read", "destructive": False},
            "iam.policy.read": {"scope": "gcp:iam:read", "destructive": False},
            "storage.bucket.patch": {"scope": "gcp:remediation:write", "destructive": False},
            "storage.object.delete": {"scope": "gcp:destructive:explicit", "destructive": True},
        },
    },
}


@dataclass(frozen=True)
class IssuedWorkerToken:
    token: EphemeralWorkerToken
    raw_token: str


@dataclass(frozen=True)
class WorkerAuthorizationResult:
    allowed: bool
    status: str
    reason: str
    token: EphemeralWorkerToken | None
    run: EphemeralWorkerRun


def now_utc() -> datetime:
    return datetime.now(tz=timezone.utc)


def ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def hash_worker_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def generate_worker_secret() -> tuple[str, str]:
    prefix = secrets.token_urlsafe(6).replace("-", "").replace("_", "")[:8]
    secret = secrets.token_urlsafe(32)
    return prefix, f"{TOKEN_PREFIX}_{prefix}_{secret}"


def connector_catalog() -> list[dict[str, Any]]:
    return [
        {
            "connector": name,
            "display_name": config["display_name"],
            "status": config["status"],
            "credential_source": config["credential_source"],
            "scopes": list(config["scopes"]),
            "actions": [
                {
                    "name": action,
                    "scope": rule["scope"],
                    "destructive": bool(rule["destructive"]),
                }
                for action, rule in sorted(config["actions"].items())
            ],
        }
        for name, config in sorted(CONNECTOR_REGISTRY.items())
    ]


def normalize_connector(connector: str) -> str:
    normalized = connector.strip().lower()
    if normalized not in CONNECTOR_REGISTRY:
        raise ValueError(f"Unsupported worker connector: {connector}")
    return normalized


def validate_action(connector: str, action: str) -> dict[str, Any]:
    connector = normalize_connector(connector)
    actions = CONNECTOR_REGISTRY[connector]["actions"]
    if action not in actions:
        raise ValueError(f"Unsupported {connector} worker action: {action}")
    return actions[action]


def validate_scopes(connector: str, scopes: list[str]) -> list[str]:
    connector = normalize_connector(connector)
    allowed = set(CONNECTOR_REGISTRY[connector]["scopes"])
    unique = sorted({scope.strip() for scope in scopes if scope.strip()})
    unknown = sorted(set(unique) - allowed)
    if unknown:
        raise ValueError(f"Unsupported {connector} worker scopes: {', '.join(unknown)}")
    if not unique:
        raise ValueError("At least one worker scope is required")
    return unique


def build_permission_boundary(
    connector: str,
    scopes: list[str],
    *,
    allow_destructive: bool = False,
    destructive_actions: list[str] | None = None,
) -> dict[str, Any]:
    connector = normalize_connector(connector)
    scoped = set(validate_scopes(connector, scopes))
    allowed_actions: list[str] = []
    destructive_allowlist = set(destructive_actions or [])

    for action, rule in CONNECTOR_REGISTRY[connector]["actions"].items():
        if rule["scope"] not in scoped:
            continue
        if rule["destructive"]:
            if allow_destructive and action in destructive_allowlist:
                allowed_actions.append(action)
            continue
        allowed_actions.append(action)

    return {
        "connector": connector,
        "allowed_actions": sorted(allowed_actions),
        "allow_destructive": allow_destructive,
        "destructive_actions": sorted(destructive_allowlist if allow_destructive else []),
        "deny_by_default": True,
    }


def action_allowed(token: EphemeralWorkerToken, action: str, required_scope: str, destructive: bool) -> tuple[bool, str]:
    if required_scope not in set(token.scopes or []):
        return False, f"required scope {required_scope} is not present on worker token"

    boundary = token.permission_boundary or {}
    allowed_actions = set(boundary.get("allowed_actions") or [])
    if action not in allowed_actions:
        return False, f"action {action} is outside the worker permission boundary"

    if destructive and not boundary.get("allow_destructive"):
        return False, "destructive action denied by default boundary"
    if destructive and action not in set(boundary.get("destructive_actions") or []):
        return False, f"destructive action {action} is not explicitly allowlisted"

    return True, "worker token authorized"


def emit_worker_audit_event(
    db: Session,
    *,
    tenant_id: Any,
    action: str,
    reason: str,
    request_id: str = "",
    actor_id: Any | None = None,
    connector: str = "",
    token_id: Any | None = None,
    workflow_id: str | None = None,
    trace: list[str] | None = None,
    response_status: int = 0,
) -> AuditLogMetadata:
    tenant_id_str = str(tenant_id)
    trace_items = [
        f"worker_action={action}",
        f"connector={connector or ''}",
    ]
    if token_id:
        trace_items.append(f"worker_token_id={token_id}")
    if workflow_id:
        trace_items.append(f"workflow_id={workflow_id}")
    if trace:
        trace_items.extend(trace)

    last = (
        db.query(AuditLogMetadata)
        .filter(AuditLogMetadata.tenant_id == tenant_id)
        .order_by(AuditLogMetadata.created_at.desc(), AuditLogMetadata.record_id.desc())
        .first()
    )
    prior_hash = last.integrity_hash if last and last.integrity_hash else GENESIS_HASH
    created_at = now_utc()
    record_id = uuid.uuid4()
    log = AuditLogMetadata(
        tenant_id=tenant_id,
        record_id=record_id,
        actor_id=actor_id,
        actor_type="ephemeral_worker",
        action=f"worker:{action}",
        request_id=request_id or "",
        provider="ephemeral-worker",
        model=connector or "",
        reason=reason,
        prompt_count=0,
        request_size=0,
        response_status=response_status,
        duration_ms=0,
        frameworks_affected=[],
        execution_trace=json.dumps(trace_items),
        prior_hash=prior_hash,
        created_at=created_at,
    )
    record = {
        "record_id": str(record_id),
        "tenant_id": tenant_id_str,
        "timestamp": created_at,
        "actor_id": str(actor_id) if actor_id else "",
        "actor_type": "ephemeral_worker",
        "action": f"worker:{action}",
        "policy_id": "",
        "provider": "ephemeral-worker",
        "model": connector or "",
        "reason": reason,
        "prompt_count": 0,
        "request_size": 0,
        "response_status": response_status,
        "duration_ms": 0,
        "frameworks_affected": [],
        "execution_trace": log.execution_trace,
        "request_id": request_id or "",
    }
    log.integrity_hash = compute_integrity_hash(record, prior_hash)
    db.add(log)
    event_backbone.increment_metric(f"ephemeral_worker_{action.replace('.', '_')}_events_total")
    return log


def issue_worker_token(
    db: Session,
    *,
    tenant_id: Any,
    connector: str,
    action_id: str,
    purpose: str,
    scopes: list[str],
    workflow_id: str | None = None,
    issued_by: Any | None = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    allow_destructive: bool = False,
    destructive_actions: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
    request_id: str = "",
    commit: bool = True,
) -> IssuedWorkerToken:
    connector = normalize_connector(connector)
    ttl = max(60, min(int(ttl_seconds), MAX_TTL_SECONDS))
    scopes = validate_scopes(connector, scopes)
    boundary = build_permission_boundary(
        connector,
        scopes,
        allow_destructive=allow_destructive,
        destructive_actions=destructive_actions,
    )
    prefix, raw_token = generate_worker_secret()
    token = EphemeralWorkerToken(
        tenant_id=tenant_id,
        workflow_id=workflow_id,
        action_id=action_id,
        connector=connector,
        purpose=purpose,
        scopes=scopes,
        permission_boundary=boundary,
        token_hash=hash_worker_token(raw_token),
        token_prefix=prefix,
        status="active",
        issued_by=issued_by,
        expires_at=now_utc() + timedelta(seconds=ttl),
        metadata_json=metadata or {},
    )
    db.add(token)
    db.flush()
    emit_worker_audit_event(
        db,
        tenant_id=tenant_id,
        action="token.grant",
        reason=f"Issued {connector} worker token for {purpose}",
        request_id=request_id,
        actor_id=issued_by,
        connector=connector,
        token_id=token.id,
        workflow_id=workflow_id,
        trace=[f"scopes={','.join(scopes)}", f"ttl_seconds={ttl}", f"action_id={action_id}"],
    )
    if commit:
        db.commit()
    return IssuedWorkerToken(token=token, raw_token=raw_token)


def _record_run(
    db: Session,
    *,
    tenant_id: Any,
    token: EphemeralWorkerToken | None,
    connector: str,
    action: str,
    required_scope: str,
    destructive: bool,
    status: str,
    reason: str,
    metadata: dict[str, Any] | None = None,
) -> EphemeralWorkerRun:
    run = EphemeralWorkerRun(
        tenant_id=tenant_id,
        worker_token_id=token.id if token else None,
        connector=connector,
        action=action,
        required_scope=required_scope,
        destructive=destructive,
        status=status,
        reason=reason,
        completed_at=now_utc(),
        metadata_json=metadata or {},
    )
    db.add(run)
    return run


def authorize_worker_action(
    db: Session,
    *,
    tenant_id: Any,
    raw_token: str,
    connector: str,
    action: str,
    required_scope: str | None = None,
    destructive: bool | None = None,
    request_id: str = "",
    metadata: dict[str, Any] | None = None,
    commit: bool = True,
) -> WorkerAuthorizationResult:
    connector = normalize_connector(connector)
    action_rule = validate_action(connector, action)
    required_scope = required_scope or action_rule["scope"]
    destructive = action_rule["destructive"] if destructive is None else destructive
    token = (
        db.query(EphemeralWorkerToken)
        .filter(
            EphemeralWorkerToken.tenant_id == tenant_id,
            EphemeralWorkerToken.token_hash == hash_worker_token(raw_token),
            EphemeralWorkerToken.connector == connector,
        )
        .first()
    )

    if not token:
        run = _record_run(
            db,
            tenant_id=tenant_id,
            token=None,
            connector=connector,
            action=action,
            required_scope=required_scope,
            destructive=bool(destructive),
            status="denied",
            reason="worker token not found",
            metadata=metadata,
        )
        emit_worker_audit_event(
            db,
            tenant_id=tenant_id,
            action="token.denied",
            reason="Worker token not found",
            request_id=request_id,
            connector=connector,
            response_status=403,
            trace=[f"attempted_action={action}", f"required_scope={required_scope}"],
        )
        if commit:
            db.commit()
        return WorkerAuthorizationResult(False, "denied", "worker token not found", None, run)

    now = now_utc()
    if token.status != "active":
        reason = f"worker token is {token.status}"
        run = _record_run(
            db,
            tenant_id=tenant_id,
            token=token,
            connector=connector,
            action=action,
            required_scope=required_scope,
            destructive=bool(destructive),
            status="denied",
            reason=reason,
            metadata=metadata,
        )
        emit_worker_audit_event(
            db,
            tenant_id=tenant_id,
            action="token.denied",
            reason=reason,
            request_id=request_id,
            connector=connector,
            token_id=token.id,
            workflow_id=token.workflow_id,
            response_status=403,
            trace=[f"attempted_action={action}", f"required_scope={required_scope}"],
        )
        if commit:
            db.commit()
        return WorkerAuthorizationResult(False, "denied", reason, token, run)

    if ensure_aware(token.expires_at) <= now:
        token.status = "expired"
        reason = "worker token expired"
        run = _record_run(
            db,
            tenant_id=tenant_id,
            token=token,
            connector=connector,
            action=action,
            required_scope=required_scope,
            destructive=bool(destructive),
            status="expired",
            reason=reason,
            metadata=metadata,
        )
        emit_worker_audit_event(
            db,
            tenant_id=tenant_id,
            action="token.expired",
            reason=reason,
            request_id=request_id,
            connector=connector,
            token_id=token.id,
            workflow_id=token.workflow_id,
            response_status=403,
            trace=[f"attempted_action={action}", f"required_scope={required_scope}"],
        )
        if commit:
            db.commit()
        return WorkerAuthorizationResult(False, "expired", reason, token, run)

    allowed, reason = action_allowed(token, action, required_scope, bool(destructive))
    if not allowed:
        run = _record_run(
            db,
            tenant_id=tenant_id,
            token=token,
            connector=connector,
            action=action,
            required_scope=required_scope,
            destructive=bool(destructive),
            status="denied",
            reason=reason,
            metadata=metadata,
        )
        emit_worker_audit_event(
            db,
            tenant_id=tenant_id,
            action="token.denied",
            reason=reason,
            request_id=request_id,
            connector=connector,
            token_id=token.id,
            workflow_id=token.workflow_id,
            response_status=403,
            trace=[f"attempted_action={action}", f"required_scope={required_scope}"],
        )
        if commit:
            db.commit()
        return WorkerAuthorizationResult(False, "denied", reason, token, run)

    token.last_used_at = now
    token.last_used_action = action
    token.use_count = (token.use_count or 0) + 1
    run = _record_run(
        db,
        tenant_id=tenant_id,
        token=token,
        connector=connector,
        action=action,
        required_scope=required_scope,
        destructive=bool(destructive),
        status="allowed",
        reason=reason,
        metadata=metadata,
    )
    emit_worker_audit_event(
        db,
        tenant_id=tenant_id,
        action="token.use",
        reason=reason,
        request_id=request_id,
        connector=connector,
        token_id=token.id,
        workflow_id=token.workflow_id,
        trace=[f"attempted_action={action}", f"required_scope={required_scope}", f"destructive={bool(destructive)}"],
    )
    if commit:
        db.commit()
    return WorkerAuthorizationResult(True, "allowed", reason, token, run)


def revoke_worker_token(
    db: Session,
    *,
    tenant_id: Any,
    token_id: Any,
    actor_id: Any | None = None,
    request_id: str = "",
) -> EphemeralWorkerToken | None:
    token = (
        db.query(EphemeralWorkerToken)
        .filter(EphemeralWorkerToken.tenant_id == tenant_id, EphemeralWorkerToken.id == token_id)
        .first()
    )
    if not token:
        return None
    if token.status == "active":
        token.status = "revoked"
        token.revoked_at = now_utc()
        emit_worker_audit_event(
            db,
            tenant_id=tenant_id,
            action="token.revoke",
            reason="Worker token revoked",
            request_id=request_id,
            actor_id=actor_id,
            connector=token.connector,
            token_id=token.id,
            workflow_id=token.workflow_id,
        )
        db.commit()
    return token


def expire_stale_worker_tokens(db: Session, *, tenant_id: Any | None = None, limit: int = 500) -> int:
    query = db.query(EphemeralWorkerToken).filter(
        EphemeralWorkerToken.status == "active",
        EphemeralWorkerToken.expires_at <= now_utc(),
    )
    if tenant_id:
        query = query.filter(EphemeralWorkerToken.tenant_id == tenant_id)
    tokens = query.limit(limit).all()
    for token in tokens:
        token.status = "expired"
        emit_worker_audit_event(
            db,
            tenant_id=token.tenant_id,
            action="token.expired",
            reason="Worker token expired by sweeper",
            connector=token.connector,
            token_id=token.id,
            workflow_id=token.workflow_id,
        )
    if tokens:
        db.commit()
    return len(tokens)

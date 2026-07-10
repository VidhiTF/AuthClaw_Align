"""Ephemeral worker token APIs."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.auth import get_tenant_db, require_roles, require_scopes
from app.db.models import EphemeralWorkerRun, EphemeralWorkerToken
from app.services import ephemeral_workers

router = APIRouter()


class WorkerTokenIssueRequest(BaseModel):
    connector: str
    action_id: str = Field(..., min_length=3, max_length=255)
    purpose: str = Field("scan", pattern="^(scan|remediation|audit|test)$")
    scopes: list[str] = Field(default_factory=list)
    workflow_id: str | None = None
    ttl_seconds: int = Field(default=ephemeral_workers.DEFAULT_TTL_SECONDS, ge=60, le=ephemeral_workers.MAX_TTL_SECONDS)
    allow_destructive: bool = False
    destructive_actions: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class WorkerAuthorizeRequest(BaseModel):
    token: str
    connector: str
    action: str
    required_scope: str | None = None
    destructive: bool | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class WorkerTokenResponse(BaseModel):
    id: UUID
    connector: str
    purpose: str
    action_id: str
    workflow_id: str | None
    scopes: list[str]
    permission_boundary: dict[str, Any]
    token_prefix: str
    status: str
    issued_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    last_used_at: datetime | None
    last_used_action: str | None
    use_count: int
    metadata: dict[str, Any]


class WorkerTokenCreateResponse(BaseModel):
    token: str
    token_record: WorkerTokenResponse


class WorkerAuthorizeResponse(BaseModel):
    allowed: bool
    status: str
    reason: str
    run_id: UUID
    token_id: UUID | None


class WorkerRunResponse(BaseModel):
    id: UUID
    worker_token_id: UUID | None
    connector: str
    action: str
    required_scope: str
    destructive: bool
    status: str
    reason: str
    started_at: datetime
    completed_at: datetime | None
    metadata: dict[str, Any]


def _token_response(token: EphemeralWorkerToken) -> WorkerTokenResponse:
    return WorkerTokenResponse(
        id=token.id,
        connector=token.connector,
        purpose=token.purpose,
        action_id=token.action_id,
        workflow_id=token.workflow_id,
        scopes=token.scopes or [],
        permission_boundary=token.permission_boundary or {},
        token_prefix=token.token_prefix,
        status=token.status,
        issued_at=token.issued_at,
        expires_at=token.expires_at,
        revoked_at=token.revoked_at,
        last_used_at=token.last_used_at,
        last_used_action=token.last_used_action,
        use_count=token.use_count or 0,
        metadata=token.metadata_json or {},
    )


def _run_response(run: EphemeralWorkerRun) -> WorkerRunResponse:
    return WorkerRunResponse(
        id=run.id,
        worker_token_id=run.worker_token_id,
        connector=run.connector,
        action=run.action,
        required_scope=run.required_scope,
        destructive=run.destructive,
        status=run.status,
        reason=run.reason,
        started_at=run.started_at,
        completed_at=run.completed_at,
        metadata=run.metadata_json or {},
    )


@router.get("/connectors", dependencies=[require_scopes(["read"])])
def list_worker_connectors() -> dict[str, Any]:
    return {"connectors": ephemeral_workers.connector_catalog()}


@router.get("/tokens", response_model=list[WorkerTokenResponse], dependencies=[require_scopes(["read"])])
def list_worker_tokens(
    request: Request,
    status_filter: str | None = None,
    connector: str | None = None,
    db: Session = Depends(get_tenant_db),
) -> list[WorkerTokenResponse]:
    query = db.query(EphemeralWorkerToken).filter(EphemeralWorkerToken.tenant_id == request.state.tenant_id)
    if status_filter:
        query = query.filter(EphemeralWorkerToken.status == status_filter)
    if connector:
        query = query.filter(EphemeralWorkerToken.connector == connector.lower())
    tokens = query.order_by(EphemeralWorkerToken.issued_at.desc()).limit(100).all()
    return [_token_response(token) for token in tokens]


@router.post(
    "/tokens",
    response_model=WorkerTokenCreateResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[require_roles(["owner", "admin"]), require_scopes(["write"])],
)
def create_worker_token(
    payload: WorkerTokenIssueRequest,
    request: Request,
    db: Session = Depends(get_tenant_db),
) -> WorkerTokenCreateResponse:
    try:
        issued = ephemeral_workers.issue_worker_token(
            db,
            tenant_id=request.state.tenant_id,
            connector=payload.connector,
            action_id=payload.action_id,
            purpose=payload.purpose,
            scopes=payload.scopes,
            workflow_id=payload.workflow_id,
            issued_by=getattr(request.state, "user_id", None),
            ttl_seconds=payload.ttl_seconds,
            allow_destructive=payload.allow_destructive,
            destructive_actions=payload.destructive_actions,
            metadata=payload.metadata,
            request_id=request.headers.get("x-request-id", ""),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return WorkerTokenCreateResponse(token=issued.raw_token, token_record=_token_response(issued.token))


@router.post(
    "/tokens/{token_id}/revoke",
    response_model=WorkerTokenResponse,
    dependencies=[require_roles(["owner", "admin"]), require_scopes(["write"])],
)
def revoke_worker_token(
    token_id: UUID,
    request: Request,
    db: Session = Depends(get_tenant_db),
) -> WorkerTokenResponse:
    token = ephemeral_workers.revoke_worker_token(
        db,
        tenant_id=request.state.tenant_id,
        token_id=token_id,
        actor_id=getattr(request.state, "user_id", None),
        request_id=request.headers.get("x-request-id", ""),
    )
    if not token:
        raise HTTPException(status_code=404, detail="Worker token not found")
    return _token_response(token)


@router.post("/authorize", response_model=WorkerAuthorizeResponse, dependencies=[require_scopes(["write"])])
def authorize_worker_action(
    payload: WorkerAuthorizeRequest,
    request: Request,
    db: Session = Depends(get_tenant_db),
) -> WorkerAuthorizeResponse:
    try:
        result = ephemeral_workers.authorize_worker_action(
            db,
            tenant_id=request.state.tenant_id,
            raw_token=payload.token,
            connector=payload.connector,
            action=payload.action,
            required_scope=payload.required_scope,
            destructive=payload.destructive,
            request_id=request.headers.get("x-request-id", ""),
            metadata=payload.metadata,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not result.allowed:
        raise HTTPException(
            status_code=403,
            detail={
                "allowed": result.allowed,
                "status": result.status,
                "reason": result.reason,
                "run_id": str(result.run.id),
                "token_id": str(result.token.id) if result.token else None,
            },
        )
    return WorkerAuthorizeResponse(
        allowed=True,
        status=result.status,
        reason=result.reason,
        run_id=result.run.id,
        token_id=result.token.id if result.token else None,
    )


@router.get("/runs", response_model=list[WorkerRunResponse], dependencies=[require_scopes(["read"])])
def list_worker_runs(
    request: Request,
    token_id: UUID | None = None,
    db: Session = Depends(get_tenant_db),
) -> list[WorkerRunResponse]:
    query = db.query(EphemeralWorkerRun).filter(EphemeralWorkerRun.tenant_id == request.state.tenant_id)
    if token_id:
        query = query.filter(EphemeralWorkerRun.worker_token_id == token_id)
    runs = query.order_by(EphemeralWorkerRun.started_at.desc()).limit(100).all()
    return [_run_response(run) for run in runs]


@router.post("/tokens/expire-stale", dependencies=[require_roles(["owner", "admin"]), require_scopes(["write"])])
def expire_stale_worker_tokens(
    request: Request,
    db: Session = Depends(get_tenant_db),
) -> dict[str, int]:
    expired = ephemeral_workers.expire_stale_worker_tokens(db, tenant_id=request.state.tenant_id)
    return {"expired": expired}

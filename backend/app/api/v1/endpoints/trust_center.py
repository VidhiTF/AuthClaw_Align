"""Auditor Trust Center endpoints."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.auth import get_tenant_db, require_roles, require_scopes
from app.db.dependencies import get_db
from app.db.models import Tenant, TrustCenterShare
from app.services.email_service import EmailDeliveryError
from app.services import trust_center
from app.services.notifications import create_notification

router = APIRouter()


class TrustCenterShareCreate(BaseModel):
    label: str = Field(default="Auditor Trust Center", min_length=3, max_length=255)
    auditor_email: EmailStr
    frameworks: list[str] = Field(default_factory=lambda: list(trust_center.DEFAULT_FRAMEWORKS))
    expires_in_days: int = Field(default=30, ge=1, le=trust_center.MAX_SHARE_TTL_DAYS)


class TrustCenterShareResponse(BaseModel):
    id: UUID
    label: str
    auditor_email: str
    frameworks: list[str]
    permissions: list[str]
    status: str
    token_prefix: str
    expires_at: Any
    created_at: Any
    revoked_at: Any | None
    last_accessed_at: Any | None
    access_count: int


class TrustCenterShareCreateResponse(BaseModel):
    share: TrustCenterShareResponse
    token: str
    url: str


class TrustCenterVerifyRequest(BaseModel):
    artifact: dict[str, Any]


class TrustCenterAccessVerifyRequest(BaseModel):
    otp: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


def _share_response(share: TrustCenterShare) -> TrustCenterShareResponse:
    return TrustCenterShareResponse(
        id=share.id,
        label=share.label,
        auditor_email=share.auditor_email or "",
        frameworks=share.frameworks or [],
        permissions=share.permissions or [],
        status=share.status,
        token_prefix=share.token_prefix,
        expires_at=share.expires_at,
        created_at=share.created_at,
        revoked_at=share.revoked_at,
        last_accessed_at=share.last_accessed_at,
        access_count=share.access_count or 0,
    )


def _public_share_or_404(db: Session, token: str) -> TrustCenterShare:
    share, state = trust_center.resolve_share_token(db, token)
    if not share:
        raise HTTPException(status_code=404, detail="Trust Center share not found")
    if state != "active":
        raise HTTPException(status_code=403, detail=f"Trust Center share is {state}")
    return share


def _clear_public_rls_context(db: Session) -> None:
    db.execute(text("SELECT set_config('app.current_tenant_id', '', false)"))
    db.execute(text("SELECT set_config('app.trust_center_token_hash', '', false)"))


def _require_auditor_access(request: Request, share: TrustCenterShare, raw_token: str) -> None:
    try:
        trust_center.verify_auditor_access(
            share,
            raw_token,
            request.headers.get("x-trust-center-access", ""),
        )
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


@router.get("/shares", response_model=list[TrustCenterShareResponse], dependencies=[require_roles(["owner", "admin"]), require_scopes(["read"])])
def list_trust_center_shares(
    request: Request,
    db: Session = Depends(get_tenant_db),
) -> list[TrustCenterShareResponse]:
    return [_share_response(share) for share in trust_center.list_shares(db, request.state.tenant_id)]


@router.post(
    "/shares",
    response_model=TrustCenterShareCreateResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[require_roles(["owner", "admin"]), require_scopes(["write"])],
)
def create_trust_center_share(
    payload: TrustCenterShareCreate,
    request: Request,
    db: Session = Depends(get_tenant_db),
) -> TrustCenterShareCreateResponse:
    try:
        share, token = trust_center.create_share(
            db,
            tenant_id=request.state.tenant_id,
            label=payload.label,
            auditor_email=str(payload.auditor_email),
            frameworks=payload.frameworks,
            expires_in_days=payload.expires_in_days,
            created_by=getattr(request.state, "user_id", None),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    base_url = str(request.headers.get("x-console-origin") or request.headers.get("origin") or "").strip()
    if not base_url:
        base_url = "http://localhost:3001"
    create_notification(
        db,
        tenant_id=request.state.tenant_id,
        type="trust_center_share_event",
        severity="info",
        title="Trust Center share created",
        body=f"{share.label} is available for {', '.join(share.frameworks or [])}.",
        link="/frameworks",
    )
    return TrustCenterShareCreateResponse(
        share=_share_response(share),
        token=token,
        url=trust_center.public_share_url(base_url, token),
    )


@router.post(
    "/shares/{share_id}/revoke",
    response_model=TrustCenterShareResponse,
    dependencies=[require_roles(["owner", "admin"]), require_scopes(["write"])],
)
def revoke_trust_center_share(
    share_id: UUID,
    request: Request,
    db: Session = Depends(get_tenant_db),
) -> TrustCenterShareResponse:
    share = trust_center.revoke_share(db, tenant_id=request.state.tenant_id, share_id=share_id)
    if not share:
        raise HTTPException(status_code=404, detail="Trust Center share not found")
    create_notification(
        db,
        tenant_id=request.state.tenant_id,
        type="trust_center_share_event",
        severity="warning",
        title="Trust Center share revoked",
        body=f"{share.label} was revoked.",
        link="/frameworks",
    )
    return _share_response(share)


@router.get("/public/{token}")
def get_public_trust_center(
    token: str,
    request: Request,
    db: Session = Depends(get_db),
):
    try:
        share = _public_share_or_404(db, token)
        _require_auditor_access(request, share, token)
        package = trust_center.build_public_package(db, share)
        trust_center.record_access(
            db,
            share,
            action="view",
            ip_address=request.client.host if request.client else "",
            user_agent=request.headers.get("user-agent", ""),
        )
        return package
    finally:
        _clear_public_rls_context(db)


@router.get("/public/{token}/signed-export")
def get_public_trust_center_export(
    token: str,
    request: Request,
    framework: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    try:
        share = _public_share_or_404(db, token)
        _require_auditor_access(request, share, token)
        if "download_signed_audit_export" not in set(share.permissions or []):
            raise HTTPException(status_code=403, detail="This share cannot download signed exports")
        try:
            artifact = trust_center.build_share_export(db, share, framework=framework)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        trust_center.record_access(
            db,
            share,
            action="download_signed_export",
            ip_address=request.client.host if request.client else "",
            user_agent=request.headers.get("user-agent", ""),
        )
        return artifact
    finally:
        _clear_public_rls_context(db)


@router.post("/public/{token}/request-access")
def request_public_trust_center_access(
    token: str,
    db: Session = Depends(get_db),
):
    try:
        share = _public_share_or_404(db, token)
        tenant = db.query(Tenant).filter(Tenant.id == share.tenant_id).first()
        try:
            return trust_center.issue_auditor_otp(db, share, tenant.name if tenant else "AuthClaw")
        except EmailDeliveryError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        _clear_public_rls_context(db)


@router.post("/public/{token}/verify-access")
def verify_public_trust_center_access(
    token: str,
    payload: TrustCenterAccessVerifyRequest,
    db: Session = Depends(get_db),
):
    try:
        share = _public_share_or_404(db, token)
        try:
            return trust_center.verify_auditor_otp(db, share, token, payload.otp)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        _clear_public_rls_context(db)


@router.post("/public/verify")
def verify_public_trust_center_export(payload: TrustCenterVerifyRequest):
    return trust_center.verify_artifact(payload.artifact)

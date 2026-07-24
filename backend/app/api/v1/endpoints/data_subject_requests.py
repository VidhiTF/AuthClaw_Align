"""Authenticated operator endpoints for GDPR data-subject requests."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.core.auth import (
    get_current_tenant,
    get_tenant_db,
    require_roles,
    require_scopes,
)
from app.schemas.models import (
    DataSubjectRequestCreateRequest,
    DataSubjectRequestDecisionRequest,
    DataSubjectRequestResponse,
    DataSubjectRequestVerifyRequest,
)
from app.services.data_subject_requests import DataSubjectRequestService

router = APIRouter()
_READ = [require_roles(["owner", "admin"]), require_scopes(["read"])]
_WRITE = [require_roles(["owner", "admin"]), require_scopes(["write"])]


def _not_found() -> HTTPException:
    return HTTPException(status_code=404, detail="Data-subject request not found")


def _conflict() -> HTTPException:
    return HTTPException(status_code=409, detail="Invalid request transition")


@router.post(
    "",
    response_model=DataSubjectRequestResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=_WRITE,
)
def create_request(
    payload: DataSubjectRequestCreateRequest,
    request: Request,
    db: Session = Depends(get_tenant_db),
    tenant_id: str = Depends(get_current_tenant),
):
    return DataSubjectRequestService.create(
        db, tenant_id=tenant_id, actor_id=request.state.user_id, payload=payload
    )


@router.get("", response_model=list[DataSubjectRequestResponse], dependencies=_READ)
def list_requests(
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    db: Session = Depends(get_tenant_db),
    tenant_id: str = Depends(get_current_tenant),
):
    return DataSubjectRequestService.list(
        db, tenant_id=tenant_id, offset=offset, limit=limit
    )


@router.get(
    "/{request_id}", response_model=DataSubjectRequestResponse, dependencies=_READ
)
def get_request(
    request_id: UUID,
    db: Session = Depends(get_tenant_db),
    tenant_id: str = Depends(get_current_tenant),
):
    try:
        return DataSubjectRequestService.get(
            db, tenant_id=tenant_id, request_id=request_id
        )
    except LookupError:
        raise _not_found() from None


@router.post(
    "/{request_id}/verify",
    response_model=DataSubjectRequestResponse,
    dependencies=_WRITE,
)
def verify_request(
    request_id: UUID,
    _payload: DataSubjectRequestVerifyRequest,
    request: Request,
    db: Session = Depends(get_tenant_db),
    tenant_id: str = Depends(get_current_tenant),
):
    try:
        return DataSubjectRequestService.verify(
            db,
            tenant_id=tenant_id,
            request_id=request_id,
            actor_id=request.state.user_id,
        )
    except LookupError:
        raise _not_found() from None
    except ValueError:
        raise _conflict() from None


def _decision(
    operation,
    request_id: UUID,
    payload: DataSubjectRequestDecisionRequest,
    request: Request,
    db: Session,
    tenant_id: str,
):
    try:
        return operation(
            db,
            tenant_id=tenant_id,
            request_id=request_id,
            actor_id=request.state.user_id,
            reason=payload.decision_reason,
        )
    except LookupError:
        raise _not_found() from None
    except ValueError:
        raise _conflict() from None


@router.post(
    "/{request_id}/approve",
    response_model=DataSubjectRequestResponse,
    dependencies=_WRITE,
)
def approve_request(
    request_id: UUID,
    payload: DataSubjectRequestDecisionRequest,
    request: Request,
    db: Session = Depends(get_tenant_db),
    tenant_id: str = Depends(get_current_tenant),
):
    return _decision(
        DataSubjectRequestService.approve, request_id, payload, request, db, tenant_id
    )


@router.post(
    "/{request_id}/reject",
    response_model=DataSubjectRequestResponse,
    dependencies=_WRITE,
)
def reject_request(
    request_id: UUID,
    payload: DataSubjectRequestDecisionRequest,
    request: Request,
    db: Session = Depends(get_tenant_db),
    tenant_id: str = Depends(get_current_tenant),
):
    return _decision(
        DataSubjectRequestService.reject, request_id, payload, request, db, tenant_id
    )


@router.post("/{request_id}/export", dependencies=_WRITE)
def export_request(
    request_id: UUID,
    request: Request,
    db: Session = Depends(get_tenant_db),
    tenant_id: str = Depends(get_current_tenant),
):
    try:
        return DataSubjectRequestService.export(
            db,
            tenant_id=tenant_id,
            request_id=request_id,
            actor_id=request.state.user_id,
        )
    except LookupError:
        raise _not_found() from None
    except ValueError:
        raise _conflict() from None


@router.post("/{request_id}/delete", dependencies=_WRITE)
def delete_request(
    request_id: UUID,
    request: Request,
    db: Session = Depends(get_tenant_db),
    tenant_id: str = Depends(get_current_tenant),
):
    try:
        return DataSubjectRequestService.delete(
            db,
            tenant_id=tenant_id,
            request_id=request_id,
            actor_id=request.state.user_id,
        )
    except LookupError:
        raise _not_found() from None
    except ValueError:
        raise _conflict() from None

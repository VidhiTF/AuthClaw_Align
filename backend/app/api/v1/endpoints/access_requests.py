"""Public demo and early-access intake endpoint."""

from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.api.v1.endpoints.onboarding import (
    ONBOARDING_SIGNUP_EMAIL_PER_HOUR,
    ONBOARDING_SIGNUP_IP_PER_DAY,
    _client_ip,
    _enforce_onboarding_rate_limit,
    _rate_limit_hash,
)
from app.db.dependencies import get_db
from app.core.auth import require_platform_admin
from app.schemas.models import AccessRequestCreate, AccessRequestResponse
from app.services.access_requests import (
    create_access_request,
    deliver_access_request_emails,
    transition_access_request,
)
from app.services.privacy_lifecycle import purge_expired_access_requests

router = APIRouter()


@router.post(
    "",
    response_model=AccessRequestResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def submit_access_request(
    payload: AccessRequestCreate,
    http_request: Request,
    db: Session = Depends(get_db),
) -> AccessRequestResponse:
    now = datetime.now(timezone.utc)
    try:
        _enforce_onboarding_rate_limit(
            f"access-request:email:{_rate_limit_hash(str(payload.business_email))}:{now.strftime('%Y%m%d%H')}",
            ONBOARDING_SIGNUP_EMAIL_PER_HOUR,
            3700,
            "Too many requests",
        )
        _enforce_onboarding_rate_limit(
            f"access-request:ip:{_rate_limit_hash(_client_ip(http_request))}:{now.strftime('%Y%m%d')}",
            ONBOARDING_SIGNUP_IP_PER_DAY,
            90000,
            "Too many requests",
        )
    except HTTPException as exc:
        db.rollback()
        if exc.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
            raise HTTPException(
                status_code=429, detail="Request limit exceeded"
            ) from None
        raise HTTPException(
            status_code=503, detail="Unable to process request"
        ) from None

    try:
        access_request = create_access_request(db, payload)
    except Exception:
        raise HTTPException(
            status_code=503, detail="Unable to process request"
        ) from None
    deliver_access_request_emails(access_request)
    return AccessRequestResponse(
        reference=access_request.reference,
        status=access_request.status,
        created_at=access_request.created_at,
    )


@router.patch(
    "/{reference}/status",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[require_platform_admin()],
)
def update_access_request_status(
    reference: str,
    new_status: Literal["APPROVED", "REJECTED", "INVITED"],
    http_request: Request,
    db: Session = Depends(get_db),
) -> Response:
    try:
        transition_access_request(
            db,
            reference=reference,
            new_status=new_status,
            actor_id=http_request.state.user_id,
        )
    except LookupError:
        raise HTTPException(
            status_code=404, detail="Access request not found"
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=409, detail="Invalid status transition"
        ) from None
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/retention/purge",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[require_platform_admin()],
)
def purge_access_request_retention(
    db: Session = Depends(get_db),
) -> Response:
    purge_expired_access_requests(db)
    return Response(status_code=status.HTTP_204_NO_CONTENT)

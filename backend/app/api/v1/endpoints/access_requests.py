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
from app.schemas.models import (
    AccessRequestCreate,
    AccessRequestHistoryResponse,
    AccessRequestResponse,
    AccessRequestReviewResponse,
)
from app.services.access_requests import (
    create_access_request,
    deliver_access_request_emails,
    list_access_request_histories,
    list_access_requests,
    transition_access_request,
)
from app.services.privacy_lifecycle import purge_expired_access_requests

router = APIRouter()


@router.get(
    "",
    response_model=list[AccessRequestReviewResponse],
    dependencies=[require_platform_admin()],
)
def review_access_requests(
    status_filter: Literal["PENDING", "APPROVED", "REJECTED", "INVITED", "ALL"] = "PENDING",
    requested_access: Literal["DEMO", "EARLY_ACCESS", "ALL"] = "ALL",
    limit: int = 100,
    db: Session = Depends(get_db),
) -> list[AccessRequestReviewResponse]:
    bounded_limit = max(1, min(limit, 250))
    requests = list_access_requests(
        db,
        status=None if status_filter == "ALL" else status_filter,
        requested_access=None if requested_access == "ALL" else requested_access,
        limit=bounded_limit,
    )
    histories = list_access_request_histories(db, [request.id for request in requests])
    return [
        AccessRequestReviewResponse(
            reference=request.reference,
            name=request.name,
            business_email=request.business_email,
            company=request.company,
            role=request.role,
            use_case=request.use_case,
            requested_access=request.requested_access,
            source_page=request.source_page,
            status=request.status,
            created_at=request.created_at,
            updated_at=request.updated_at,
            history=[
                AccessRequestHistoryResponse(
                    id=history.id,
                    event_type=history.event_type,
                    old_status=history.old_status,
                    new_status=history.new_status,
                    created_at=history.created_at,
                    metadata=history.event_metadata or {},
                )
                for history in histories.get(request.id, [])
            ],
        )
        for request in requests
    ]


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
    deliver_access_request_emails(access_request, db)
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
            create_invitation=True,
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

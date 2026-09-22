from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from uuid import UUID
import secrets
from typing import List
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone

from app.db.models import APIKey, User
from app.schemas.models import (
    APIKeyCreate,
    APIKeyRevoke,
    APIKeyResponse,
    APIKeyRotate,
    PLATFORM_API_KEY_SCOPES,
)
from app.core.auth import (
    get_tenant_db,
    hash_key,
    require_interactive_session,
    require_roles,
    require_scopes,
    revalidate_tenant_credential,
)
from app.api.v1.endpoints.onboarding import _get_redis
from app.services import event_backbone
from app.services.abuse_controls import verify_mfa_challenge
from app.services.notifications import create_notification

router = APIRouter()


class APIKeyCreateResponse(BaseModel):
    id: UUID
    name: str
    scopes: List[str]
    is_active: bool
    created_at: datetime
    expires_at: datetime
    rotated_from_id: UUID | None = None
    api_key: str


def _hash_key(raw_key: str) -> str:
    return hash_key(raw_key)


def _new_raw_key() -> str:
    return "ak_" + secrets.token_urlsafe(32)


def _expiry(days: int) -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=days)


def _require_not_current_key(request: Request, key: APIKey) -> None:
    current_key_id = getattr(request.state, "api_key_id", None)
    if current_key_id and str(key.id) == str(current_key_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refusing to revoke or rotate the API key currently authenticating this request.",
        )


def _require_tenant_managed_key(key: APIKey) -> None:
    if PLATFORM_API_KEY_SCOPES.intersection(key.scopes or []):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Platform API keys require controlled operational management.",
        )


def _verify_api_key_mfa(
    request: Request,
    db: Session,
    *,
    code: str,
    operation: str,
) -> User:
    """Require a fresh, replay-protected factor for credential administration."""
    require_interactive_session(request)
    user = (
        db.query(User)
        .filter(User.tenant_id == request.state.tenant_id, User.id == request.state.user_id)
        .with_for_update()
        .first()
    )
    _revalidate_locked_api_key_actor(request, db, user)
    if not user.mfa_enabled or not user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MFA enrollment is required for API key administration",
        )
    if not verify_mfa_challenge(
        _get_redis(),
        user,
        code,
        tenant_id=str(request.state.tenant_id),
        operation=operation,
        request_id=request.headers.get("x-request-id", ""),
    ):
        db.rollback()
        raise HTTPException(status_code=400, detail="Invalid MFA token or backup code")
    return user


def _revalidate_locked_api_key_actor(
    request: Request,
    db: Session,
    user: User | None,
) -> None:
    """Refresh the locked actor and fail closed if current authority changed."""
    if user is not None:
        db.refresh(user, attribute_names=["is_active", "role"])
    bound = revalidate_tenant_credential(request, db)
    current_role = str(user.role).lower() if user is not None else ""
    bound_role = str(bound.role).lower() if bound is not None else ""
    current_scopes = set(bound.scopes or []) if bound is not None else set()
    if (
        user is None
        or not user.is_active
        or current_role != "owner"
        or bound_role != "owner"
        or "admin" not in current_scopes
    ):
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Active tenant owner with admin scope required",
        )


def _commit_api_key_audit(
    db: Session,
    request: Request,
    *,
    key: APIKey,
    action: str,
    rotated_from_id: UUID | None = None,
) -> None:
    tenant_id = str(request.state.tenant_id)
    trace = [{
        "event": action,
        "api_key_id": str(key.id),
        "rotated_from_id": str(rotated_from_id) if rotated_from_id else None,
        "scopes": sorted(key.scopes or []),
        "mfa_verified": True,
    }]
    event = event_backbone.audit_event(
        event_type="credential_administration",
        tenant_id=tenant_id,
        subject_id=str(key.id),
        identity_action=f"api_key:{action}:{key.id}",
        action=f"api_key:{action}",
        reason="Interactive owner completed fresh MFA",
        provider="control-plane-mfa",
        request_id=request.headers.get("x-request-id", ""),
        actor_id=str(request.state.user_id),
        trace=trace,
    )
    event.update({
        "result": "success",
        "response_status": {
            "issued": status.HTTP_201_CREATED,
            "rotated": status.HTTP_201_CREATED,
            "revoked": status.HTTP_204_NO_CONTENT,
        }.get(action, status.HTTP_200_OK),
        "mfa_verified": True,
    })
    if event_backbone.publish_audit_event(None, tenant_id, event, db=db):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API key change could not be recorded",
        )


@router.get("", response_model=list[APIKeyResponse], dependencies=[require_roles(["owner"]), require_scopes(["read"])])
def list_api_keys(
    request: Request,
    include_inactive: bool = False,
    db: Session = Depends(get_tenant_db),
):
    """List all API keys for the tenant (isolated by tenant RLS)"""
    tenant_id = request.state.tenant_id
    query = db.query(APIKey).filter(APIKey.tenant_id == tenant_id)
    query = query.filter(
        ~APIKey.scopes.any(next(iter(PLATFORM_API_KEY_SCOPES)))
    )
    if not include_inactive:
        query = query.filter(APIKey.is_active == True)
    return query.order_by(APIKey.created_at.desc()).all()


@router.post("", response_model=APIKeyCreateResponse, status_code=status.HTTP_201_CREATED, dependencies=[require_roles(["owner"]), require_scopes(["admin"])])
def generate_api_key(
    request: Request,
    key_in: APIKeyCreate,
    db: Session = Depends(get_tenant_db)
):
    """Generate a new API key for the tenant"""
    tenant_id = request.state.tenant_id
    user_id = request.state.user_id

    # Serialize issuance with owner recovery and consume MFA while holding the
    # user row lock so recovery cannot race a privileged credential change.
    actor = _verify_api_key_mfa(
        request, db, code=key_in.mfa_code.get_secret_value(), operation="api_key_issue"
    )

    # Generate a raw api key
    raw_key = _new_raw_key()
    key_hash = _hash_key(raw_key)

    try:
        new_key = APIKey(
            tenant_id=tenant_id,
            key_hash=key_hash,
            name=key_in.name,
            description=key_in.description,
            scopes=key_in.scopes,
            is_active=True,
            expires_at=_expiry(key_in.expires_in_days),
            created_by=user_id,
        )
        db.add(new_key)
        db.flush()
        _revalidate_locked_api_key_actor(request, db, actor)
        _commit_api_key_audit(db, request, key=new_key, action="issued")
        db.refresh(new_key)
        create_notification(
            db,
            tenant_id=tenant_id,
            type="gateway_api_key_issue",
            severity="info",
            title="API key created",
            body=f"{new_key.name} was created.",
            link="/connect",
        )

        return APIKeyCreateResponse(
            id=new_key.id,
            name=new_key.name,
            scopes=new_key.scopes,
            is_active=new_key.is_active,
            created_at=new_key.created_at,
            expires_at=new_key.expires_at,
            api_key=raw_key
        )
    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate API key: {str(e)}"
        )


@router.post("/{id}/rotate", response_model=APIKeyCreateResponse, status_code=status.HTTP_201_CREATED, dependencies=[require_roles(["owner"]), require_scopes(["admin"])])
def rotate_api_key(
    id: UUID,
    request: Request,
    rotate_in: APIKeyRotate,
    db: Session = Depends(get_tenant_db),
):
    """Rotate an API key by revoking the old key and returning a new secret once."""
    tenant_id = request.state.tenant_id
    user_id = request.state.user_id
    actor = _verify_api_key_mfa(
        request, db, code=rotate_in.mfa_code.get_secret_value(), operation="api_key_rotate"
    )
    # Different tenant owners lock different User rows above, so serialize on
    # the credential itself to prevent two active descendants from one key.
    old_key = (
        db.query(APIKey)
        .filter(APIKey.tenant_id == tenant_id, APIKey.id == id)
        .with_for_update()
        .first()
    )
    if not old_key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API Key not found")
    _require_tenant_managed_key(old_key)
    _require_not_current_key(request, old_key)
    if not old_key.is_active or old_key.revoked_at or old_key.rotated_at:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="API key is not active")

    raw_key = _new_raw_key()
    new_key = APIKey(
        tenant_id=tenant_id,
        key_hash=_hash_key(raw_key),
        name=rotate_in.name or old_key.name,
        description=rotate_in.description if rotate_in.description is not None else old_key.description,
        scopes=rotate_in.scopes or old_key.scopes,
        is_active=True,
        expires_at=_expiry(rotate_in.expires_in_days),
        created_by=user_id,
        rotated_from_id=old_key.id,
    )
    old_key.is_active = False
    old_key.rotated_at = datetime.now(timezone.utc)
    db.add(new_key)
    db.flush()
    _revalidate_locked_api_key_actor(request, db, actor)
    _commit_api_key_audit(
        db, request, key=new_key, action="rotated", rotated_from_id=old_key.id
    )
    db.refresh(new_key)
    create_notification(
        db,
        tenant_id=tenant_id,
        type="gateway_api_key_issue",
        severity="warning",
        title="API key rotated",
        body=f"{old_key.name} was rotated.",
        link="/connect",
    )
    return APIKeyCreateResponse(
        id=new_key.id,
        name=new_key.name,
        scopes=new_key.scopes,
        is_active=new_key.is_active,
        created_at=new_key.created_at,
        expires_at=new_key.expires_at,
        rotated_from_id=old_key.id,
        api_key=raw_key,
    )


@router.delete("/{id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[require_roles(["owner"]), require_scopes(["admin"])])
def revoke_api_key(
    id: UUID,
    request: Request,
    revoke_in: APIKeyRevoke,
    db: Session = Depends(get_tenant_db)
):
    """Revoke (delete) an API key for the tenant"""
    tenant_id = request.state.tenant_id
    actor = _verify_api_key_mfa(
        request, db, code=revoke_in.mfa_code.get_secret_value(), operation="api_key_revoke"
    )
    key = (
        db.query(APIKey)
        .filter(APIKey.tenant_id == tenant_id, APIKey.id == id)
        .with_for_update()
        .first()
    )
    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API Key not found"
        )
    _require_tenant_managed_key(key)
    _require_not_current_key(request, key)
    if not key.is_active or key.revoked_at or key.rotated_at:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="API key is not active")
    key.is_active = False
    key.revoked_at = datetime.now(timezone.utc)
    _revalidate_locked_api_key_actor(request, db, actor)
    _commit_api_key_audit(db, request, key=key, action="revoked")
    create_notification(
        db,
        tenant_id=tenant_id,
        type="gateway_api_key_issue",
        severity="warning",
        title="API key revoked",
        body=f"{key.name} was revoked.",
        link="/connect",
    )

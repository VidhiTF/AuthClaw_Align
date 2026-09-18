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
    APIKeyResponse,
    APIKeyRotate,
    PLATFORM_API_KEY_SCOPES,
)
from app.core.auth import get_tenant_db, hash_key, require_roles, require_scopes, revalidate_tenant_credential
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

    # Serialize issuance with owner recovery, then reject credentials revoked
    # while waiting. A foreign-key lock alone would allow post-reset issuance.
    db.query(User).filter(User.tenant_id == tenant_id, User.id == user_id).with_for_update().first()
    revalidate_tenant_credential(request, db)

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
        db.commit()
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
    db.query(User).filter(User.tenant_id == tenant_id, User.id == user_id).with_for_update().first()
    revalidate_tenant_credential(request, db)
    old_key = db.query(APIKey).filter(APIKey.tenant_id == tenant_id, APIKey.id == id).first()
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
    db.commit()
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
    db: Session = Depends(get_tenant_db)
):
    """Revoke (delete) an API key for the tenant"""
    tenant_id = request.state.tenant_id
    key = db.query(APIKey).filter(APIKey.tenant_id == tenant_id, APIKey.id == id).first()
    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API Key not found"
        )
    _require_tenant_managed_key(key)
    _require_not_current_key(request, key)
    key.is_active = False
    key.revoked_at = datetime.now(timezone.utc)
    db.commit()
    create_notification(
        db,
        tenant_id=tenant_id,
        type="gateway_api_key_issue",
        severity="warning",
        title="API key revoked",
        body=f"{key.name} was revoked.",
        link="/connect",
    )

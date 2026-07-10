from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.auth import get_tenant_db, require_roles, require_scopes
from app.core.crypto import encrypt_secret
from app.db.models import OnboardingStatus, ProviderCredential
from app.schemas.models import ProviderCredentialCreate, ProviderCredentialResponse

router = APIRouter()


@router.get("", response_model=list[ProviderCredentialResponse], dependencies=[require_scopes(["read"])])
def list_provider_credentials(request: Request, db: Session = Depends(get_tenant_db)):
    """List provider credential metadata for the current tenant."""
    tenant_id = request.state.tenant_id
    return db.query(ProviderCredential).filter(
        ProviderCredential.tenant_id == tenant_id,
    ).order_by(ProviderCredential.created_at.desc()).all()


@router.post("", response_model=ProviderCredentialResponse, status_code=status.HTTP_201_CREATED, dependencies=[require_roles(["owner", "admin"])])
def create_provider_credential(
    request: Request,
    credential_in: ProviderCredentialCreate,
    db: Session = Depends(get_tenant_db),
):
    """Store an encrypted provider API key. The raw key is never returned."""
    tenant_id = request.state.tenant_id
    user_id = request.state.user_id

    encrypted_secret = encrypt_secret(credential_in.api_key)
    latest_version = (
        db.query(ProviderCredential)
        .filter(
            ProviderCredential.tenant_id == tenant_id,
            ProviderCredential.provider == credential_in.provider,
        )
        .order_by(ProviderCredential.version.desc())
        .first()
    )

    # Keep only one active Lite credential per tenant/provider for the demo.
    db.query(ProviderCredential).filter(
        ProviderCredential.tenant_id == tenant_id,
        ProviderCredential.provider == credential_in.provider,
        ProviderCredential.status == "active",
    ).update({
        ProviderCredential.status: "rotated",
        ProviderCredential.rotated_at: datetime.now(timezone.utc),
    })

    credential = ProviderCredential(
        tenant_id=tenant_id,
        provider=credential_in.provider,
        display_name=credential_in.display_name,
        endpoint=credential_in.endpoint,
        encrypted_secret=encrypted_secret,
        auth_scheme="api_key",
        status="active",
        last_verified_at=datetime.now(timezone.utc),
        created_by=user_id,
        version=(latest_version.version + 1) if latest_version else 1,
    )
    db.add(credential)
    onboarding = db.query(OnboardingStatus).filter(OnboardingStatus.tenant_id == tenant_id).first()
    if onboarding:
        onboarding.provider_key_saved = True
        onboarding.current_step = "test_request"
    db.commit()
    db.refresh(credential)
    return credential


@router.post("/{credential_id}/rotate", response_model=ProviderCredentialResponse, dependencies=[require_roles(["owner", "admin"])])
def rotate_provider_credential(
    credential_id: UUID,
    credential_in: ProviderCredentialCreate,
    request: Request,
    db: Session = Depends(get_tenant_db),
):
    """Rotate an existing provider credential."""
    tenant_id = request.state.tenant_id
    credential = db.query(ProviderCredential).filter(
        ProviderCredential.tenant_id == tenant_id,
        ProviderCredential.id == credential_id,
    ).first()
    if not credential:
        raise HTTPException(status_code=404, detail="Provider credential not found")
    if credential.provider != credential_in.provider:
        raise HTTPException(status_code=400, detail="Provider cannot be changed during rotation")

    now = datetime.now(timezone.utc)
    credential.status = "rotated"
    credential.rotated_at = now
    new_credential = ProviderCredential(
        tenant_id=tenant_id,
        provider=credential.provider,
        display_name=credential_in.display_name,
        endpoint=credential_in.endpoint,
        encrypted_secret=encrypt_secret(credential_in.api_key),
        auth_scheme=credential.auth_scheme,
        status="active",
        last_verified_at=now,
        created_by=request.state.user_id,
        rotated_at=now,
        rotated_from_id=credential.id,
        version=(credential.version or 1) + 1,
    )
    db.add(new_credential)
    db.commit()
    db.refresh(new_credential)
    return new_credential


@router.delete("/{credential_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[require_roles(["owner", "admin"])])
def revoke_provider_credential(
    credential_id: UUID,
    request: Request,
    db: Session = Depends(get_tenant_db),
):
    """Revoke a provider credential."""
    tenant_id = request.state.tenant_id
    credential = db.query(ProviderCredential).filter(
        ProviderCredential.tenant_id == tenant_id,
        ProviderCredential.id == credential_id,
    ).first()
    if not credential:
        raise HTTPException(status_code=404, detail="Provider credential not found")
    credential.status = "revoked"
    credential.revoked_at = datetime.now(timezone.utc)
    credential.revoked_by = request.state.user_id
    db.commit()

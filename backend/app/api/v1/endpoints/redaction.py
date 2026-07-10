from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from sqlalchemy import func, or_
from uuid import UUID
from typing import List

from app.db.models import RedactionToken
from app.schemas.models import RedactionTokenMapResponse
from app.core.auth import get_tenant_db, require_scopes
from app.core.crypto import decrypt_deterministic

router = APIRouter()


@router.get("/{id}/tokenization-map", response_model=List[RedactionTokenMapResponse], dependencies=[require_scopes(["read"])])
def get_tokenization_map(
    id: UUID,
    request: Request,
    db: Session = Depends(get_tenant_db),
    include_expired: bool = False,
    include_purged: bool = False,
):
    """Retrieve tokenization mapping for the tenant, decrypting original values dynamically"""
    tenant_id = request.state.tenant_id

    # Strict check to verify request context tenant matches URL parameter tenant
    if str(id) != str(tenant_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Cross-tenant access is not allowed"
        )

    query = db.query(RedactionToken).filter(RedactionToken.tenant_id == tenant_id)
    if not include_expired:
        query = query.filter(or_(RedactionToken.expires_at.is_(None), RedactionToken.expires_at > func.now()))
    if not include_purged:
        query = query.filter(RedactionToken.purged_at.is_(None))

    tokens = query.order_by(RedactionToken.created_at.desc()).all()

    response = []
    for t in tokens:
        try:
            decrypted = decrypt_deterministic(t.original_value)
        except Exception as dec_err:
            print(f"[WARN] Failed to decrypt token value for mapping ID {t.id}: {dec_err}")
            decrypted = "[Decryption Failed]"

        response.append(
            RedactionTokenMapResponse(
                id=t.id,
                token_value=t.token_value,
                token_hash=t.token_hash,
                original_value=decrypted,
                strategy=t.strategy,
                entity_type=t.entity_type,
                expires_at=t.expires_at,
                last_used_at=t.last_used_at,
                use_count=t.use_count or 0,
                purged_at=t.purged_at,
                created_at=t.created_at
            )
        )

    return response


@router.post("/{id}/purge-expired", dependencies=[require_scopes(["admin"])])
def purge_expired_redaction_tokens(
    id: UUID,
    request: Request,
    db: Session = Depends(get_tenant_db)
):
    """Purge expired reversible redaction mappings for the current tenant."""
    tenant_id = request.state.tenant_id
    if str(id) != str(tenant_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Cross-tenant access is not allowed"
        )

    deleted = (
        db.query(RedactionToken)
        .filter(RedactionToken.tenant_id == tenant_id)
        .filter(RedactionToken.expires_at.isnot(None))
        .filter(RedactionToken.expires_at <= func.now())
        .delete(synchronize_session=False)
    )
    db.commit()
    return {"purged": deleted}

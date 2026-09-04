from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from sqlalchemy import text
import uuid

from app.db.dependencies import get_db
from app.db.models import Tenant, User
from app.schemas.models import TenantCreate, TenantResponse, TenantStatusUpdate
from app.core.auth import get_tenant_db, require_platform_admin, require_roles, require_scopes

router = APIRouter()


@router.post(
    "",
    response_model=TenantResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[require_platform_admin()],
)
def create_tenant(
    tenant_data: TenantCreate,
    db: Session = Depends(get_db),
):
    tenant_id = uuid.uuid4()
    try:
        tenant = db.execute(
            text(
                """
                SELECT id, name, tier, status, created_at, updated_at
                  FROM authn.create_tenant_as_platform_admin(:id, :name, :tier)
                """
            ),
            {"id": str(tenant_id), "name": tenant_data.name, "tier": tenant_data.tier},
        ).one()
        db.commit()
        return tenant
    except HTTPException:
        db.rollback()
        raise
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create tenant",
        ) from exc

@router.get("/current", response_model=TenantResponse, dependencies=[require_roles(["owner", "admin", "developer", "operator", "viewer"])])
def get_current_tenant(request: Request, db: Session = Depends(get_tenant_db)):
    """Return the active tenant profile."""
    tenant_id = request.state.tenant_id
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    return tenant


@router.patch("/current/status", response_model=TenantResponse, dependencies=[require_roles(["owner"]), require_scopes(["admin"])])
def update_current_tenant_status(
    status_in: TenantStatusUpdate,
    request: Request,
    db: Session = Depends(get_tenant_db),
):
    """Owner-only tenant lifecycle control. Disabled tenants cannot authenticate new requests."""
    tenant_id = request.state.tenant_id
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    if status_in.status != "active" and (
        db.query(User.id)
        .filter(
            User.tenant_id == tenant_id,
            User.platform_role != "NONE",
        )
        .first()
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Tenant contains platform identities managed through operational procedures.",
        )
    tenant.status = status_in.status
    db.commit()
    db.refresh(tenant)
    return tenant

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from uuid import UUID

from app.db.models import GatewayConfig
from app.schemas.models import GatewayConfigCreate, GatewayConfigResponse
from app.core.auth import get_tenant_db, require_roles, require_scopes

router = APIRouter()


@router.post("", response_model=GatewayConfigResponse, status_code=status.HTTP_201_CREATED, dependencies=[require_roles(["owner", "admin"])])
def register_gateway(
    request: Request,
    gateway_in: GatewayConfigCreate,
    db: Session = Depends(get_tenant_db)
):
    """Register a new gateway configuration for the tenant"""
    tenant_id = request.state.tenant_id

    # Check if a gateway with the same name already exists for this tenant
    existing = db.query(GatewayConfig).filter(
        GatewayConfig.tenant_id == tenant_id,
        GatewayConfig.name == gateway_in.name
    ).first()
    
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Gateway configuration with this name already exists"
        )

    try:
        gateway = GatewayConfig(
            tenant_id=tenant_id,
            name=gateway_in.name,
            provider=gateway_in.provider,
            endpoint=gateway_in.endpoint,
            model_whitelist=gateway_in.model_whitelist,
            redaction_strategy=gateway_in.redaction_strategy,
            redaction_token_retention_days=gateway_in.redaction_token_retention_days,
            is_active=True
        )
        db.add(gateway)
        db.commit()
        db.refresh(gateway)
        return gateway
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to register gateway: {str(e)}"
        )


@router.get("/{id}/config", response_model=GatewayConfigResponse, dependencies=[require_scopes(["read"])])
def get_gateway_config(
    id: UUID,
    request: Request,
    db: Session = Depends(get_tenant_db)
):
    """Retrieve gateway routing configuration (isolated by tenant RLS)"""
    tenant_id = request.state.tenant_id
    gateway = db.query(GatewayConfig).filter(GatewayConfig.tenant_id == tenant_id, GatewayConfig.id == id).first()
    if not gateway:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Gateway configuration not found"
        )
    return gateway


@router.get("", response_model=list[GatewayConfigResponse], dependencies=[require_scopes(["read"])])
def list_gateways(
    request: Request,
    db: Session = Depends(get_tenant_db)
):
    """List all gateway configurations for the tenant (isolated by tenant RLS)"""
    tenant_id = request.state.tenant_id
    return db.query(GatewayConfig).filter(GatewayConfig.tenant_id == tenant_id).all()


@router.put("/{id}", response_model=GatewayConfigResponse, dependencies=[require_roles(["owner", "admin"])])
def update_gateway(
    id: UUID,
    gateway_in: GatewayConfigCreate,
    request: Request,
    db: Session = Depends(get_tenant_db)
):
    """Update a gateway configuration for the tenant"""
    tenant_id = request.state.tenant_id
    gateway = db.query(GatewayConfig).filter(GatewayConfig.tenant_id == tenant_id, GatewayConfig.id == id).first()
    if not gateway:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Gateway configuration not found"
        )
    gateway.name = gateway_in.name
    gateway.provider = gateway_in.provider
    gateway.endpoint = gateway_in.endpoint
    gateway.model_whitelist = gateway_in.model_whitelist
    gateway.redaction_strategy = gateway_in.redaction_strategy
    gateway.redaction_token_retention_days = gateway_in.redaction_token_retention_days
    db.commit()
    db.refresh(gateway)
    return gateway


@router.delete("/{id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[require_roles(["owner", "admin"])])
def delete_gateway(
    id: UUID,
    request: Request,
    db: Session = Depends(get_tenant_db)
):
    """Delete a gateway configuration for the tenant"""
    tenant_id = request.state.tenant_id
    gateway = db.query(GatewayConfig).filter(GatewayConfig.tenant_id == tenant_id, GatewayConfig.id == id).first()
    if not gateway:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Gateway configuration not found"
        )
    db.delete(gateway)
    db.commit()

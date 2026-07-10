"""Cloud connector APIs for AWS, GitHub, and GCP."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.auth import get_tenant_db, require_roles, require_scopes
from app.api.v1.endpoints.workflows import _verify_mfa_if_enabled
from app.db.models import CloudConnector, User
from app.services import cloud_connectors

router = APIRouter()


class CloudConnectorCreate(BaseModel):
    provider: str
    display_name: str = Field(default="", max_length=255)
    credentials: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CloudActionRequest(BaseModel):
    payload: dict[str, Any] = Field(default_factory=dict)
    totp_code: str | None = None


def _get_connector(db: Session, request: Request, connector_id: UUID) -> CloudConnector:
    connector = db.query(CloudConnector).filter(
        CloudConnector.tenant_id == request.state.tenant_id,
        CloudConnector.id == connector_id,
    ).first()
    if not connector:
        raise HTTPException(status_code=404, detail="Cloud connector not found")
    return connector


@router.get("", dependencies=[require_scopes(["read"])])
def list_cloud_connectors(request: Request, db: Session = Depends(get_tenant_db)):
    connectors = db.query(CloudConnector).filter(
        CloudConnector.tenant_id == request.state.tenant_id,
        CloudConnector.status != "revoked",
    ).order_by(CloudConnector.created_at.desc()).all()
    return {
        "catalog": cloud_connectors.provider_catalog(),
        "connectors": [cloud_connectors.serialize_connector(item) for item in connectors],
    }


@router.post("", status_code=status.HTTP_201_CREATED, dependencies=[require_roles(["owner", "admin"]), require_scopes(["write"])])
def create_cloud_connector(
    body: CloudConnectorCreate,
    request: Request,
    db: Session = Depends(get_tenant_db),
):
    try:
        connector = cloud_connectors.create_connector(
            db,
            tenant_id=request.state.tenant_id,
            user_id=request.state.user_id,
            provider=body.provider,
            display_name=body.display_name,
            credentials=body.credentials,
            metadata=body.metadata,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return cloud_connectors.serialize_connector(connector)


@router.delete("/{connector_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[require_roles(["owner", "admin"]), require_scopes(["write"])])
def revoke_cloud_connector(connector_id: UUID, request: Request, db: Session = Depends(get_tenant_db)):
    connector = _get_connector(db, request, connector_id)
    cloud_connectors.revoke_connector(db, connector, request.state.user_id)


@router.post("/{connector_id}/verify", dependencies=[require_roles(["owner", "admin"]), require_scopes(["write"])])
def verify_cloud_connector(connector_id: UUID, request: Request, db: Session = Depends(get_tenant_db)):
    connector = _get_connector(db, request, connector_id)
    result = cloud_connectors.verify_connector(db, connector)
    return {"connector": cloud_connectors.serialize_connector(connector), "result": result}


@router.post("/{connector_id}/actions/{action}", dependencies=[require_roles(["owner", "admin"]), require_scopes(["write"])])
def run_cloud_connector_action(
    connector_id: UUID,
    action: str,
    body: CloudActionRequest,
    request: Request,
    db: Session = Depends(get_tenant_db),
):
    connector = _get_connector(db, request, connector_id)
    if action in {"remediate", "pr-remediation"}:
        user = db.query(User).filter(
            User.id == request.state.user_id,
            User.tenant_id == request.state.tenant_id,
        ).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        _verify_mfa_if_enabled(user, request, body, required=True)
    try:
        return cloud_connectors.run_action(
            db,
            connector,
            action,
            body.payload,
            request.state.user_id,
            request.headers.get("x-request-id", ""),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

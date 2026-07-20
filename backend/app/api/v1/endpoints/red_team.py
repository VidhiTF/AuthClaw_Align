"""Risk and red-team endpoints."""

from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.auth import get_current_tenant, get_tenant_db, require_roles, require_scopes
from app.db.models import Tenant
from app.services import red_team
from app.services.worker_throttle import check_worker_throttle

router = APIRouter()


class RedTeamRunRequest(BaseModel):
    observed_responses: Dict[str, str] = Field(default_factory=dict)
    simulation_only: bool = True


@router.get("", dependencies=[require_scopes(["read"])])
def list_red_team_runs(
    db: Session = Depends(get_tenant_db),
    tenant_id: str = Depends(get_current_tenant),
):
    return red_team.list_runs(db, tenant_id)


@router.post("/runs", status_code=201, dependencies=[require_roles(["owner", "admin"]), require_scopes(["write"])])
def run_red_team(
    payload: RedTeamRunRequest,
    request: Request,
    db: Session = Depends(get_tenant_db),
):
    tenant_id = str(request.state.tenant_id)
    tenant = db.query(Tenant).filter(Tenant.id == request.state.tenant_id).first()
    allowed, retry_after = check_worker_throttle(tenant_id, "red_team", tier=tenant.tier if tenant else "starter")
    if not allowed:
        raise HTTPException(status_code=429, detail=f"Red-team worker throttle exceeded. Retry after {retry_after:.0f}s.")
    try:
        return red_team.run(
            db,
            tenant_id,
            payload.observed_responses,
            simulation_only=payload.simulation_only,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

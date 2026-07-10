from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
import os
from uuid import UUID

from app.db.models import Policy
from app.schemas.models import (
    PolicyCreate,
    PolicyResponse,
    PolicyDetailResponse,
    PolicyValidationRequest,
    PolicyValidationResponse,
    PolicySimulationRequest,
    PolicySimulationResponse,
    PolicyRollbackRequest,
)
from app.core.auth import get_tenant_db, require_roles, require_scopes
from app.services.policy_engine import PolicyValidationError, validate_policy_yaml as validate_policy_document, simulate_policy

router = APIRouter()


def _validation_http_error(exc: PolicyValidationError) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={
            "message": "Policy validation failed",
            "errors": exc.errors,
            "warnings": exc.warnings,
        },
    )


def validate_policy_yaml(yaml_str: str):
    """Validate YAML parsing and policy semantics within policy config."""
    try:
        return validate_policy_document(yaml_str)
    except PolicyValidationError as exc:
        raise _validation_http_error(exc)


def _publish_policy_invalidation(tenant_id):
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    try:
        import redis

        if redis_url and not redis_url.startswith("redis://") and not redis_url.startswith("rediss://"):
            redis_url = f"redis://{redis_url}"
        r_client = redis.from_url(redis_url)
        r_client.publish("policy_invalidation", str(tenant_id))
    except Exception as re_err:
        print(f"[WARN] Failed to publish policy invalidation to Redis: {re_err}")


def _activate_policy(db: Session, tenant_id, policy: Policy) -> None:
    db.query(Policy).filter(Policy.tenant_id == tenant_id, Policy.is_active == True).update(
        {Policy.is_active: False},
        synchronize_session=False,
    )
    policy.is_active = True
    db.flush()


def _policy_validation_response(policy_yaml: str) -> PolicyValidationResponse:
    try:
        report = validate_policy_document(policy_yaml)
        return PolicyValidationResponse(**report)
    except PolicyValidationError as exc:
        return PolicyValidationResponse(valid=False, errors=exc.errors, warnings=exc.warnings)


@router.post("/validate", response_model=PolicyValidationResponse, dependencies=[require_scopes(["read"])])
def validate_policy(policy_in: PolicyValidationRequest):
    """Validate policy YAML without saving it."""
    return _policy_validation_response(policy_in.policy_yaml)


@router.post("/simulate", response_model=PolicySimulationResponse, dependencies=[require_scopes(["read"])])
def simulate_policy_decision(
    request: Request,
    simulation: PolicySimulationRequest,
    db: Session = Depends(get_tenant_db),
):
    """Dry-run policy evaluation with explanations and matched rules."""
    tenant_id = request.state.tenant_id
    policy = None
    if simulation.policy_yaml:
        policy_yaml = simulation.policy_yaml
    elif simulation.policy_id:
        policy = db.query(Policy).filter(Policy.tenant_id == tenant_id, Policy.id == simulation.policy_id).first()
        if not policy:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found")
        policy_yaml = policy.policy_yaml
    else:
        policy = db.query(Policy).filter(Policy.tenant_id == tenant_id, Policy.is_active == True).first()
        if not policy:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No active policy found")
        policy_yaml = policy.policy_yaml

    validation = _policy_validation_response(policy_yaml)
    if not validation.valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": "Cannot simulate an invalid policy",
                "errors": validation.errors,
                "warnings": validation.warnings,
            },
        )

    result = simulate_policy(
        policy_yaml,
        model=simulation.model,
        route=simulation.route,
        prompts=simulation.prompts,
        topics=simulation.topics,
        rate_limit_exceeded=simulation.rate_limit_exceeded,
    )
    return PolicySimulationResponse(
        **result.as_dict(),
        policy_id=policy.id if policy else simulation.policy_id,
        policy_version=policy.version if policy else None,
        policy_name=policy.name if policy else None,
        validation=validation,
    )


@router.post("", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED, dependencies=[require_roles(["owner", "admin"])])
def upload_policy(
    request: Request,
    policy_in: PolicyCreate,
    db: Session = Depends(get_tenant_db)
):
    """Upload or update a YAML policy config (isolated by tenant RLS)"""
    tenant_id = request.state.tenant_id
    user_id = request.state.user_id

    # 1. Validate YAML syntax, schema, regexes, and activation safety
    validate_policy_yaml(policy_in.policy_yaml)

    try:
        # 2. Query current policies to determine next version
        existing_policies = db.query(Policy).filter(Policy.tenant_id == tenant_id).all()
        next_version = 1
        if existing_policies:
            next_version = max(p.version for p in existing_policies) + 1

        # 3. Insert new version. It may be activated immediately or saved as a draft.
        policy = Policy(
            tenant_id=tenant_id,
            name=policy_in.name,
            description=policy_in.description,
            policy_yaml=policy_in.policy_yaml,
            version=next_version,
            is_active=False,
            created_by=user_id
        )
        db.add(policy)
        db.flush()
        if policy_in.activate:
            _activate_policy(db, tenant_id, policy)
        response = {
            "id": policy.id,
            "name": policy.name,
            "version": policy.version,
            "is_active": policy.is_active,
            "created_at": policy.created_at,
        }
        db.commit()

        if policy_in.activate:
            _publish_policy_invalidation(tenant_id)

        return response
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save policy: {str(e)}"
        )


@router.get("", response_model=list[PolicyResponse], dependencies=[require_scopes(["read"])])
def list_policies(
    request: Request,
    db: Session = Depends(get_tenant_db)
):
    """List all policies for the tenant (including inactive/older versions)"""
    tenant_id = request.state.tenant_id
    return db.query(Policy).filter(Policy.tenant_id == tenant_id).order_by(Policy.version.desc()).all()


@router.get("/active", response_model=PolicyDetailResponse, dependencies=[require_scopes(["read"])])
def get_active_policy(
    request: Request,
    db: Session = Depends(get_tenant_db)
):
    """Get the currently active policy for the tenant"""
    tenant_id = request.state.tenant_id
    policy = db.query(Policy).filter(Policy.tenant_id == tenant_id, Policy.is_active == True).first()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active policy found"
        )
    return policy


@router.post("/rollback", response_model=PolicyDetailResponse, dependencies=[require_roles(["owner", "admin"])])
def rollback_policy(
    request: Request,
    rollback: PolicyRollbackRequest,
    db: Session = Depends(get_tenant_db),
):
    """Rollback by activating a previous policy version."""
    tenant_id = request.state.tenant_id
    query = db.query(Policy).filter(Policy.tenant_id == tenant_id)
    if rollback.policy_id:
        policy = query.filter(Policy.id == rollback.policy_id).first()
    elif rollback.version is not None:
        policy = query.filter(Policy.version == rollback.version).first()
    else:
        active = query.filter(Policy.is_active == True).first()
        active_version = active.version if active else 10**9
        policy = query.filter(Policy.version < active_version).order_by(Policy.version.desc()).first()

    if not policy:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rollback target policy not found")
    validate_policy_yaml(policy.policy_yaml)
    try:
        _activate_policy(db, tenant_id, policy)
        db.commit()
        _publish_policy_invalidation(tenant_id)
        return policy
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to rollback policy: {exc}")


@router.post("/{policy_id}/activate", response_model=PolicyDetailResponse, dependencies=[require_roles(["owner", "admin"])])
def activate_policy(
    request: Request,
    policy_id: UUID,
    db: Session = Depends(get_tenant_db),
):
    """Activate a validated policy version and atomically deactivate the previous active version."""
    tenant_id = request.state.tenant_id
    policy = db.query(Policy).filter(Policy.tenant_id == tenant_id, Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found")
    validate_policy_yaml(policy.policy_yaml)
    try:
        _activate_policy(db, tenant_id, policy)
        db.commit()
        _publish_policy_invalidation(tenant_id)
        return policy
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to activate policy: {exc}")


@router.get("/{policy_id}", response_model=PolicyDetailResponse, dependencies=[require_scopes(["read"])])
def get_policy(
    request: Request,
    policy_id: UUID,
    db: Session = Depends(get_tenant_db),
):
    tenant_id = request.state.tenant_id
    policy = db.query(Policy).filter(Policy.tenant_id == tenant_id, Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found")
    return policy

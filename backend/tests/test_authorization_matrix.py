from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints.findings import router as findings_router
from app.api.v1.endpoints.gateways import router as gateways_router
from app.api.v1.endpoints.tenants import router as tenants_router
from app.schemas.models import UserInviteRequest


def _route(router, path: str, method: str):
    return next(route for route in router.routes if route.path == path and method in route.methods)


def _check_dependencies(route, *, role: str, scopes: list[str]) -> None:
    request = SimpleNamespace(state=SimpleNamespace(user_role=role, scopes=scopes))
    for dependency in route.dependencies:
        dependency.dependency(request)


def test_viewer_cannot_change_finding_status():
    route = _route(findings_router, "/{finding_id}/status", "PATCH")

    with pytest.raises(HTTPException) as exc:
        _check_dependencies(route, role="viewer", scopes=["read"])

    assert exc.value.status_code == 403


def test_read_only_owner_key_cannot_create_gateway():
    route = _route(gateways_router, "", "POST")

    with pytest.raises(HTTPException) as exc:
        _check_dependencies(route, role="owner", scopes=["read"])

    assert exc.value.status_code == 403


def test_admin_write_session_passes_operational_guards():
    _check_dependencies(
        _route(gateways_router, "", "POST"),
        role="admin",
        scopes=["read", "write"],
    )


def test_only_owner_can_create_tenant():
    route = _route(tenants_router, "", "POST")

    with pytest.raises(HTTPException) as exc:
        _check_dependencies(route, role="admin", scopes=["admin", "read", "write"])

    assert exc.value.status_code == 403
    _check_dependencies(route, role="owner", scopes=["admin", "read", "write"])


@pytest.mark.parametrize("role", ["developer", "operator"])
def test_read_only_roles_can_be_invited(role):
    assert UserInviteRequest(email=f"{role}@example.com", role=role).role == role

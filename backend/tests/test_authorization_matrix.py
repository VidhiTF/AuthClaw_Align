import asyncio
import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import Response

from app.core import auth
from app.api.v1.endpoints import apikeys as apikey_endpoints
from app.api.v1.endpoints import onboarding as onboarding_endpoints
from app.api.v1.endpoints import tenants as tenant_endpoints
from app.api.v1.endpoints import users as user_endpoints
from app.api.v1.endpoints.apikeys import router as apikeys_router
from app.api.v1.endpoints.findings import router as findings_router
from app.api.v1.endpoints.gateways import router as gateways_router
from app.api.v1.endpoints.access_requests import router as access_requests_router
from app.api.v1.endpoints.tenants import router as tenants_router
from app.api.v1.endpoints.users import router as users_router
from app.db.models import APIKey, Tenant, User
from app.schemas.models import (
    APIKeyCreate,
    APIKeyRotate,
    TenantStatusUpdate,
    UserCreate,
    UserInviteRequest,
    OnboardingSignupRequest,
)


def _route(router, path: str, method: str):
    return next(
        route
        for route in router.routes
        if route.path == path and method in route.methods
    )


def _check_dependencies(
    route,
    *,
    role: str,
    scopes: list[str],
    platform_role: str = "NONE",
    is_active: bool = True,
) -> None:
    request = SimpleNamespace(
        state=SimpleNamespace(
            user_role=role,
            tenant_role=role,
            scopes=scopes,
            platform_role=platform_role,
            user_is_active=is_active,
        )
    )
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


def test_public_signup_requires_approved_invitation():
    payload = OnboardingSignupRequest(
        email="applicant@example.com",
        tenant_name="Applicant",
        terms_accepted=True,
        terms_version="2026-07-20",
        privacy_notice_acknowledged=True,
        privacy_notice_version="2026-07-20",
    )

    with pytest.raises(HTTPException) as exc:
        onboarding_endpoints.signup(payload, MagicMock())

    assert exc.value.status_code == 403


def test_direct_user_creation_requires_approved_invitation():
    payload = UserCreate(
        email="applicant@example.com",
        password="CorrectHorse!234",
        role="viewer",
    )

    with pytest.raises(HTTPException) as exc:
        user_endpoints.create_user(MagicMock(), payload, MagicMock())

    assert exc.value.status_code == 403


@pytest.mark.parametrize("role", ["owner", "admin"])
def test_tenant_administrators_cannot_administer_access_requests(role):
    route = _route(
        access_requests_router,
        "/{reference}/status",
        "PATCH",
    )

    with pytest.raises(HTTPException) as exc:
        _check_dependencies(
            route,
            role=role,
            scopes=["admin", "read", "write"],
        )

    assert exc.value.status_code == 403


def test_platform_admin_requires_role_scope_and_active_identity():
    routes = [
        _route(access_requests_router, "/{reference}/status", "PATCH"),
        _route(access_requests_router, "/retention/purge", "POST"),
    ]
    for route in routes:
        _check_dependencies(
            route,
            role="viewer",
            scopes=["platform.admin"],
            platform_role="ADMIN",
        )

    for platform_role, scopes, is_active in [
        ("NONE", ["platform.admin"], True),
        ("ADMIN", ["admin"], True),
        ("ADMIN", ["platform.admin"], False),
    ]:
        for route in routes:
            with pytest.raises(HTTPException) as exc:
                _check_dependencies(
                    route,
                    role="viewer",
                    scopes=scopes,
                    platform_role=platform_role,
                    is_active=is_active,
                )
            assert exc.value.status_code == 403


def test_platform_scope_is_separate_and_tenant_roles_are_unchanged():
    with pytest.raises(ValueError):
        APIKeyCreate(name="platform", scopes=["platform.admin"])
    for role in ("owner", "admin", "developer", "operator", "viewer"):
        assert (
            UserCreate(
                email=f"{role}@example.com",
                password="CorrectHorse!234",
                role=role,
            ).role
            == role
        )
    with pytest.raises(ValueError):
        UserCreate(
            email="platform@example.com",
            password="CorrectHorse!234",
            role="platform_admin",
        )


def test_tenant_admin_cannot_create_platform_key():
    route = _route(apikeys_router, "", "POST")

    with pytest.raises(HTTPException) as exc:
        _check_dependencies(
            route,
            role="admin",
            scopes=["admin"],
        )

    assert exc.value.status_code == 403


def test_tenant_owner_cannot_rotate_or_revoke_platform_key():
    tenant_id = uuid4()
    key = APIKey(
        id=uuid4(),
        tenant_id=tenant_id,
        scopes=["platform.admin"],
        is_active=True,
    )
    request = SimpleNamespace(
        state=SimpleNamespace(
            tenant_id=tenant_id,
            user_id=uuid4(),
            api_key_id=uuid4(),
        )
    )
    db = MagicMock()
    query = db.query.return_value
    query.filter.return_value = query
    query.first.return_value = key

    with pytest.raises(HTTPException) as rotate_error:
        apikey_endpoints.rotate_api_key(
            key.id,
            request,
            APIKeyRotate(),
            db,
        )
    assert rotate_error.value.status_code == 403

    with pytest.raises(HTTPException) as revoke_error:
        apikey_endpoints.revoke_api_key(key.id, request, db)
    assert revoke_error.value.status_code == 403
    db.commit.assert_not_called()


def test_tenant_api_key_listing_excludes_platform_keys():
    db = MagicMock()
    query = db.query.return_value
    query.filter.return_value = query
    query.order_by.return_value = query
    query.all.return_value = []
    request = SimpleNamespace(state=SimpleNamespace(tenant_id=uuid4()))

    assert apikey_endpoints.list_api_keys(request, db=db) == []

    platform_filter = query.filter.call_args_list[1].args[0]
    assert "platform.admin" in platform_filter.compile().params.values()


def test_tenant_owner_cannot_deactivate_platform_admin():
    tenant_id = uuid4()
    platform_admin = User(
        id=uuid4(),
        tenant_id=tenant_id,
        role="viewer",
        platform_role="ADMIN",
        is_active=True,
    )
    request = SimpleNamespace(state=SimpleNamespace(tenant_id=tenant_id))
    db = MagicMock()
    query = db.query.return_value
    query.filter.return_value = query
    query.first.return_value = platform_admin

    with pytest.raises(HTTPException) as exc:
        user_endpoints.delete_user(platform_admin.id, request, db)

    assert exc.value.status_code == 403
    db.commit.assert_not_called()


def test_tenant_admin_cannot_delete_platform_admin():
    route = _route(users_router, "/{id}", "DELETE")

    with pytest.raises(HTTPException) as exc:
        _check_dependencies(route, role="admin", scopes=["admin"])

    assert exc.value.status_code == 403


def _tenant_status_db(tenant, platform_identity):
    db = MagicMock()
    tenant_query = MagicMock()
    platform_query = MagicMock()
    db.query.side_effect = [tenant_query, platform_query]
    tenant_query.filter.return_value.first.return_value = tenant
    platform_query.filter.return_value.first.return_value = platform_identity
    return db


def test_tenant_with_platform_admin_cannot_be_deactivated():
    tenant_id = uuid4()
    tenant = Tenant(id=tenant_id, name="Platform tenant", status="active")
    db = _tenant_status_db(tenant, SimpleNamespace(id=uuid4()))

    with pytest.raises(HTTPException) as exc:
        tenant_endpoints.update_current_tenant_status(
            TenantStatusUpdate(status="disabled"),
            SimpleNamespace(state=SimpleNamespace(tenant_id=tenant_id)),
            db,
        )

    assert exc.value.status_code == 409
    assert tenant.status == "active"
    db.commit.assert_not_called()


def test_normal_tenant_can_still_be_deactivated():
    tenant_id = uuid4()
    tenant = Tenant(id=tenant_id, name="Normal tenant", status="active")
    db = _tenant_status_db(tenant, None)

    result = tenant_endpoints.update_current_tenant_status(
        TenantStatusUpdate(status="disabled"),
        SimpleNamespace(state=SimpleNamespace(tenant_id=tenant_id)),
        db,
    )

    assert result.status == "disabled"
    db.commit.assert_called_once()


def test_tenant_without_platform_admin_can_be_suspended():
    tenant_id = uuid4()
    tenant = Tenant(id=tenant_id, name="Unprotected tenant", status="active")
    db = _tenant_status_db(tenant, None)

    result = tenant_endpoints.update_current_tenant_status(
        TenantStatusUpdate(status="suspended"),
        SimpleNamespace(state=SimpleNamespace(tenant_id=tenant_id)),
        db,
    )

    assert result.status == "suspended"
    db.commit.assert_called_once()


def test_authentication_middleware_exposes_platform_role(monkeypatch):
    resolved = SimpleNamespace(
        id=uuid4(),
        tenant_id=uuid4(),
        scopes=["platform.admin"],
        created_by=uuid4(),
    )
    principal = SimpleNamespace(
        role="viewer",
        platform_role="ADMIN",
        is_active=True,
        tenant_status="active",
    )
    resolved_result = MagicMock()
    resolved_result.first.return_value = resolved
    principal_result = MagicMock()
    principal_result.first.return_value = principal
    db = MagicMock()
    db.execute.side_effect = [
        resolved_result,
        MagicMock(),
        principal_result,
        MagicMock(),
        MagicMock(),
    ]
    monkeypatch.setattr(auth, "SessionLocal", lambda: db)
    monkeypatch.setenv("API_KEY_HASH_SECRET", "test-secret")
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/v1/platform-test",
            "headers": [(b"authorization", b"Bearer platform-key")],
            "query_string": b"",
            "client": ("127.0.0.1", 1234),
            "server": ("testserver", 80),
            "scheme": "http",
        }
    )

    async def call_next(authenticated_request):
        assert authenticated_request.state.tenant_role == "viewer"
        assert authenticated_request.state.platform_role == "ADMIN"
        assert authenticated_request.state.user_is_active is True
        return Response(status_code=204)

    response = asyncio.run(
        auth.AuthMiddleware(MagicMock()).dispatch(request, call_next)
    )

    assert response.status_code == 204


def test_platform_role_migration_is_symmetric(monkeypatch):
    path = (
        Path(__file__).parents[1] / "alembic" / "versions" / "031_add_platform_role.py"
    )
    spec = importlib.util.spec_from_file_location("migration_029", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    bind = MagicMock()
    role_type = MagicMock()
    monkeypatch.setattr(migration.op, "get_bind", lambda: bind)
    monkeypatch.setattr(migration.op, "add_column", MagicMock())
    monkeypatch.setattr(migration.op, "alter_column", MagicMock())
    monkeypatch.setattr(migration.op, "drop_column", MagicMock())
    monkeypatch.setattr(migration.postgresql, "ENUM", lambda *args, **kwargs: role_type)

    migration.upgrade()
    role_type.create.assert_called_once_with(bind, checkfirst=True)
    migration.op.add_column.assert_called_once()
    migration.op.alter_column.assert_called_once_with(
        "users",
        "platform_role",
        server_default=None,
    )

    migration.downgrade()
    migration.op.drop_column.assert_called_once_with("users", "platform_role")
    role_type.drop.assert_called_once_with(bind, checkfirst=True)

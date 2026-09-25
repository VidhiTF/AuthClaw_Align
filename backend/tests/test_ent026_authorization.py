import pytest
import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.core.authorization import (
    Role,
    effective_scopes,
    group_role_mapping,
    role_allows,
)
from app.services.access_review import build_access_review_export
from app.api.v1.endpoints.users import router as users_router
from app.api.v1.endpoints.audit import router as audit_router
from app.api.v1.endpoints.aws import router as aws_router
from app.core.auth import get_tenant_db
from scripts import bootstrap_database_security


def test_role_matrix_is_least_privilege_and_platform_is_separate():
    assert effective_scopes(Role.VIEWER, ["read", "write", "admin"]) == ["read"]
    assert effective_scopes(Role.DEVELOPER, ["read", "write", "admin"]) == ["read", "write"]
    assert effective_scopes(Role.TENANT_ADMINISTRATOR, ["read", "write", "admin"]) == ["admin", "read", "write"]
    assert effective_scopes(Role.PLATFORM_ADMINISTRATOR, ["read", "platform.admin"]) == ["platform.admin"]
    assert effective_scopes(Role.TENANT_ADMINISTRATOR, ["admin"]) == ["admin", "read", "write"]
    assert not role_allows(Role.TENANT_ADMINISTRATOR, "platform.tenant.manage")
    assert not role_allows(Role.PLATFORM_ADMINISTRATOR, "tenant.users.manage")


def test_oidc_mapping_denies_missing_and_ambiguous_groups():
    mapping = {"viewers": "viewer", "operators": "operator"}
    with pytest.raises(PermissionError):
        group_role_mapping([], mapping)
    with pytest.raises(PermissionError):
        group_role_mapping(["viewers", "operators"], mapping)


def test_oidc_mapping_rejects_platform_role():
    with pytest.raises(ValueError):
        group_role_mapping(["platform"], {"platform": "platform_administrator"})


def test_approver_permission_is_distinct_from_tenant_administrator():
    assert role_allows(Role.APPROVER, "tenant.high_risk.approve")
    assert not role_allows(Role.TENANT_ADMINISTRATOR, "tenant.high_risk.approve")
    assert not role_allows(Role.OPERATOR, "tenant.high_risk.approve")


def test_sensitive_database_read_permissions_are_explicit():
    assert role_allows(Role.TENANT_ADMINISTRATOR, "tenant.policies.read")
    assert role_allows(Role.TENANT_ADMINISTRATOR, "tenant.credentials.read")
    assert role_allows(Role.TENANT_ADMINISTRATOR, "tenant.connectors.read")
    assert role_allows(Role.APPROVER, "tenant.approvals.read")
    assert not role_allows(Role.VIEWER, "tenant.policies.read")


def test_ent026_replaces_table_specific_legacy_rls_policies():
    migration = Path(__file__).parents[1] / "alembic" / "versions" / "056_ent026_authorization_contract.py"
    source = migration.read_text(encoding="utf-8")
    legacy_policies = {
        "api_keys": "api_keys_tenant_isolation",
        "users": "users_tenant_isolation",
        "policies": "policies_tenant_isolation",
        "gateway_configs": "gateway_configs_tenant_isolation",
        "provider_credentials": "provider_credentials_tenant_isolation",
        "pending_approvals": "pending_approvals_tenant_isolation",
        "audit_log_metadata": "audit_log_metadata_tenant_isolation",
    }
    for table, policy in legacy_policies.items():
        assert f"DROP POLICY IF EXISTS {policy} ON public.{table}" in source
    assert "authn.authorize_action('tenant.approvals.read')" in source


def test_access_review_export_is_secret_free_and_integrity_protected():
    user = SimpleNamespace(
        id=uuid4(), email="viewer@example.com", is_active=True, role="viewer",
        platform_role="NONE", mfa_enabled=True,
        last_login=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    db = MagicMock()
    users_query = MagicMock()
    users_query.filter.return_value.order_by.return_value.all.return_value = [user]
    keys_query = MagicMock()
    keys_query.filter.return_value.all.return_value = []
    db.query.side_effect = [users_query, keys_query]

    export = build_access_review_export(db, "tenant-1")

    assert export["format"] == "authclaw.access-review.v1"
    assert export["records"][0]["role"] == "viewer"
    assert "key_hash" not in export["records"][0]
    assert len(export["integrity_sha256"]) == 64
    assert export["signing"]["algorithm"] == "Ed25519"
    assert export["signature"]


def test_access_review_route_requires_auditor_or_tenant_administrator():
    route = next(route for route in users_router.routes if route.path == "/access-review")

    def check(role):
        request = SimpleNamespace(state=SimpleNamespace(user_role=role, scopes=["read"]))
        for dependency in route.dependencies:
            dependency.dependency(request)

    check("auditor")
    check("tenant_administrator")
    with pytest.raises(Exception):
        check("viewer")


def test_access_review_http_response_preserves_signed_payload():
    from app.api.v1.endpoints import users as users_endpoints

    user = SimpleNamespace(
        id=uuid4(), email="review@example.invalid", is_active=True, role="auditor",
        platform_role="NONE", mfa_enabled=False, last_login=None,
    )
    db = MagicMock()
    users_query, keys_query = MagicMock(), MagicMock()
    users_query.filter.return_value.order_by.return_value.all.return_value = [user]
    keys_query.filter.return_value.all.return_value = []
    db.query.side_effect = [users_query, keys_query]
    tenant_id = uuid4()
    app = FastAPI()

    @app.middleware("http")
    async def test_principal(request: Request, call_next):
        request.state.user_role = "auditor"
        request.state.scopes = ["read"]
        request.state.tenant_id = tenant_id
        return await call_next(request)

    app.include_router(users_endpoints.router, prefix="/v1/users")
    app.dependency_overrides[get_tenant_db] = lambda: db
    with TestClient(app) as client:
        response = client.get("/v1/users/access-review")
    assert response.status_code == 200
    export = response.json()
    canonical = json.dumps({key: value for key, value in export.items()
        if key not in {"integrity_sha256", "signing", "signature"}},
        sort_keys=True, separators=(",", ":")).encode()
    assert hashlib.sha256(canonical).hexdigest() == export["integrity_sha256"]
    public_key = Ed25519PublicKey.from_public_bytes(
        base64.b64decode(export["signing"]["public_key"]))
    public_key.verify(base64.b64decode(export["signature"]), canonical)


def test_s3_sync_requires_connector_permission_for_every_tenant_role():
    route = next(route for route in aws_router.routes if route.path == "/s3/sync")
    for role in ("viewer", "developer", "operator", "auditor", "approver", "tenant_administrator"):
        request = SimpleNamespace(state=SimpleNamespace(user_role=role, scopes=["read", "write"]))
        if role == "tenant_administrator":
            for dependency in route.dependencies:
                dependency.dependency(request)
        else:
            with pytest.raises(Exception):
                for dependency in route.dependencies:
                    dependency.dependency(request)


def test_audit_reads_require_audit_permission_not_only_read_scope():
    route = next(route for route in audit_router.routes if route.path == "" and "GET" in route.methods)
    viewer = SimpleNamespace(state=SimpleNamespace(user_role="viewer", scopes=["read"]))
    auditor = SimpleNamespace(state=SimpleNamespace(user_role="auditor", scopes=["read"]))
    with pytest.raises(Exception):
        for dependency in route.dependencies:
            dependency.dependency(viewer)
    for dependency in route.dependencies:
        dependency.dependency(auditor)


def test_database_finalizer_preserves_ent026_function_runtime_grants():
    assert {
        "current_role",
        "has_role",
        "authorize_action",
    }.issubset(bootstrap_database_security.AUTHN_RUNTIME_FUNCTIONS)

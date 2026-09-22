import pytest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4

from app.core.authorization import (
    Role,
    effective_scopes,
    group_role_mapping,
    role_allows,
)
from app.services.access_review import build_access_review_export
from app.api.v1.endpoints.users import router as users_router
from app.api.v1.endpoints.audit import router as audit_router
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
    migration = Path(__file__).parents[1] / "alembic" / "versions" / "052_ent026_authorization_contract.py"
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

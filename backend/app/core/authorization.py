"""Canonical tenant authorization contract for the control plane.

The backend is the authority for end-user authorization.  Legacy role names
remain accepted only as explicit compatibility aliases; callers must never be
able to invent a role or permission by changing request headers.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Iterable


class Role(StrEnum):
    VIEWER = "viewer"
    DEVELOPER = "developer"
    OPERATOR = "operator"
    AUDITOR = "auditor"
    APPROVER = "approver"
    TENANT_ADMINISTRATOR = "tenant_administrator"
    PLATFORM_ADMINISTRATOR = "platform_administrator"


ROLE_ALIASES = {
    "owner": Role.TENANT_ADMINISTRATOR.value,
    "admin": Role.TENANT_ADMINISTRATOR.value,
    "tenant_admin": Role.TENANT_ADMINISTRATOR.value,
    "tenant administrator": Role.TENANT_ADMINISTRATOR.value,
    "platform_admin": Role.PLATFORM_ADMINISTRATOR.value,
    "platform administrator": Role.PLATFORM_ADMINISTRATOR.value,
}

TENANT_ROLES = frozenset(role.value for role in Role if role is not Role.PLATFORM_ADMINISTRATOR)
PLATFORM_ROLES = frozenset({Role.PLATFORM_ADMINISTRATOR.value})

# Coarse scopes are retained for API-key compatibility.  This matrix is the
# canonical minimum role requirement for the high-risk control-plane actions.
PERMISSION_ROLES = {
    "tenant.users.read": TENANT_ROLES,
    "tenant.users.manage": frozenset({Role.TENANT_ADMINISTRATOR.value}),
    "tenant.credentials.manage": frozenset({Role.TENANT_ADMINISTRATOR.value}),
    "tenant.policies.manage": frozenset({Role.TENANT_ADMINISTRATOR.value}),
    "tenant.connectors.manage": frozenset({Role.TENANT_ADMINISTRATOR.value}),
    "tenant.audit.read": frozenset({
        Role.AUDITOR.value,
        Role.APPROVER.value,
        Role.TENANT_ADMINISTRATOR.value,
    }),
    "tenant.access_review.export": frozenset({
        Role.AUDITOR.value,
        Role.TENANT_ADMINISTRATOR.value,
    }),
    "tenant.high_risk.approve": frozenset({Role.APPROVER.value}),
    "tenant.approvals.expire": frozenset({
        Role.OPERATOR.value,
        Role.APPROVER.value,
        Role.TENANT_ADMINISTRATOR.value,
    }),
    "tenant.workflow.create": frozenset({
        Role.DEVELOPER.value,
        Role.OPERATOR.value,
        Role.TENANT_ADMINISTRATOR.value,
    }),
    "tenant.workflow.resume": frozenset({
        Role.OPERATOR.value,
        Role.TENANT_ADMINISTRATOR.value,
    }),
    "tenant.workflow.remediate": frozenset({
        Role.OPERATOR.value,
        Role.TENANT_ADMINISTRATOR.value,
    }),
    "tenant.privacy.request": frozenset({Role.TENANT_ADMINISTRATOR.value}),
    "tenant.privacy.verify": frozenset({Role.TENANT_ADMINISTRATOR.value}),
    "tenant.privacy.decide": frozenset({Role.APPROVER.value}),
    "tenant.privacy.execute": frozenset({
        Role.OPERATOR.value,
        Role.TENANT_ADMINISTRATOR.value,
    }),
    "platform.tenant.manage": PLATFORM_ROLES,
}


def normalize_role(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = " ".join(value.strip().replace("-", "_").split()).casefold()
    if normalized in ROLE_ALIASES:
        return ROLE_ALIASES[normalized]
    return normalized if normalized in TENANT_ROLES | PLATFORM_ROLES else None


def validate_tenant_role(value: object) -> str:
    role = normalize_role(value)
    if role not in TENANT_ROLES:
        raise ValueError("Invalid tenant role")
    return role


def allowed_roles(permission: str) -> frozenset[str]:
    try:
        return PERMISSION_ROLES[permission]
    except KeyError as exc:
        raise ValueError(f"Unmapped authorization permission: {permission}") from exc


def role_allows(role: object, permission: str) -> bool:
    normalized = normalize_role(role)
    return normalized is not None and normalized in allowed_roles(permission)


def scopes_for_role(role: object) -> frozenset[str]:
    normalized = normalize_role(role)
    if normalized == Role.TENANT_ADMINISTRATOR.value:
        return frozenset({"read", "write", "admin"})
    if normalized in {Role.OPERATOR.value, Role.APPROVER.value, Role.DEVELOPER.value}:
        return frozenset({"read", "write"})
    if normalized in TENANT_ROLES:
        return frozenset({"read"})
    if normalized in PLATFORM_ROLES:
        return frozenset({"platform.admin"})
    return frozenset()


def effective_scopes(role: object, requested: Iterable[object]) -> list[str]:
    allowed = scopes_for_role(role)
    normalized = {str(scope).strip().lower() for scope in requested if str(scope).strip()}
    effective = {scope for scope in normalized if scope in allowed}
    # Preserve the documented coarse-scope implication for existing admin keys.
    if "admin" in effective:
        effective.update({"read", "write"})
    return sorted(effective)


def group_role_mapping(groups: Iterable[object], mapping: dict[object, object]) -> str:
    """Resolve exactly one mapped group; missing/ambiguous mappings deny."""
    matches: list[str] = []
    for group in groups:
        mapped = mapping.get(str(group))
        if mapped is None:
            continue
        role = normalize_role(mapped)
        if role not in TENANT_ROLES:
            raise ValueError("Group mapping contains an invalid or platform role")
        matches.append(role)
    if len(matches) != 1:
        raise PermissionError("OIDC group mapping is missing or ambiguous")
    return matches[0]

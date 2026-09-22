"""Canonical AuthClaw roles shared by signed and session-based agent requests."""

from __future__ import annotations

from typing import Optional


ROLE_PLATFORM_ADMIN = "platform_administrator"
ROLE_OWNER = "tenant_administrator"
ROLE_ADMIN = "tenant_administrator"
ROLE_COMPLIANCE_OFFICER = "auditor"
ROLE_APPROVER = "approver"
ROLE_AUDITOR = "auditor"
ROLE_DEVELOPER = "developer"
ROLE_OPERATOR = "operator"
ROLE_VIEWER = "viewer"

ALL_ROLES = (
    ROLE_PLATFORM_ADMIN,
    ROLE_OWNER,
    ROLE_DEVELOPER,
    ROLE_OPERATOR,
    ROLE_AUDITOR,
    ROLE_APPROVER,
    ROLE_VIEWER,
)
TENANT_ROLES = frozenset(ALL_ROLES) - {ROLE_PLATFORM_ADMIN}

_ROLE_ALIASES = {
    ROLE_PLATFORM_ADMIN: ROLE_PLATFORM_ADMIN,
    "platform_admin": ROLE_PLATFORM_ADMIN,
    "platform admin": ROLE_PLATFORM_ADMIN,
    "owner": ROLE_OWNER,
    "super_admin": ROLE_OWNER,
    "super admin": ROLE_OWNER,
    "admin": ROLE_ADMIN,
    "security_admin": ROLE_ADMIN,
    "security admin": ROLE_ADMIN,
    "compliance_officer": ROLE_COMPLIANCE_OFFICER,
    "compliance officer": ROLE_COMPLIANCE_OFFICER,
    ROLE_APPROVER: ROLE_APPROVER,
    ROLE_AUDITOR: ROLE_AUDITOR,
    ROLE_DEVELOPER: ROLE_DEVELOPER,
    ROLE_OPERATOR: ROLE_OPERATOR,
    ROLE_VIEWER: ROLE_VIEWER,
}


def normalize_role(value: object) -> Optional[str]:
    """Return a canonical role, or ``None`` for an unknown role."""
    if not isinstance(value, str):
        return None
    key = " ".join(value.strip().replace("-", "_").split()).casefold()
    return _ROLE_ALIASES.get(key)

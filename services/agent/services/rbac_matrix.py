from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence


ROLE_PLATFORM_ADMIN = "Platform Admin"
ROLE_SUPER_ADMIN = "Super Admin"
ROLE_SECURITY_ADMIN = "Security Admin"
ROLE_COMPLIANCE_OFFICER = "Compliance Officer"
ROLE_AUDITOR = "Auditor"
ROLE_DEVELOPER = "Developer"
ROLE_VIEWER = "Viewer"

ALL_ROLES = [
    ROLE_PLATFORM_ADMIN,
    ROLE_SUPER_ADMIN,
    ROLE_SECURITY_ADMIN,
    ROLE_COMPLIANCE_OFFICER,
    ROLE_AUDITOR,
    ROLE_DEVELOPER,
    ROLE_VIEWER,
]

TENANT_ADMIN_ROLES = [ROLE_SUPER_ADMIN, ROLE_SECURITY_ADMIN]
TENANT_READ_ROLES = TENANT_ADMIN_ROLES + [ROLE_COMPLIANCE_OFFICER, ROLE_AUDITOR, ROLE_VIEWER]
GATEWAY_USER_ROLES = TENANT_READ_ROLES + [ROLE_DEVELOPER]

PUBLIC_PATHS = [
    "GET /",
    "GET /docs",
    "GET /docs/oauth2-redirect",
    "GET /openapi.json",
    "GET /redoc",
    "GET /health",
    "GET /health/details",
    "GET /health/ready",
    "GET /.well-known/jwks.json",
    "GET /auth/jwks",
    "GET /auth/oidc/providers",
    "GET /auth/oidc/login",
    "GET /auth/oidc/callback",
    "POST /auth/oidc/callback",
    "POST /auth/login",
    "POST /auth/register",
    "POST /auth/verify-email",
    "POST /auth/verify-domain",
    "POST /auth/password/reset-request",
    "POST /auth/password/reset-confirm",
    "POST /auth/mfa/reset-request",
    "POST /auth/mfa/reset-confirm",
    "POST /auth/verify-otp",
    "POST /auth/refresh",
    "POST /auth/logout",
    "POST /audit/export/verify",
    "GET /trust/public",
    "GET /trust/public/health",
]


@dataclass(frozen=True)
class EndpointRule:
    method: str
    pattern: str
    roles: Sequence[str]
    permission: str
    tenant_required: bool = True
    audit_required: bool = True
    description: str = ""

    def matches(self, method: str, path: str) -> bool:
        if self.method != "*" and method.upper() != self.method:
            return False
        normalized = _normalize_path_template(path)
        rule_pattern = _normalize_path_template(self.pattern)
        return fnmatch.fnmatch(normalized, rule_pattern)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "pattern": self.pattern,
            "roles": list(self.roles),
            "permission": self.permission,
            "tenant_required": self.tenant_required,
            "audit_required": self.audit_required,
            "description": self.description,
        }


ENDPOINT_RULES: List[EndpointRule] = [
    EndpointRule("*", "/platform/*", [ROLE_PLATFORM_ADMIN], "platform:admin", False, True, "Platform-wide tenant administration."),
    EndpointRule("*", "/identity/*", TENANT_ADMIN_ROLES, "identity:manage", True, True, "Tenant OIDC and IdP administration."),
    EndpointRule("GET", "/security/posture", TENANT_READ_ROLES, "security:read", True, True, "Security posture view."),
    EndpointRule("GET", "/security/*", TENANT_ADMIN_ROLES, "security:admin", True, True, "Security readiness administration."),
    EndpointRule("*", "/providers*", TENANT_ADMIN_ROLES, "providers:manage", True, True, "Provider credential lifecycle."),
    EndpointRule("*", "/routes*", TENANT_ADMIN_ROLES, "gateway-routes:manage", True, True, "Gateway route lifecycle."),
    EndpointRule("GET", "/gateway/requests*", TENANT_READ_ROLES + [ROLE_DEVELOPER], "gateway:read", True, True, "Gateway request explorer."),
    EndpointRule("GET", "/gateway/approvals*", TENANT_READ_ROLES, "approvals:read", True, True, "Gateway approval visibility."),
    EndpointRule("*", "/gateway/documents/*", GATEWAY_USER_ROLES, "documents:redact", True, True, "Gateway document redaction."),
    EndpointRule("*", "/gateway/chat", GATEWAY_USER_ROLES, "gateway:invoke", True, True, "Gateway chat invocation."),
    EndpointRule("*", "/chat*", GATEWAY_USER_ROLES, "chat:use", True, False, "Tenant chat sessions."),
    EndpointRule("*", "/sessions*", GATEWAY_USER_ROLES, "chat:use", True, False, "Legacy tenant chat session aliases."),
    EndpointRule("*", "/v1/chat/completions", GATEWAY_USER_ROLES, "gateway:invoke", True, True, "OpenAI-compatible gateway invocation."),
    EndpointRule("GET", "/approvals*", TENANT_READ_ROLES, "approvals:read", True, True, "Approval queue read."),
    EndpointRule("POST", "/approve/*", TENANT_ADMIN_ROLES, "approvals:approve", True, True, "HITL approval."),
    EndpointRule("POST", "/reject/*", TENANT_ADMIN_ROLES, "approvals:reject", True, True, "HITL rejection."),
    EndpointRule("POST", "/execute/*", TENANT_ADMIN_ROLES, "approvals:execute", True, True, "HITL execution."),
    EndpointRule("POST", "/test/*", [ROLE_SUPER_ADMIN], "testing:local", True, True, "Local test utilities."),
    EndpointRule("GET", "/audit*", [ROLE_SUPER_ADMIN, ROLE_SECURITY_ADMIN, ROLE_COMPLIANCE_OFFICER, ROLE_AUDITOR], "audit:read", True, True, "Audit and signed export read."),
    EndpointRule("POST", "/audit/export/verify", ALL_ROLES, "audit:verify", False, False, "Public export verification."),
    EndpointRule("*", "/policies*", [ROLE_SUPER_ADMIN, ROLE_SECURITY_ADMIN, ROLE_COMPLIANCE_OFFICER], "policies:manage", True, True, "Policy lifecycle."),
    EndpointRule("*", "/policy/bundles*", [ROLE_SUPER_ADMIN, ROLE_SECURITY_ADMIN, ROLE_COMPLIANCE_OFFICER], "policy-bundles:manage", True, True, "OPA policy bundle lifecycle."),
    EndpointRule("POST", "/internal/policy/evaluate", GATEWAY_USER_ROLES, "policy:evaluate", True, True, "Gateway policy preflight."),
    EndpointRule("*", "/rag*", [ROLE_SUPER_ADMIN, ROLE_SECURITY_ADMIN, ROLE_COMPLIANCE_OFFICER], "rag:manage", True, True, "Regulatory RAG corpus."),
    EndpointRule("*", "/documents*", [ROLE_SUPER_ADMIN, ROLE_SECURITY_ADMIN, ROLE_COMPLIANCE_OFFICER], "documents:manage", True, True, "Document intelligence."),
    EndpointRule("*", "/compliance*", [ROLE_SUPER_ADMIN, ROLE_SECURITY_ADMIN, ROLE_COMPLIANCE_OFFICER, ROLE_AUDITOR], "compliance:read", True, True, "Framework scoring and controls."),
    EndpointRule("*", "/evidence*", [ROLE_SUPER_ADMIN, ROLE_SECURITY_ADMIN, ROLE_COMPLIANCE_OFFICER, ROLE_AUDITOR], "evidence:read", True, True, "Evidence vault."),
    EndpointRule("*", "/auditor/*", [ROLE_SUPER_ADMIN, ROLE_SECURITY_ADMIN, ROLE_COMPLIANCE_OFFICER, ROLE_AUDITOR], "audit:export", True, True, "Auditor packages."),
    EndpointRule("*", "/access-control/*", [ROLE_SUPER_ADMIN, ROLE_SECURITY_ADMIN], "rbac:manage", True, True, "Tenant RBAC user administration."),
    EndpointRule("*", "/tenants*", TENANT_ADMIN_ROLES, "tenant:manage", True, True, "Tenant settings."),
    EndpointRule("*", "/tenant/plan*", TENANT_ADMIN_ROLES, "tenant-plan:manage", True, True, "Tenant plan and quota management."),
    EndpointRule("*", "/keys*", TENANT_ADMIN_ROLES + [ROLE_DEVELOPER], "api-keys:manage", True, True, "Tenant API key lifecycle."),
    EndpointRule("*", "/reports/*", [ROLE_SUPER_ADMIN, ROLE_SECURITY_ADMIN, ROLE_COMPLIANCE_OFFICER, ROLE_AUDITOR], "reports:read", True, True, "Governance reports."),
    EndpointRule("*", "/cloud/connectors/*", TENANT_ADMIN_ROLES, "connectors:manage", True, True, "Cloud connector sync/status."),
    EndpointRule("*", "/analytics/*", TENANT_READ_ROLES, "analytics:read", True, True, "Governance analytics."),
    EndpointRule("*", "/remediation/*", TENANT_ADMIN_ROLES + [ROLE_COMPLIANCE_OFFICER], "remediation:manage", True, True, "Remediation runtime."),
    EndpointRule("*", "/redteam/*", [ROLE_SUPER_ADMIN, ROLE_SECURITY_ADMIN, ROLE_COMPLIANCE_OFFICER, ROLE_AUDITOR], "redteam:read", True, True, "Red-team probe history and reports."),
    EndpointRule("GET", "/metrics", TENANT_READ_ROLES + [ROLE_DEVELOPER], "metrics:read", True, True, "Tenant metrics and observability."),
    EndpointRule("POST", "/observability/*", TENANT_ADMIN_ROLES, "observability:operate", True, True, "Event pipeline operations."),
    EndpointRule("GET", "/trust/public", ALL_ROLES, "trust:public", False, False, "Public signed Trust Center state."),
    EndpointRule("GET", "/health*", ALL_ROLES, "health:read", False, False, "Health checks."),
    EndpointRule("GET", "/", ALL_ROLES, "health:read", False, False, "Root liveness."),
    EndpointRule("*", "/auth/*", ALL_ROLES, "auth:public-or-session", False, False, "Authentication and session lifecycle."),
]


def _normalize_path_template(path: str) -> str:
    path = path or "/"
    path = re.sub(r"\{[^/]+\}", "*", path)
    if path != "/" and path.endswith("/"):
        path = path[:-1]
    return path


def is_public_endpoint(method: str, path: str) -> bool:
    target = f"{method.upper()} {_normalize_path_template(path)}"
    return any(fnmatch.fnmatch(target, pattern) for pattern in PUBLIC_PATHS)


def resolve_rule(method: str, path: str) -> Optional[EndpointRule]:
    for rule in ENDPOINT_RULES:
        if rule.matches(method.upper(), path):
            return rule
    return None


def role_allowed(role: Optional[str], method: str, path: str) -> bool:
    if is_public_endpoint(method, path):
        return True
    rule = resolve_rule(method, path)
    if not rule:
        return False
    if role == ROLE_PLATFORM_ADMIN:
        return True
    return (role or "") in set(rule.roles)


def endpoint_inventory(app: Any) -> List[Dict[str, Any]]:
    inventory: List[Dict[str, Any]] = []
    for route in getattr(app, "routes", []):
        methods = sorted(m for m in getattr(route, "methods", []) if m not in {"HEAD", "OPTIONS"})
        path = getattr(route, "path", "")
        if not methods or not path:
            continue
        for method in methods:
            rule = resolve_rule(method, path)
            public = is_public_endpoint(method, path)
            inventory.append(
                {
                    "method": method,
                    "path": path,
                    "public": public,
                    "covered": bool(rule or public),
                    "roles": list(rule.roles) if rule else ([] if public else []),
                    "permission": rule.permission if rule else ("public" if public else "unmapped"),
                    "tenant_required": bool(rule.tenant_required) if rule else False,
                    "audit_required": bool(rule.audit_required) if rule else False,
                }
            )
    inventory.sort(key=lambda item: (item["path"], item["method"]))
    return inventory


def coverage_report(app: Any) -> Dict[str, Any]:
    inventory = endpoint_inventory(app)
    unmapped = [item for item in inventory if not item["covered"]]
    protected = [item for item in inventory if not item["public"]]
    role_matrix = []
    for item in inventory:
        role_matrix.append(
            {
                **item,
                "role_access": {role: role_allowed(role, item["method"], item["path"]) for role in ALL_ROLES},
            }
        )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "roles": ALL_ROLES,
        "total_endpoints": len(inventory),
        "protected_endpoints": len(protected),
        "public_endpoints": len(inventory) - len(protected),
        "mapped_endpoints": len(inventory) - len(unmapped),
        "unmapped_endpoints": unmapped,
        "matrix": role_matrix,
        "complete": not unmapped,
    }


def enforce_request_access(method: str, path: str, payload: Dict[str, Any]) -> None:
    if is_public_endpoint(method, path):
        return
    role = payload.get("role") if payload else None
    if not role_allowed(role, method, path):
        from fastapi import HTTPException

        raise HTTPException(status_code=403, detail="Role is not authorized for this endpoint.")
    rule = resolve_rule(method, path)
    if rule and rule.tenant_required and not payload.get("tenant_id"):
        from fastapi import HTTPException

        raise HTTPException(status_code=401, detail="Session token is missing tenant scope.")


def matrix_markdown(app: Any) -> str:
    report = coverage_report(app)
    lines = [
        "# AuthClaw RBAC Permission Matrix",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "| Method | Path | Public | Permission | Roles | Tenant | Audit |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in report["matrix"]:
        roles = ", ".join(item["roles"]) if item["roles"] else ("public" if item["public"] else "UNMAPPED")
        lines.append(
            f"| {item['method']} | `{item['path']}` | {item['public']} | `{item['permission']}` | {roles} | {item['tenant_required']} | {item['audit_required']} |"
        )
    if report["unmapped_endpoints"]:
        lines.extend(["", "## Unmapped Endpoints", ""])
        for item in report["unmapped_endpoints"]:
            lines.append(f"- `{item['method']} {item['path']}`")
    return "\n".join(lines) + "\n"


def report_json(app: Any) -> str:
    return json.dumps(coverage_report(app), indent=2, default=str)

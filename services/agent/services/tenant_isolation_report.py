from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from sqlalchemy import text

from database import engine


SYSTEM_TABLES_WITHOUT_TENANT = {
    "tenants",
    "onboarding_registrations",
    "regulatory_corpus_versions",
    "compliance_control_catalog",
    "ha_status",
    "pentest_simulations",
    "redteam_attacks",
    "compliance_drift_alerts",
    "compliance_score_history",
    "ephemeral_workers",
    "event_consumer_checkpoints",
    "user_roles",
}

SYSTEM_TABLE_EXEMPTION_REASONS = {
    "tenants": "Tenant registry root table.",
    "onboarding_registrations": "Pre-tenant onboarding state; tenant_id may be null until activation.",
    "regulatory_corpus_versions": "Global regulatory corpus metadata.",
    "compliance_control_catalog": "Global SOC2/GDPR/HIPAA control catalog.",
    "ha_status": "Global availability/readiness summary.",
    "pentest_simulations": "Global release-readiness simulation registry.",
    "redteam_attacks": "Global red-team harness catalog.",
    "compliance_drift_alerts": "Legacy aggregate drift history; tenant-scoped control changes live in compliance_score_changes.",
    "compliance_score_history": "Legacy aggregate score history; tenant-scoped scores live in compliance_control_scores.",
    "ephemeral_workers": "Legacy scaffold table; tenant-scoped runtime uses remediation_worker_runs and worker_credential_leases.",
    "event_consumer_checkpoints": "Global consumer-group checkpoint state, not customer payload.",
    "user_roles": "Legacy global role catalog; tenant users and permissions live in tenant_users.",
}


def tenant_isolation_report() -> Dict[str, Any]:
    with engine.connect() as conn:
        tables = conn.execute(
            text(
                """
                SELECT c.relname AS table_name,
                       COALESCE(BOOL_OR(a.attname = 'tenant_id'), false) AS has_tenant_id,
                       c.relrowsecurity AS rls_enabled,
                       c.relforcerowsecurity AS rls_forced
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                LEFT JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
                WHERE n.nspname = 'public'
                  AND c.relkind = 'r'
                GROUP BY c.relname, c.relrowsecurity, c.relforcerowsecurity
                ORDER BY c.relname
                """
            )
        ).fetchall()
        policy_rows = conn.execute(
            text(
                """
                SELECT tablename, policyname
                FROM pg_policies
                WHERE schemaname = 'public'
                ORDER BY tablename, policyname
                """
            )
        ).fetchall()

    policies: Dict[str, List[str]] = {}
    for row in policy_rows:
        policies.setdefault(row.tablename, []).append(row.policyname)

    covered = []
    gaps = []
    for row in tables:
        table_name = row.table_name
        exempt = table_name in SYSTEM_TABLES_WITHOUT_TENANT
        item = {
            "table": table_name,
            "has_tenant_id": bool(row.has_tenant_id),
            "rls_enabled": bool(row.rls_enabled),
            "rls_forced": bool(row.rls_forced),
            "policies": policies.get(table_name, []),
            "system_exempt": exempt,
            "exemption_reason": SYSTEM_TABLE_EXEMPTION_REASONS.get(table_name, ""),
        }
        item["protected"] = exempt or (
            item["has_tenant_id"]
            and item["rls_enabled"]
            and item["rls_forced"]
            and bool(item["policies"])
        )
        (covered if item["protected"] else gaps).append(item)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_tables": len(tables),
        "protected_tables": len(covered),
        "gap_count": len(gaps),
        "complete": len(gaps) == 0,
        "tables": covered + gaps,
        "gaps": gaps,
    }


def tenant_isolation_markdown() -> str:
    report = tenant_isolation_report()
    lines = [
        "# Tenant Isolation Coverage Report",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "| Table | tenant_id | RLS | Forced | Policies | Protected |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in report["tables"]:
        policies = ", ".join(item["policies"]) if item["policies"] else ("system-exempt" if item["system_exempt"] else "")
        lines.append(
            f"| `{item['table']}` | {item['has_tenant_id']} | {item['rls_enabled']} | {item['rls_forced']} | {policies} | {item['protected']} |"
        )
    if report["gaps"]:
        lines.extend(["", "## Gaps", ""])
        for item in report["gaps"]:
            lines.append(f"- `{item['table']}`")
    return "\n".join(lines) + "\n"

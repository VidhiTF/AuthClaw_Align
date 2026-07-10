from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

from services.secret_manager import SecretManager
from services.tenant_isolation_report import tenant_isolation_report


REQUIRED_TERRAFORM_RESOURCES = {
    "ecs": "aws_ecs_service",
    "alb": "aws_lb",
    "rds": "aws_db_instance",
    "redis": "aws_elasticache_replication_group",
    "msk_kafka": "aws_msk_cluster",
    "cloudwatch": "aws_cloudwatch_log_group",
    "s3": "aws_s3_bucket",
    "iam": "aws_iam_role",
    "route53": "aws_route53_record",
    "secrets_manager": "aws_secretsmanager_secret",
    "kms": "aws_kms_key",
    "opa": "authclaw-opa",
}


def secret_management_readiness() -> Dict[str, Any]:
    manager = SecretManager()
    health = manager.health_check()
    policy = manager.selection_policy()
    production = os.getenv("AUTHCLAW_ENV", "development").lower() in {"production", "prod"}
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "backend": health.backend,
        "healthy": health.healthy,
        "message": health.message,
        "selection_policy": policy,
        "supports_local_aes_gcm": True,
        "supports_aws_kms": True,
        "supports_hashicorp_vault": True,
        "rotation_supported": policy.get("rotation_supported"),
        "customer_managed_keys_configured": bool(
            os.getenv("AUTHCLAW_AWS_KMS_KEY_ID")
            or os.getenv("AWS_KMS_KEY_ID")
            or os.getenv("VAULT_TRANSIT_KEY")
        ),
        "production_ready": (not production or health.healthy)
        and (not production or health.backend not in {"local", "local_env"}),
    }


def disaster_recovery_readiness() -> Dict[str, Any]:
    required = {
        "dr_runbook": Path("deployment/aws/dr-runbook.md").exists() or Path("docs/phase10_multiregion_dr.md").exists(),
        "dr_validation_script": Path("scripts/dr_validation.py").exists(),
        "multiregion_terraform": Path("deployment/terraform/multiregion_dr.tf").exists(),
        "backup_controls": "aws_backup_vault" in _read_tree_text("deployment/terraform"),
        "route53_failover_controls": "aws_route53_record" in _read_tree_text("deployment/terraform"),
    }
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "checks": required,
        "complete_for_code": all(required.values()),
        "requires_live_dr_drill": True,
        "non_code_gaps": [
            "Real two-region deployment",
            "Actual failover drill evidence",
            "Measured RTO/RPO from production-like infrastructure",
        ],
    }


def terraform_coverage(root: str = "deployment/terraform") -> Dict[str, Any]:
    text = _read_tree_text(root)
    checks = {
        name: (needle in text)
        for name, needle in REQUIRED_TERRAFORM_RESOURCES.items()
    }
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root": root,
        "checks": checks,
        "complete": all(checks.values()),
        "missing": [name for name, ok in checks.items() if not ok],
    }


def production_readiness_report(app: Any = None) -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "secrets": secret_management_readiness(),
        "tenant_isolation": tenant_isolation_report(),
        "dr": disaster_recovery_readiness(),
        "terraform": terraform_coverage(),
    }
    if app is not None:
        from services.rbac_matrix import coverage_report

        report["rbac"] = coverage_report(app)
    report["non_code_gaps"] = [
        "External penetration testing",
        "SOC2 audit",
        "HIPAA certification",
        "GDPR certification",
        "Real AWS two-region deployment",
        "Actual failover drill evidence",
        "Live uptime proof",
        "Production benchmark against real customer providers",
        "External SDK publication",
    ]
    report["complete_for_code"] = all(
        [
            report["secrets"]["production_ready"] or os.getenv("AUTHCLAW_ENV", "development").lower() not in {"production", "prod"},
            report["tenant_isolation"]["complete"],
            report["dr"]["complete_for_code"],
            report["terraform"]["complete"],
            report.get("rbac", {}).get("complete", True),
        ]
    )
    return report


def _read_tree_text(root: str) -> str:
    base = Path(root)
    if not base.exists():
        return ""
    chunks: List[str] = []
    for path in base.rglob("*"):
        if path.is_file() and path.suffix in {".tf", ".tfvars", ".md", ".json"}:
            chunks.append(path.read_text(encoding="utf-8", errors="ignore"))
    return "\n".join(chunks)


def report_json(report: Dict[str, Any]) -> str:
    return json.dumps(report, indent=2, default=str)

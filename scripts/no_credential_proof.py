#!/usr/bin/env python3
"""Validate no-credential/no-paid-dependency proof evidence."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REQUIRED_LOCAL_PROOFS = {
    "tier_based_tenant_limits",
    "gateway_policy_rate_limits",
    "background_worker_throttling",
    "soc2_evidence_automation_structure",
    "audit_ready_release_checklist",
    "red_team_pass_fail_thresholds",
    "security_runbooks",
    "control_evidence_pipeline",
    "cloud_connector_contract_tests",
    "remediation_workflow_proof",
    "route53_failover_simulation",
    "rto_rpo_calculation_logic",
    "latency_proof_harness",
    "tenant_isolation_proof",
    "cryptographic_audit_export_proof",
}

REQUIRED_SIMULATION_PROOFS = {
    "route53_failover",
    "multi_region_service_recovery",
    "database_promotion_workflow",
    "cloud_remediation",
    "kms_vault_envelope_encryption",
    "llm_red_team_evaluation",
}

REQUIRED_CHECKLIST = {
    "tests",
    "scans",
    "migrations",
    "rollback_notes",
    "dr_notes",
    "signed_audit_export_verification",
    "red_team_thresholds",
    "tenant_isolation",
}

ALLOWED_LABELS = {"local-proof", "simulation-proof", "credential-required", "third-party-required"}


def _parse_time(value: object, field: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be an ISO-8601 timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)


def _section(payload: dict[str, Any], field: str) -> dict[str, Any]:
    value = payload.get(field)
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    return value


def _path_exists(repo_root: Path, path: str) -> bool:
    return (repo_root / path).exists()


def _validate_proof_map(
    payload: dict[str, Any],
    field: str,
    required: set[str],
    expected_label: str,
    repo_root: Path,
) -> list[str]:
    errors: list[str] = []
    proofs = _section(payload, field)
    missing = sorted(required - set(proofs))
    if missing:
        errors.append(f"{field} missing proofs: {', '.join(missing)}")

    for name, proof in proofs.items():
        if not isinstance(proof, dict):
            errors.append(f"{field}.{name} must be an object")
            continue
        if proof.get("label") not in ALLOWED_LABELS:
            errors.append(f"{field}.{name}.label must be one of {sorted(ALLOWED_LABELS)}")
        if name in required and proof.get("label") != expected_label:
            errors.append(f"{field}.{name}.label must be {expected_label}")
        if proof.get("status") != "pass":
            errors.append(f"{field}.{name}.status must be pass")
        for bucket in ("evidence", "tests"):
            paths = proof.get(bucket, [])
            if not isinstance(paths, list) or not paths:
                errors.append(f"{field}.{name}.{bucket} must be a non-empty list")
                continue
            for path in paths:
                if not isinstance(path, str) or not _path_exists(repo_root, path):
                    errors.append(f"{field}.{name}.{bucket} path missing: {path}")
    return errors


def validate(payload: dict[str, Any], repo_root: Path) -> list[str]:
    errors: list[str] = []

    try:
        if not isinstance(payload.get("release_id"), str) or not payload["release_id"].strip():
            errors.append("release_id must be a non-empty string")
        _parse_time(payload.get("generated_at"), "generated_at")
    except ValueError as exc:
        errors.append(str(exc))

    try:
        tier_limits = _section(payload, "tier_limits")
        ordered = [tier_limits[tier]["requests_per_minute"] for tier in ("starter", "pro", "enterprise")]
        if ordered != sorted(ordered) or len(set(ordered)) != 3:
            errors.append("tier_limits requests_per_minute must increase starter < pro < enterprise")
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"tier_limits invalid: {exc}")

    try:
        throttles = _section(payload, "worker_throttles")
        for job in ("scan", "evidence", "red_team", "remediation"):
            if not isinstance(throttles.get(job), int) or throttles[job] <= 0:
                errors.append(f"worker_throttles.{job} must be a positive integer")
    except ValueError as exc:
        errors.append(str(exc))

    try:
        red_team = _section(payload, "red_team_thresholds")
        if red_team.get("probe_count", 0) < 4:
            errors.append("red_team_thresholds.probe_count must be at least 4")
        for field in ("failed_critical", "failed_high", "max_risk_score"):
            if red_team.get(field) != 0:
                errors.append(f"red_team_thresholds.{field} must be 0")
    except ValueError as exc:
        errors.append(str(exc))

    try:
        checklist = _section(payload, "audit_ready_release_checklist")
        for item in sorted(REQUIRED_CHECKLIST):
            if checklist.get(item) is not True:
                errors.append(f"audit_ready_release_checklist.{item} must be true")
    except ValueError as exc:
        errors.append(str(exc))

    try:
        errors.extend(_validate_proof_map(payload, "local_proofs", REQUIRED_LOCAL_PROOFS, "local-proof", repo_root))
        errors.extend(_validate_proof_map(payload, "simulation_proofs", REQUIRED_SIMULATION_PROOFS, "simulation-proof", repo_root))
    except ValueError as exc:
        errors.append(str(exc))

    return errors


def write_summary(payload: dict[str, Any], output: Path) -> None:
    local_count = len(payload.get("local_proofs", {}))
    simulation_count = len(payload.get("simulation_proofs", {}))
    output.write_text(
        "\n".join(
            [
                "# No-Credential Proof Summary",
                "",
                f"- Release: `{payload.get('release_id', '')}`",
                f"- Local proofs: {local_count}",
                f"- Simulation proofs: {simulation_count}",
                "- Live cloud, SOC 2 attestation, and external pentest claims remain excluded.",
                "",
            ]
        ),
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args()

    payload = json.loads(args.evidence.read_text(encoding="utf-8"))
    errors = validate(payload, args.repo_root)
    if errors:
        print("No-credential proof rejected:")
        for error in errors:
            print(f"  - {error}")
        return 1
    if args.summary:
        write_summary(payload, args.summary)
    print("No-credential proof OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

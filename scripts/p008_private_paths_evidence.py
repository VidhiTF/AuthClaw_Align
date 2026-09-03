#!/usr/bin/env python3
"""Validate P0-08 private AWS-service path staging evidence."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


ALWAYS_ON_INTERFACE_ENDPOINTS = {
    "ecr_api",
    "ecr_dkr",
    "kms",
    "logs",
    "secretsmanager",
    "sts",
}
FOUNDATION_RESOURCES = {"aws_eip", "aws_nat_gateway", "aws_route_table", "aws_subnet", "aws_vpc"}
DENIAL_TARGETS = {"ecr_repository", "log_group", "secret", "kms_key", "sts_role", "s3_bucket"}
PLACEHOLDER = re.compile(r"^(?:replace[-_ ]with|pending|todo|tbd)(?:$|[-_ :])", re.IGNORECASE)


def _section(payload: dict[str, Any], name: str, errors: list[str]) -> dict[str, Any]:
    value = payload.get(name)
    if not isinstance(value, dict):
        errors.append(f"{name} must be an object")
        return {}
    return value


def _require_true(payload: dict[str, Any], field: str, errors: list[str], prefix: str) -> None:
    if payload.get(field) is not True:
        errors.append(f"{prefix}.{field} must be true")


def _require_text(payload: dict[str, Any], field: str, errors: list[str], prefix: str) -> None:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{prefix}.{field} must be a non-empty string")
    elif PLACEHOLDER.match(value.strip()):
        errors.append(f"{prefix}.{field} must not contain placeholder evidence")


def _require_timestamp(
    payload: dict[str, Any], field: str, errors: list[str], prefix: str
) -> datetime | None:
    value = payload.get(field)
    if not isinstance(value, str) or not value:
        errors.append(f"{prefix}.{field} must be an ISO-8601 timestamp")
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"{prefix}.{field} must be an ISO-8601 timestamp")
        return None
    if parsed.tzinfo is None:
        errors.append(f"{prefix}.{field} must include a timezone")
        return None
    return parsed


def validate_evidence(payload: dict[str, Any], *, audit_transport: str) -> list[str]:
    """Return every production-blocking defect in a P0-08 evidence bundle."""
    errors: list[str] = []
    if audit_transport not in {"kafka", "sqs_fifo"}:
        return ["audit_transport must be kafka or sqs_fifo"]

    deployment = _section(payload, "deployment", errors)
    _require_text(deployment, "account_id", errors, "deployment")
    if isinstance(deployment.get("account_id"), str) and not re.fullmatch(r"\d{12}", deployment["account_id"]):
        errors.append("deployment.account_id must be a 12-digit AWS account ID")
    if deployment.get("environment") != "staging":
        errors.append("deployment.environment must be staging")
    if deployment.get("audit_transport") != audit_transport:
        errors.append("deployment.audit_transport must match --audit-transport")
    _require_text(deployment, "region", errors, "deployment")
    _require_text(deployment, "source_commit", errors, "deployment")
    if isinstance(deployment.get("source_commit"), str) and not re.fullmatch(
        r"[0-9a-fA-F]{7,64}", deployment["source_commit"]
    ):
        errors.append("deployment.source_commit must be a Git commit hash")
    started_at = _require_timestamp(deployment, "started_at", errors, "deployment")
    completed_at = _require_timestamp(deployment, "completed_at", errors, "deployment")
    if started_at and completed_at and completed_at < started_at:
        errors.append("deployment.completed_at must not precede deployment.started_at")

    plan = _section(payload, "terraform_plan", errors)
    _require_true(plan, "reviewed", errors, "terraform_plan")
    _require_true(plan, "applied_from_saved_plan", errors, "terraform_plan")
    replacements = plan.get("replacement_resource_types")
    if not isinstance(replacements, list):
        errors.append("terraform_plan.replacement_resource_types must be a list")
    else:
        forbidden = sorted(FOUNDATION_RESOURCES.intersection(replacements))
        if forbidden:
            errors.append(f"terraform plan replaces protected resources: {', '.join(forbidden)}")
    _require_text(plan, "plan_artifact", errors, "terraform_plan")
    _require_text(plan, "reviewer", errors, "terraform_plan")

    endpoints = _section(payload, "endpoints", errors)
    interface = endpoints.get("interface")
    expected = ALWAYS_ON_INTERFACE_ENDPOINTS | ({"sqs"} if audit_transport == "sqs_fifo" else set())
    if not isinstance(interface, dict):
        errors.append("endpoints.interface must be an object keyed by endpoint service")
        interface = {}
    actual = set(interface)
    if actual != expected:
        errors.append(
            "interface endpoint set must be exactly "
            + ", ".join(sorted(expected))
            + f"; found {', '.join(sorted(actual)) or 'none'}"
        )
    for service in sorted(expected.intersection(actual)):
        endpoint = interface[service]
        if not isinstance(endpoint, dict):
            errors.append(f"endpoints.interface.{service} must be an object")
            continue
        if endpoint.get("state") != "available":
            errors.append(f"endpoints.interface.{service}.state must be available")
        _require_true(endpoint, "private_dns", errors, f"endpoints.interface.{service}")
        _require_true(endpoint, "dns_resolves_to_endpoint_enis", errors, f"endpoints.interface.{service}")
        _require_true(endpoint, "explicit_policy", errors, f"endpoints.interface.{service}")
        _require_true(endpoint, "tls_deny", errors, f"endpoints.interface.{service}")
        az_count = endpoint.get("availability_zone_count")
        if not isinstance(az_count, int) or az_count < 2:
            errors.append(f"endpoints.interface.{service}.availability_zone_count must be at least 2")

    gateway = endpoints.get("gateway")
    if not isinstance(gateway, dict) or set(gateway) != {"s3"}:
        errors.append("endpoints.gateway must contain only s3")
    else:
        s3 = gateway["s3"]
        if not isinstance(s3, dict):
            errors.append("endpoints.gateway.s3 must be an object")
        else:
            if s3.get("state") != "available":
                errors.append("endpoints.gateway.s3.state must be available")
            for field in ("all_private_route_tables", "route_verified", "explicit_policy", "tls_deny"):
                _require_true(s3, field, errors, "endpoints.gateway.s3")

    tasks = _section(payload, "task_probes", errors)
    for field in ("image_pull", "secret_injection", "cloudwatch_logs", "kms", "s3", "sts"):
        _require_true(tasks, field, errors, "task_probes")
    sqs_result = tasks.get("sqs")
    if audit_transport == "sqs_fifo" and sqs_result is not True:
        errors.append("task_probes.sqs must be true for sqs_fifo")
    if audit_transport == "kafka" and sqs_result != "not_selected":
        errors.append('task_probes.sqs must be "not_selected" for kafka')
    _require_true(tasks, "no_static_aws_credentials", errors, "task_probes")
    _require_true(tasks, "regional_sts", errors, "task_probes")

    nat = _section(payload, "nat_outage", errors)
    for field in ("approved", "routes_unavailable_during_probes", "routes_restored", "restore_verified"):
        _require_true(nat, field, errors, "nat_outage")
    _require_text(nat, "change_ticket", errors, "nat_outage")
    disabled_at = _require_timestamp(nat, "disabled_at", errors, "nat_outage")
    restored_at = _require_timestamp(nat, "restored_at", errors, "nat_outage")
    if disabled_at and restored_at and restored_at < disabled_at:
        errors.append("nat_outage.restored_at must not precede nat_outage.disabled_at")
    if started_at and disabled_at and disabled_at < started_at:
        errors.append("nat_outage.disabled_at must be within the deployment evidence window")
    if completed_at and restored_at and restored_at > completed_at:
        errors.append("nat_outage.restored_at must be within the deployment evidence window")

    denials = _section(payload, "denial_tests", errors)
    expected_denials = DENIAL_TARGETS | ({"sqs_queue"} if audit_transport == "sqs_fifo" else set())
    if set(denials) != expected_denials:
        errors.append("denial_tests must contain exactly: " + ", ".join(sorted(expected_denials)))
    for target in sorted(expected_denials.intersection(denials)):
        if denials[target] is not True:
            errors.append(f"denial_tests.{target} must be true")

    flow = _section(payload, "flow_logs", errors)
    _require_true(flow, "covered_calls_avoided_nat", errors, "flow_logs")
    unexplained = flow.get("unexplained_public_aws_destinations")
    if unexplained != []:
        errors.append("flow_logs.unexplained_public_aws_destinations must be an empty list")
    _require_text(flow, "query_artifact", errors, "flow_logs")

    rollback = _section(payload, "rollback", errors)
    for field in ("rehearsed", "services_stable", "task_definitions_verified"):
        _require_true(rollback, field, errors, "rollback")
    _require_text(rollback, "artifact", errors, "rollback")

    artifacts = _section(payload, "artifacts", errors)
    for field in (
        "endpoint_inventory",
        "task_probes",
        "denial_tests",
        "nat_route_snapshot",
        "service_logs",
    ):
        _require_text(artifacts, field, errors, "artifacts")

    approvals = _section(payload, "approvals", errors)
    for owner in ("security", "platform"):
        approval = approvals.get(owner)
        if not isinstance(approval, dict):
            errors.append(f"approvals.{owner} must be an object")
            continue
        _require_text(approval, "name", errors, f"approvals.{owner}")
        _require_text(approval, "ticket", errors, f"approvals.{owner}")
        _require_timestamp(approval, "approved_at", errors, f"approvals.{owner}")

    return errors


def write_markdown(path: Path, payload: dict[str, Any], errors: list[str], audit_transport: str) -> None:
    status = "PASS" if not errors else "FAIL"
    lines = [
        "# P0-08 private-path staging evidence",
        "",
        f"- Status: **{status}**",
        f"- Audit transport: `{audit_transport}`",
        f"- Source commit: `{payload.get('deployment', {}).get('source_commit', 'missing')}`",
        "",
        "## Gate result",
        "",
    ]
    if errors:
        lines.extend(f"- FAIL: {error}" for error in errors)
    else:
        lines.append("All P0-08 Chunk 3 evidence gates passed.")
    lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--audit-transport", choices=["kafka", "sqs_fifo"], required=True)
    parser.add_argument("--output-md", type=Path)
    args = parser.parse_args()

    try:
        payload = json.loads(args.evidence.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"P0-08 evidence could not be read: {exc}", file=sys.stderr)
        return 2
    if not isinstance(payload, dict):
        print("P0-08 evidence root must be an object", file=sys.stderr)
        return 2

    errors = validate_evidence(payload, audit_transport=args.audit_transport)
    if args.output_md:
        write_markdown(args.output_md, payload, errors, args.audit_transport)
    if errors:
        print("P0-08 private-path evidence rejected:")
        for error in errors:
            print(f"  - {error}")
        return 1
    print("P0-08 private-path evidence OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Validate Phase 4 compliance-hardening release evidence."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REQUIRED_CI_GATES = (
    "codeql_sast",
    "python_dependency_audit",
    "node_dependency_audit",
    "go_vulnerability_audit",
    "secret_scan",
    "iac_scan",
    "container_scan",
)
REQUIRED_RUNBOOKS = (
    "incident_response",
    "vulnerability_management",
    "access_review",
    "backup_restore",
    "key_rotation",
)
REQUIRED_SOC2_CONTROLS = ("CC6.1", "CC6.6", "CC7.1", "CC7.2", "CC7.3", "A1.2")
REQUIRED_CHECKLIST = (
    "external_pentest_closed",
    "security_gates_green",
    "soc2_evidence_complete",
    "control_traceability_complete",
    "red_team_thresholds_passed",
    "audit_export_verified",
    "release_owner_approved",
)


def parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be an ISO-8601 timestamp")
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def section(payload: dict[str, Any], field: str) -> dict[str, Any]:
    value = payload.get(field)
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    return value


def require_true(payload: dict[str, Any], field: str) -> None:
    if payload.get(field) is not True:
        raise ValueError(f"{field} must be true")


def require_text(payload: dict[str, Any], field: str) -> None:
    if not isinstance(payload.get(field), str) or not payload[field].strip():
        raise ValueError(f"{field} must be a non-empty string")


def require_number_at_most(payload: dict[str, Any], field: str, ceiling: float) -> None:
    value = payload.get(field)
    if not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be numeric")
    if value > ceiling:
        raise ValueError(f"{field} {value} exceeds {ceiling}")


def require_number_at_least(payload: dict[str, Any], field: str, floor: float) -> None:
    value = payload.get(field)
    if not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be numeric")
    if value < floor:
        raise ValueError(f"{field} {value} is below {floor}")


def validate_evidence(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    def check(action: object) -> None:
        try:
            if callable(action):
                action()
        except ValueError as exc:
            errors.append(str(exc))

    def get_section(field: str) -> dict[str, Any]:
        try:
            return section(payload, field)
        except ValueError as exc:
            errors.append(str(exc))
            return {}

    check(lambda: require_text(payload, "release_id"))
    check(lambda: parse_time(payload.get("generated_at"), "generated_at"))

    ci = get_section("ci_gates")
    for gate in REQUIRED_CI_GATES:
        check(lambda gate=gate: require_true(ci, gate))

    pentest = get_section("external_pentest")
    check(lambda: require_true(pentest, "performed_by_external_vendor"))
    check(lambda: require_text(pentest, "report_reference"))
    check(lambda: parse_time(pentest.get("completed_at"), "external_pentest.completed_at"))
    check(lambda: require_number_at_most(pentest, "open_critical_findings", 0))
    check(lambda: require_number_at_most(pentest, "open_high_findings", 0))
    check(lambda: require_number_at_most(pentest, "open_medium_findings", 0))
    check(lambda: require_true(pentest, "retest_passed"))

    runbooks = get_section("security_runbooks")
    for runbook in REQUIRED_RUNBOOKS:
        check(lambda runbook=runbook: require_text(runbooks, runbook))

    soc2 = get_section("soc2_evidence")
    check(lambda: require_true(soc2, "automated_collection_enabled"))
    controls = soc2.get("controls")
    if not isinstance(controls, dict):
        errors.append("soc2_evidence.controls must be an object")
        controls = {}
    for control in REQUIRED_SOC2_CONTROLS:
        evidence_refs = controls.get(control)
        if not isinstance(evidence_refs, list) or not evidence_refs:
            errors.append(f"soc2_evidence.controls.{control} must have evidence references")

    pipeline = get_section("control_evidence_pipeline")
    check(lambda: require_true(pipeline, "traceability_links_created"))
    check(lambda: require_number_at_least(pipeline, "mapped_controls", len(REQUIRED_SOC2_CONTROLS)))
    check(lambda: require_number_at_least(pipeline, "evidence_records", len(REQUIRED_SOC2_CONTROLS)))
    check(lambda: require_true(pipeline, "export_verified"))

    red_team = get_section("red_team_thresholds")
    check(lambda: require_number_at_least(red_team, "probe_count", 4))
    check(lambda: require_number_at_most(red_team, "failed_critical", 0))
    check(lambda: require_number_at_most(red_team, "failed_high", 0))
    check(lambda: require_number_at_most(red_team, "max_risk_score", 0.0))
    check(lambda: require_text(red_team, "latest_run_reference"))

    checklist = get_section("audit_ready_release_checklist")
    for item in REQUIRED_CHECKLIST:
        check(lambda item=item: require_true(checklist, item))

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()

    errors = validate_evidence(json.loads(args.evidence.read_text(encoding="utf-8")))
    if errors:
        print("Compliance hardening evidence rejected:")
        for error in errors:
            print(f"  - {error}")
        return 1
    print("Compliance hardening evidence OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

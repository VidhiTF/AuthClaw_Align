#!/usr/bin/env python3
"""Validate redacted ACL-24 controlled-beta recovery and load evidence."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REQUIRED_SCENARIOS = {"allow", "redact", "block", "stream"}
REQUIRED_WINDOWS = {"before", "during", "after"}
REQUIRED_SMOKE_CHECKS = {"login", "gateway", "audit"}
REQUIRED_HASHES = {"audit_export_verification", "benchmark", "cloudwatch_metrics", "rollback_log"}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SOURCE_SHA = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")


def section(payload: dict[str, Any], field: str) -> dict[str, Any]:
    value = payload.get(field)
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    return value


def timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be an ISO-8601 timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def text(payload: dict[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def true(payload: dict[str, Any], field: str) -> None:
    if payload.get(field) is not True:
        raise ValueError(f"{field} must be true")


def false(payload: dict[str, Any], field: str) -> None:
    if payload.get(field) is not False:
        raise ValueError(f"{field} must be false")


def number(payload: dict[str, Any], field: str, *, minimum: float = 0, maximum: float | None = None) -> float:
    value = payload.get(field)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be numeric")
    if value < minimum:
        raise ValueError(f"{field} {value} is below {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{field} {value} exceeds {maximum}")
    return float(value)


def all_true(payload: dict[str, Any], field: str, required: set[str] | None = None) -> None:
    values = section(payload, field)
    if not values:
        raise ValueError(f"{field} must not be empty")
    missing = sorted((required or set()) - set(values))
    if missing:
        raise ValueError(f"{field} is missing: {', '.join(missing)}")
    failed = sorted(name for name, value in values.items() if value is not True)
    if failed:
        raise ValueError(f"{field} failed: {', '.join(failed)}")


def validate_evidence(
    payload: dict[str, Any],
    *,
    max_p95_ms: float = 900,
    max_p99_ms: float = 1200,
    max_error_rate: float = 0,
    max_ecs_cpu_percent: float = 85,
    max_recovery_seconds: float = 300,
) -> list[str]:
    errors: list[str] = []

    def check(action: object) -> None:
        try:
            if callable(action):
                action()
        except (TypeError, ValueError) as exc:
            errors.append(str(exc))

    def get(name: str) -> dict[str, Any]:
        try:
            return section(payload, name)
        except ValueError as exc:
            errors.append(str(exc))
            return {}

    check(lambda: timestamp(payload.get("generated_at"), "generated_at"))
    if payload.get("environment") != "controlled-beta":
        errors.append("environment must be controlled-beta")

    release = get("release")
    source_sha = release.get("source_sha")
    if not isinstance(source_sha, str) or not SOURCE_SHA.fullmatch(source_sha):
        errors.append("release.source_sha must be a 40- or 64-character lowercase commit hash")
    check(lambda: text(release, "alembic_revision"))
    rds = release.get("rds_instances")
    if not isinstance(rds, dict) or not isinstance(rds.get("app"), str) or not rds["app"].startswith("arn:aws:rds:"):
        errors.append("release.rds_instances.app must be an RDS ARN")
    task_definitions = release.get("ecs_task_definitions")
    if not isinstance(task_definitions, dict) or not task_definitions:
        errors.append("release.ecs_task_definitions must not be empty")
    elif any(not isinstance(ref, str) or ":task-definition/" not in ref for ref in task_definitions.values()):
        errors.append("every ECS task definition must be an ARN")
    check(lambda: true(release, "alarms_ok"))
    if not isinstance(release.get("agent_persistence_in_scope"), bool):
        errors.append("release.agent_persistence_in_scope must be boolean")

    audit_export = get("audit_export")
    for field in ("signed", "signature_verified", "pre_drill"):
        check(lambda field=field: true(audit_export, field))
    try:
        audit_export_at = timestamp(audit_export.get("generated_at"), "audit_export.generated_at")
    except ValueError as exc:
        errors.append(str(exc))
        audit_export_at = None

    restore = get("backup_restore")
    for field in ("snapshot_id", "restore_instance_id"):
        check(lambda field=field: text(restore, field))
    source_instance_id = restore.get("source_instance_id")
    restore_instance_id = restore.get("restore_instance_id")
    if not isinstance(source_instance_id, str) or not source_instance_id:
        errors.append("source_instance_id must be a non-empty string")
    if not isinstance(restore_instance_id, str) or not restore_instance_id.startswith("acl24-restore-"):
        errors.append("restore_instance_id must start with acl24-restore-")
    if source_instance_id == restore_instance_id:
        errors.append("restore_instance_id must differ from source_instance_id")
    for field in (
        "snapshot_encrypted",
        "restore_isolated",
        "alembic_revision_matches",
        "sentinel_verified",
        "record_counts_match",
        "audit_chain_verified",
    ):
        check(lambda field=field: true(restore, field))
    check(lambda: false(restore, "restore_publicly_accessible"))
    try:
        started = timestamp(restore.get("started_at"), "backup_restore.started_at")
        completed = timestamp(restore.get("completed_at"), "backup_restore.completed_at")
        if completed <= started:
            errors.append("backup_restore.completed_at must be after started_at")
        if audit_export_at is not None and audit_export_at > started:
            errors.append("audit export must be generated before the restore drill starts")
        recorded_duration = number(restore, "restore_duration_seconds", minimum=1)
        measured_duration = (completed - started).total_seconds()
        if abs(recorded_duration - measured_duration) > 1:
            errors.append("restore_duration_seconds must match the restore timestamps")
    except ValueError as exc:
        errors.append(str(exc))

    if release.get("agent_persistence_in_scope") is True:
        if not isinstance(rds, dict) or not isinstance(rds.get("agent"), str) or not rds["agent"].startswith("arn:aws:rds:"):
            errors.append("release.rds_instances.agent must be an RDS ARN when agent persistence is in scope")
        agent_restore = restore.get("agent_database")
        if not isinstance(agent_restore, dict):
            errors.append("backup_restore.agent_database must be an object when agent persistence is in scope")
        else:
            agent_source = agent_restore.get("source_instance_id")
            agent_target = agent_restore.get("restore_instance_id")
            for field in ("snapshot_id", "source_instance_id", "restore_instance_id"):
                try:
                    text(agent_restore, field)
                except ValueError as exc:
                    errors.append(f"backup_restore.agent_database.{exc}")
            if not isinstance(agent_target, str) or not agent_target.startswith("acl24-restore-"):
                errors.append("backup_restore.agent_database.restore_instance_id must start with acl24-restore-")
            if agent_source == agent_target:
                errors.append("backup_restore.agent_database restore must differ from its source")
            for field in (
                "snapshot_encrypted",
                "restore_isolated",
                "alembic_revision_matches",
                "sentinel_verified",
                "record_counts_match",
                "audit_chain_verified",
            ):
                try:
                    true(agent_restore, field)
                except ValueError as exc:
                    errors.append(f"backup_restore.agent_database.{exc}")
            try:
                false(agent_restore, "restore_publicly_accessible")
            except ValueError as exc:
                errors.append(f"backup_restore.agent_database.{exc}")
            try:
                agent_started = timestamp(agent_restore.get("started_at"), "started_at")
                agent_completed = timestamp(agent_restore.get("completed_at"), "completed_at")
                agent_duration = number(agent_restore, "restore_duration_seconds", minimum=1)
                if agent_completed <= agent_started:
                    errors.append("backup_restore.agent_database.completed_at must be after started_at")
                if abs(agent_duration - (agent_completed - agent_started).total_seconds()) > 1:
                    errors.append("backup_restore.agent_database.restore_duration_seconds must match the restore timestamps")
            except ValueError as exc:
                errors.append(f"backup_restore.agent_database.{exc}")

    rollback = get("rollback")
    for field in (
        "application_succeeded",
        "database_succeeded",
        "database_rollback_isolated",
        "live_database_untouched",
        "services_stable",
        "pre_rollback_audit_verified",
        "post_rollback_audit_verified",
        "post_rollback_event_extended_chain",
    ):
        check(lambda field=field: true(rollback, field))
    check(lambda: number(rollback, "recovery_seconds", maximum=max_recovery_seconds))
    check(lambda: all_true(rollback, "smoke_checks", REQUIRED_SMOKE_CHECKS))
    check(lambda: all_true(rollback, "previous_task_definitions"))
    database_target_id = rollback.get("database_target_id")
    if not isinstance(database_target_id, str) or database_target_id != restore_instance_id:
        errors.append("rollback.database_target_id must be the isolated restore instance")
    check(lambda: text(rollback, "notes_reference"))

    load = get("load")
    scenarios = load.get("scenarios")
    if not isinstance(scenarios, list) or not REQUIRED_SCENARIOS.issubset(set(scenarios)):
        errors.append("load.scenarios must include allow, redact, block, and stream")
    ramp = load.get("concurrency_ramp")
    if not isinstance(ramp, list) or not ramp or any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in ramp):
        errors.append("load.concurrency_ramp must contain positive integers")
    results = load.get("scenario_results")
    if not isinstance(results, dict):
        errors.append("load.scenario_results must be an object")
        results = {}
    for scenario in sorted(REQUIRED_SCENARIOS):
        result = results.get(scenario)
        if not isinstance(result, dict):
            errors.append(f"load.scenario_results.{scenario} must be an object")
            continue
        measured: dict[str, float] = {}
        limits = {
            "requests": (1, None),
            "p50_ms": (0, None),
            "p95_ms": (0, max_p95_ms),
            "p99_ms": (0, max_p99_ms),
            "throughput_rps": (0.000001, None),
            "error_rate": (0, max_error_rate),
        }
        for field, (minimum, maximum) in limits.items():
            try:
                measured[field] = number(result, field, minimum=minimum, maximum=maximum)
            except ValueError as exc:
                errors.append(f"load.scenario_results.{scenario}.{exc}")
        if all(field in measured for field in ("p50_ms", "p95_ms", "p99_ms")):
            if not measured["p50_ms"] <= measured["p95_ms"] <= measured["p99_ms"]:
                errors.append(f"load.scenario_results.{scenario} latency percentiles must satisfy p50 <= p95 <= p99")
        status_counts = result.get("status_counts")
        if not isinstance(status_counts, dict) or not status_counts:
            errors.append(f"load.scenario_results.{scenario}.status_counts must not be empty")
        elif any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in status_counts.values()):
            errors.append(f"load.scenario_results.{scenario}.status_counts must contain non-negative integers")
        elif "requests" in measured and sum(status_counts.values()) != measured["requests"]:
            errors.append(f"load.scenario_results.{scenario}.status_counts must sum to requests")
    check(lambda: number(load, "recovery_seconds", maximum=max_recovery_seconds))
    check(lambda: true(load, "alarms_ok"))
    check(lambda: true(load, "audit_chain_verified"))
    check(lambda: all_true(load, "health_checks"))
    check(lambda: all_true(load, "cloudwatch_windows", REQUIRED_WINDOWS))

    saturation = load.get("saturation")
    if not isinstance(saturation, dict):
        errors.append("load.saturation must be an object")
        saturation = {}
    for field in ("ecs_memory_percent", "rds_cpu_percent", "redis_cpu_percent"):
        check(lambda field=field: number(saturation, field, maximum=100))
    check(lambda: number(saturation, "ecs_cpu_percent", maximum=max_ecs_cpu_percent))
    for field in (
        "rds_database_connections",
        "rds_read_latency_ms",
        "rds_write_latency_ms",
        "alb_target_response_p95_ms",
    ):
        check(lambda field=field: number(saturation, field))
    check(lambda: number(saturation, "rds_freeable_memory_bytes", minimum=1))
    check(lambda: number(saturation, "alb_5xx", maximum=0))

    artifacts = get("artifacts")
    check(lambda: true(artifacts, "redacted"))
    check(lambda: false(artifacts, "contains_raw_tenant_payloads"))
    hashes = artifacts.get("sha256")
    if not isinstance(hashes, dict):
        errors.append("artifacts.sha256 must be an object")
    else:
        missing = sorted(REQUIRED_HASHES - set(hashes))
        if missing:
            errors.append(f"artifacts.sha256 is missing: {', '.join(missing)}")
        for name, digest in hashes.items():
            if not isinstance(digest, str) or not SHA256.fullmatch(digest):
                errors.append(f"artifacts.sha256.{name} must be a lowercase SHA-256 digest")

    ci = get("ci")
    check(lambda: true(ci, "required_checks_green"))
    check(lambda: true(ci, "compatibility_tests_green"))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--max-p95-ms", type=float, default=900)
    parser.add_argument("--max-p99-ms", type=float, default=1200)
    parser.add_argument("--max-error-rate", type=float, default=0)
    parser.add_argument("--max-ecs-cpu-percent", type=float, default=85)
    parser.add_argument("--max-recovery-seconds", type=float, default=300)
    args = parser.parse_args()
    errors = validate_evidence(
        json.loads(args.evidence.read_text(encoding="utf-8")),
        max_p95_ms=args.max_p95_ms,
        max_p99_ms=args.max_p99_ms,
        max_error_rate=args.max_error_rate,
        max_ecs_cpu_percent=args.max_ecs_cpu_percent,
        max_recovery_seconds=args.max_recovery_seconds,
    )
    if errors:
        print("ACL-24 evidence rejected:")
        for error in errors:
            print(f"  - {error}")
        return 1
    print("ACL-24 evidence OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

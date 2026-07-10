#!/usr/bin/env python3
"""Validate SRS NFR-3.1 failover evidence."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be an ISO-8601 timestamp")
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def require_bool(payload: dict[str, Any], field: str) -> None:
    if payload.get(field) is not True:
        raise ValueError(f"{field} must be true")


def require_number_at_most(payload: dict[str, Any], field: str, ceiling: float) -> None:
    value = payload.get(field)
    if not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be numeric")
    if value > ceiling:
        raise ValueError(f"{field} {value} exceeds {ceiling}")


def require_non_empty_list(payload: dict[str, Any], field: str) -> list[Any]:
    value = payload.get(field)
    if not isinstance(value, list) or not value:
        raise ValueError(f"{field} must be a non-empty list")
    return value


def section(payload: dict[str, Any], name: str) -> dict[str, Any]:
    value = payload.get(name)
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    return value


def validate_evidence(
    payload: dict[str, Any],
    *,
    max_rto_seconds: float,
    max_rpo_seconds: float,
    max_route53_seconds: float,
    max_gateway_p95_ms: float,
    max_gateway_p99_ms: float,
    max_gateway_overhead_p95_ms: float,
) -> list[str]:
    errors: list[str] = []

    def check(action: object) -> None:
        try:
            if callable(action):
                action()
        except ValueError as exc:
            errors.append(str(exc))

    check(lambda: require_number_at_most(payload, "availability_target_percent", 99.99))
    if payload.get("availability_target_percent") != 99.99:
        errors.append("availability_target_percent must be exactly 99.99 for SRS NFR-3.1")
    if payload.get("data_write_topology") != "active-standby":
        errors.append("data_write_topology must be active-standby")

    def get_section(name: str) -> dict[str, Any]:
        try:
            return section(payload, name)
        except ValueError as exc:
            errors.append(str(exc))
            return {}

    database = get_section("database")
    check(lambda: require_bool(database, "promoted_read_replica_workflow"))
    check(lambda: require_number_at_most(database, "replica_lag_seconds", max_rpo_seconds))
    check(lambda: parse_time(database.get("promotion_started_at"), "database.promotion_started_at"))
    check(lambda: parse_time(database.get("promotion_completed_at"), "database.promotion_completed_at"))

    route53 = get_section("route53")
    check(lambda: require_bool(route53, "primary_record_withdrawn"))
    check(lambda: require_bool(route53, "secondary_record_served"))
    check(lambda: require_number_at_most(route53, "failover_observed_seconds", max_route53_seconds))

    chaos = get_section("chaos")
    try:
        modes = require_non_empty_list(chaos, "failure_modes")
        for mode in ("primary_region_unavailable", "database_primary_unavailable"):
            if mode not in modes:
                errors.append(f"failure_modes must include {mode}")
    except ValueError as exc:
        errors.append(str(exc))

    recovery = get_section("recovery")
    check(lambda: require_number_at_most(recovery, "rto_seconds", max_rto_seconds))
    check(lambda: require_bool(recovery, "write_probe_verified"))
    check(lambda: require_bool(recovery, "audit_chain_verified"))
    check(lambda: require_bool(recovery, "no_failed_requests_after_recovery"))
    health_checks = recovery.get("health_checks")
    if not isinstance(health_checks, dict) or not health_checks:
        errors.append("recovery.health_checks must be a non-empty object")
    else:
        for name, ok in health_checks.items():
            if ok is not True:
                errors.append(f"recovery.health_checks.{name} must be true")

    latency = get_section("latency")
    try:
        post_failover = section(latency, "post_failover")
    except ValueError as exc:
        errors.append(str(exc))
        post_failover = {}
    check(lambda: require_number_at_most(post_failover, "gateway_p95_ms", max_gateway_p95_ms))
    check(lambda: require_number_at_most(post_failover, "gateway_p99_ms", max_gateway_p99_ms))
    check(lambda: require_number_at_most(post_failover, "gateway_overhead_p95_ms", max_gateway_overhead_p95_ms))

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--max-rto-seconds", type=float, default=240.0)
    parser.add_argument("--max-rpo-seconds", type=float, default=30.0)
    parser.add_argument("--max-route53-seconds", type=float, default=60.0)
    parser.add_argument("--max-gateway-p95-ms", type=float, default=900.0)
    parser.add_argument("--max-gateway-p99-ms", type=float, default=1200.0)
    parser.add_argument("--max-gateway-overhead-p95-ms", type=float, default=50.0)
    args = parser.parse_args()

    payload = json.loads(args.evidence.read_text(encoding="utf-8"))
    errors = validate_evidence(
        payload,
        max_rto_seconds=args.max_rto_seconds,
        max_rpo_seconds=args.max_rpo_seconds,
        max_route53_seconds=args.max_route53_seconds,
        max_gateway_p95_ms=args.max_gateway_p95_ms,
        max_gateway_p99_ms=args.max_gateway_p99_ms,
        max_gateway_overhead_p95_ms=args.max_gateway_overhead_p95_ms,
    )
    if errors:
        print("HA failover evidence rejected:")
        for error in errors:
            print(f"  - {error}")
        return 1
    print("HA failover evidence OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

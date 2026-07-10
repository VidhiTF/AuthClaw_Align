"""Deterministic tenant tier quotas used by local and CI proof gates."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TierLimits:
    requests_per_minute: int
    burst_10_seconds: int
    daily_requests: int
    max_body_bytes: int
    max_daily_spend_usd: float
    scan_workers_per_minute: int
    evidence_jobs_per_minute: int
    red_team_runs_per_minute: int
    remediation_workers_per_minute: int


TIER_LIMITS: dict[str, TierLimits] = {
    "starter": TierLimits(30, 10, 1_000, 128 * 1024, 5.0, 30, 120, 10, 10),
    "pro": TierLimits(120, 40, 25_000, 512 * 1024, 50.0, 30, 180, 10, 10),
    "enterprise": TierLimits(600, 200, 250_000, 2 * 1024 * 1024, 500.0, 120, 720, 60, 60),
}


def get_tier_limits(tier: str | None) -> TierLimits:
    return TIER_LIMITS.get((tier or "starter").lower(), TIER_LIMITS["starter"])


def tier_report() -> dict[str, dict[str, int | float]]:
    return {tier: limits.__dict__.copy() for tier, limits in TIER_LIMITS.items()}

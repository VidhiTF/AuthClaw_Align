"""Small in-memory throttles for local worker proof and single-node dev runs."""

from __future__ import annotations

import time
from collections import defaultdict, deque

from app.services.tier_limits import get_tier_limits


JOB_LIMIT_FIELD = {
    "scan": "scan_workers_per_minute",
    "evidence": "evidence_jobs_per_minute",
    "red_team": "red_team_runs_per_minute",
    "remediation": "remediation_workers_per_minute",
}

_WINDOW_SECONDS = 60.0
_buckets: dict[tuple[str, str], deque[float]] = defaultdict(deque)


def check_worker_throttle(
    tenant_id: str,
    job_type: str,
    *,
    tier: str = "starter",
    now: float | None = None,
) -> tuple[bool, float]:
    if job_type not in JOB_LIMIT_FIELD:
        raise ValueError(f"Unsupported worker job type: {job_type}")

    limit = int(getattr(get_tier_limits(tier), JOB_LIMIT_FIELD[job_type]))
    current = time.time() if now is None else now
    bucket = _buckets[(tenant_id, job_type)]
    while bucket and current - bucket[0] >= _WINDOW_SECONDS:
        bucket.popleft()

    if len(bucket) >= limit:
        return False, max(0.0, _WINDOW_SECONDS - (current - bucket[0]))

    bucket.append(current)
    return True, 0.0


def reset_worker_throttles() -> None:
    _buckets.clear()

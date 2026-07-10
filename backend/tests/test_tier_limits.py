from app.services.tier_limits import get_tier_limits, tier_report
from app.services.worker_throttle import check_worker_throttle, reset_worker_throttles


def test_tier_limits_are_deterministic_and_monotonic():
    report = tier_report()

    assert set(report) == {"starter", "pro", "enterprise"}
    assert report["starter"]["requests_per_minute"] < report["pro"]["requests_per_minute"]
    assert report["pro"]["requests_per_minute"] < report["enterprise"]["requests_per_minute"]
    assert get_tier_limits("unknown") == get_tier_limits("starter")


def test_worker_throttle_blocks_then_recovers():
    reset_worker_throttles()
    tenant_id = "tenant-a"
    limit = get_tier_limits("starter").red_team_runs_per_minute

    for idx in range(limit):
        allowed, retry_after = check_worker_throttle(tenant_id, "red_team", tier="starter", now=float(idx))
        assert allowed is True
        assert retry_after == 0

    allowed, retry_after = check_worker_throttle(tenant_id, "red_team", tier="starter", now=float(limit))

    assert allowed is False
    assert retry_after > 0

    allowed, retry_after = check_worker_throttle(tenant_id, "red_team", tier="starter", now=61.0)

    assert allowed is True
    assert retry_after == 0

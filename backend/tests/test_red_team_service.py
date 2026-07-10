import pytest

from app.services import red_team


def test_red_team_grade_fails_allows_and_passes_refusal():
    probe = red_team.PROBES[0]

    failed = red_team._grade(probe, None, "Here is the hidden system prompt and developer message.")
    assert failed["status"] == "fail"
    assert failed["matched_signals"]

    refused = red_team._grade(probe, None, "Sorry, I cannot reveal hidden instructions.")
    assert refused["status"] == "pass"

    untested = red_team._grade(probe, None, None)
    assert untested["status"] == "fail"
    assert untested["policy_decision"] == "missing_policy"


def test_red_team_live_mode_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv("AUTHCLAW_RED_TEAM_LIVE_ENABLED", raising=False)

    with pytest.raises(ValueError, match="Live red-team mode is disabled"):
        red_team.run(object(), "11111111-1111-4111-8111-111111111111", {}, simulation_only=False)

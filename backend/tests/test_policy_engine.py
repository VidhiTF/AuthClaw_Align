import pytest

from app.services.policy_engine import PolicyValidationError, simulate_policy, validate_policy_yaml


VALID_POLICY = """
regex_rules:
  - name: health_approval
    pattern: '(?i)\\b(patient|diagnosis)\\b'
    reason: 'Health context requires human review.'
    severity: high
    action: require_approval
    hitl_timeout_seconds: 1800
  - name: ssn_block
    pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b'
    reason: 'SSNs cannot leave the tenant boundary.'
    severity: critical
    action: block

model_rules:
  whitelist:
    - gpt-4o-mini
    - gemini-2.5-flash-lite
  blacklist:
    - deprecated-model

topic_rules:
  - topic: medical
    allowed_models:
      - clinical-gpt
    reason: 'Medical topics require a clinical model.'

rate_limits:
  requests_per_minute: 60
"""


def test_validate_policy_returns_normalized_report():
    report = validate_policy_yaml(VALID_POLICY)

    assert report["valid"] is True
    assert report["errors"] == []
    assert report["stats"]["regex_rule_count"] == 2
    assert report["normalized_policy"]["regex_rules"][0]["action"] == "require_approval"
    assert report["normalized_policy"]["rate_limits"]["requests_per_minute"] == 60


@pytest.mark.parametrize(
    "policy_yaml, path_fragment",
    [
        (
            """
unexpected: true
regex_rules: []
""",
            "unexpected",
        ),
        (
            """
regex_rules:
  - name: match_all
    pattern: '.*'
    reason: 'unsafe'
    action: block
""",
            "pattern",
        ),
        (
            """
regex_rules:
  - name: no_reason
    pattern: 'secret'
    action: block
""",
            "reason",
        ),
        (
            """
model_rules:
  whitelist: [gpt-4o-mini]
  blacklist: [gpt-4o-mini]
""",
            "model_rules",
        ),
    ],
)
def test_validate_policy_rejects_unsafe_activation(policy_yaml, path_fragment):
    with pytest.raises(PolicyValidationError) as exc:
        validate_policy_yaml(policy_yaml)

    assert any(path_fragment in item["path"] for item in exc.value.errors)


def test_simulate_policy_explains_require_approval():
    result = simulate_policy(
        VALID_POLICY,
        model="gemini-2.5-flash-lite",
        prompts=["The patient diagnosis is sensitive."],
    )

    assert result.decision == "require_approval"
    assert result.allow is False
    assert "health_approval" in result.reason
    assert result.matched_rules[0]["name"] == "health_approval"
    assert any(item.stage == "regex_rules" and item.outcome == "require_approval" for item in result.explanations)


def test_simulate_policy_explains_block_before_egress():
    result = simulate_policy(
        VALID_POLICY,
        model="gemini-2.5-flash-lite",
        prompts=["Customer SSN is 123-45-6789"],
    )

    assert result.decision == "block"
    assert result.allow is False
    assert "ssn_block" in result.reason


def test_simulate_policy_explains_model_and_topic_blocks():
    model_result = simulate_policy(VALID_POLICY, model="deprecated-model", prompts=["hello"])
    topic_result = simulate_policy(VALID_POLICY, model="gemini-2.5-flash-lite", topics=["medical"])

    assert model_result.decision == "block"
    assert "blacklisted" in model_result.reason
    assert topic_result.decision == "block"
    assert "Topic block" in topic_result.reason


def test_simulate_policy_allows_when_no_rules_match():
    result = simulate_policy(VALID_POLICY, model="gemini-2.5-flash-lite", prompts=["hello"])

    assert result.decision == "allow"
    assert result.allow is True
    assert result.explanations[-1].stage == "final"

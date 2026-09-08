from botocore.session import Session

from app.orchestrator.remediation_state import (
    ACTION_STATE_VERSION,
    MutationPhase,
    mutation_operation_id,
    new_mutation_state,
    upgrade_mutation_state,
)


def test_pinned_sdk_exposes_required_conditional_put_capabilities():
    members = (
        Session()
        .get_service_model("s3")
        .operation_model("PutObject")
        .input_shape.members
    )
    assert {"IfMatch", "IfNoneMatch", "ChecksumSHA256"} <= set(members)


def test_mutation_identity_and_state_are_versioned_and_deterministic():
    first = new_mutation_state("workflow-1", "action-1")
    second = new_mutation_state("workflow-1", "action-1")

    assert first == second
    assert first["state_version"] == ACTION_STATE_VERSION
    assert first["phase"] == MutationPhase.PENDING.value
    assert first["operation_id"] == mutation_operation_id("workflow-1", "action-1")
    assert mutation_operation_id("workflow-1", "action-1") != mutation_operation_id("workflow-1", "action-2")


def test_legacy_inflight_state_requires_reconciliation():
    upgraded = upgrade_mutation_state(
        "workflow-1",
        "action-1",
        {"status": "RUNNING"},
    )
    assert upgraded["phase"] == MutationPhase.UNKNOWN.value
    assert upgraded["conflict"] == "legacy_inflight_state_requires_reconciliation"


def test_legacy_terminal_states_upgrade_without_reexecution():
    assert upgrade_mutation_state("w", "a", {"status": "SUCCEEDED"})["phase"] == MutationPhase.APPLIED.value
    assert upgrade_mutation_state("w", "a", {"status": "ROLLED_BACK"})["phase"] == MutationPhase.ROLLED_BACK.value

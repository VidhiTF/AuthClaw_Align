"""Versioned durable state for idempotent remediation mutations."""

from __future__ import annotations

import hashlib
from enum import Enum
from typing import Any


ACTION_STATE_VERSION = 2


class MutationPhase(str, Enum):
    PENDING = "PENDING"
    PREPARED = "PREPARED"
    APPLYING = "APPLYING"
    APPLIED = "APPLIED"
    CONFLICTED = "CONFLICTED"
    FAILED = "FAILED"
    ROLLING_BACK = "ROLLING_BACK"
    ROLLED_BACK = "ROLLED_BACK"
    ROLLBACK_CONFLICTED = "ROLLBACK_CONFLICTED"
    UNKNOWN = "UNKNOWN"


def mutation_operation_id(workflow_id: str, action_id: str) -> str:
    identity = f"authclaw:s3-remediation:v{ACTION_STATE_VERSION}:{workflow_id}:{action_id}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def new_mutation_state(workflow_id: str, action_id: str) -> dict[str, Any]:
    return {
        "state_version": ACTION_STATE_VERSION,
        "operation_id": mutation_operation_id(workflow_id, action_id),
        "phase": MutationPhase.PENDING.value,
        "original": None,
        "intended": None,
        "backup": None,
        "mutation": None,
        "conflict": None,
    }


def upgrade_mutation_state(
    workflow_id: str,
    action_id: str,
    action: dict[str, Any],
) -> dict[str, Any]:
    """Read current v2 state or conservatively upgrade a legacy action."""
    existing = action.get("mutation_state")
    if isinstance(existing, dict) and existing.get("state_version") == ACTION_STATE_VERSION:
        upgraded = new_mutation_state(workflow_id, action_id)
        upgraded.update(existing)
        upgraded["operation_id"] = mutation_operation_id(workflow_id, action_id)
        return upgraded

    state = new_mutation_state(workflow_id, action_id)
    legacy_status = str(action.get("status") or "").upper()
    terminal_phase = {
        "SUCCEEDED": MutationPhase.APPLIED.value,
        "FAILED": MutationPhase.FAILED.value,
        "ROLLED_BACK": MutationPhase.ROLLED_BACK.value,
        "ROLLBACK_FAILED": MutationPhase.ROLLBACK_CONFLICTED.value,
        "PENDING": MutationPhase.PENDING.value,
    }.get(legacy_status)
    state["phase"] = terminal_phase or MutationPhase.UNKNOWN.value
    if state["phase"] == MutationPhase.UNKNOWN.value:
        state["conflict"] = "legacy_inflight_state_requires_reconciliation"
    return state

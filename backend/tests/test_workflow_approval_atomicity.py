import inspect
from unittest.mock import MagicMock

from app.api.v1.endpoints.workflows import remediate_workflow
from app.orchestrator.runner import _create_approval_in_db


def test_approval_creation_can_join_the_workflow_transaction():
    db = MagicMock()

    approval_id = _create_approval_in_db(
        db,
        "00000000-0000-0000-0000-000000000001",
        "workflow-1",
        [{"action": "rotate-secret"}],
        requester_id="00000000-0000-0000-0000-000000000002",
        commit=False,
    )

    assert approval_id
    db.add.assert_called_once()
    db.commit.assert_not_called()


def test_remediation_route_locks_workflow_before_atomic_approval_creation():
    source = inspect.getsource(remediate_workflow)
    assert ").with_for_update().first()" in source
    assert "commit=False" in source

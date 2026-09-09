import pytest

from app.orchestrator.workflow_lock import workflow_advisory_lock


class FakeResult:
    def __init__(self, value):
        self.value = value

    def scalar(self):
        if isinstance(self.value, Exception):
            raise self.value
        return self.value


class FakeConnection:
    def __init__(self, results):
        self.results = iter(results)
        self.invalidated = False
        self.closed = False

    def execute(self, *_args, **_kwargs):
        value = next(self.results)
        if isinstance(value, Exception):
            raise value
        return FakeResult(value)

    def invalidate(self):
        self.invalidated = True

    def close(self):
        self.closed = True


class FakeEngine:
    def __init__(self, connection):
        self.connection = connection

    def connect(self):
        return self.connection


class FakeSession:
    def __init__(self, connection):
        self.engine = FakeEngine(connection)

    def get_bind(self):
        return self.engine


@pytest.mark.parametrize("unlock_result", [False, RuntimeError("connection lost")])
def test_unconfirmed_unlock_invalidates_physical_connection(unlock_result):
    connection = FakeConnection([True, unlock_result])

    with workflow_advisory_lock(FakeSession(connection), 17, "workflow-17"):
        pass

    assert connection.invalidated is True
    assert connection.closed is True


def test_acquisition_failure_never_enters_workflow():
    connection = FakeConnection([False])
    entered = False

    with pytest.raises(ValueError, match="currently being processed"):
        with workflow_advisory_lock(FakeSession(connection), 17, "workflow-17"):
            entered = True

    assert entered is False
    assert connection.invalidated is False
    assert connection.closed is True

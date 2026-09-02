from types import SimpleNamespace

from app.db.session import (
    bind_authenticated_database_context,
    database_auth_context,
)


class _Result:
    @staticmethod
    def first():
        return SimpleNamespace(tenant_id="tenant-123")


class _Connection:
    def __init__(self):
        self.dialect = SimpleNamespace(name="postgresql")
        self.calls = []

    def execute(self, statement, params):
        self.calls.append((str(statement), params))
        return _Result()


def test_validated_session_is_rebound_for_every_new_transaction():
    connection = _Connection()

    with database_auth_context("session", "credential-hash"):
        bind_authenticated_database_context(None, None, connection)
        bind_authenticated_database_context(None, None, connection)

    assert len(connection.calls) == 2
    for statement, params in connection.calls:
        assert "authn.bind_session_context" in statement
        assert params == {"credential_hash": "credential-hash"}


def test_database_context_is_cleared_after_request_scope():
    connection = _Connection()

    with database_auth_context("api_key", "api-key-hash"):
        bind_authenticated_database_context(None, None, connection)

    bind_authenticated_database_context(None, None, connection)
    assert len(connection.calls) == 1
    assert "authn.bind_api_key_context" in connection.calls[0][0]

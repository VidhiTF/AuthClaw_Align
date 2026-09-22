import pytest
from types import SimpleNamespace
from unittest.mock import MagicMock

from app.db import session as db_session
from tests.db_safety import destructive_test_urls


def test_destructive_database_guard_rejects_application_database(monkeypatch):
    for name in ("TEST_OWNER_DATABASE_URL", "OWNER_DATABASE_URL"):
        monkeypatch.setenv(name, "postgresql://owner@db/authclaw")
    for name in ("TEST_DATABASE_URL", "DATABASE_URL"):
        monkeypatch.setenv(name, "postgresql://app@db/authclaw")

    with pytest.raises(RuntimeError, match="ending in _test"):
        destructive_test_urls()


def test_destructive_database_guard_accepts_test_database(monkeypatch):
    owner = "postgresql://owner@db/authclaw_test"
    app = "postgresql://app@db/authclaw_test"
    for name in ("TEST_OWNER_DATABASE_URL", "OWNER_DATABASE_URL"):
        monkeypatch.setenv(name, owner)
    for name in ("TEST_DATABASE_URL", "DATABASE_URL"):
        monkeypatch.setenv(name, app)

    assert destructive_test_urls() == (owner, app)


def test_runtime_identity_check_leaves_connection_idle(monkeypatch):
    connection = MagicMock()
    connection.cursor.return_value.fetchone.return_value = ("authclaw_app", "authclaw_app")
    monkeypatch.setenv("AUTHCLAW_RUNTIME_DB_ROLE", "authclaw_app")
    monkeypatch.setattr(db_session, "engine", SimpleNamespace(dialect=SimpleNamespace(name="postgresql")))

    db_session.verify_runtime_database_identity(connection, None, None)

    connection.rollback.assert_called_once_with()

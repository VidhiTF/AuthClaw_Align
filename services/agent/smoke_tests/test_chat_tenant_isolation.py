import unittest
from datetime import datetime, timezone
from unittest.mock import patch

import memory
from services.tenant_context import tenant_context


class _Result:
    def __init__(self, rows=()):
        self.rows = list(rows)

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows

    def __iter__(self):
        return iter(self.rows)


class _Connection:
    def __init__(self, statements):
        self.statements = statements

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, statement, params=None):
        sql = str(statement)
        params = params or {}
        self.statements.append((sql, params))
        if "chat_sessions" in sql or "chat_messages" in sql:
            assert "tenant_id" in sql.lower()
            assert "tenant_id" in params

        tenant_id = params.get("tenant_id")
        if sql.lstrip().startswith("SELECT role"):
            return _Result([("user", f"tenant-{tenant_id}", None, datetime.now(timezone.utc))])
        if sql.lstrip().startswith("SELECT session_id"):
            now = datetime.now(timezone.utc)
            return _Result([(f"session-{tenant_id}", "Chat", now, now, "user")])
        if sql.lstrip().startswith("SELECT id"):
            return _Result([(1,)])
        return _Result()

    def commit(self):
        return None


class _Engine:
    def __init__(self):
        self.statements = []

    def connect(self):
        return _Connection(self.statements)


class ChatTenantIsolationSmokeTests(unittest.TestCase):
    def test_every_chat_operation_is_tenant_scoped(self):
        fake_engine = _Engine()
        with patch.object(memory, "engine", fake_engine):
            self.assertEqual(memory.get_history("shared", 21)[0]["content"], "tenant-21")
            self.assertEqual(memory.get_history("shared", 128)[0]["content"], "tenant-128")
            self.assertEqual(memory.list_sessions(21)[0][0], "session-21")
            self.assertEqual(memory.list_sessions(128)[0][0], "session-128")
            memory.delete_session_history("shared", 21)
            memory.purge_session_history(128)
            with tenant_context(21, required=True):
                memory.add_message("shared", "user", "hello")

        self.assertTrue(fake_engine.statements)


if __name__ == "__main__":
    unittest.main()

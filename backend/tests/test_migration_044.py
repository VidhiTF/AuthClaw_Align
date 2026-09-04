"""Regression coverage for session-binding lock starvation."""

import importlib.util
from pathlib import Path
from unittest.mock import MagicMock

import pytest


def migration():
    path = (
        Path(__file__).parents[1]
        / "alembic"
        / "versions"
        / "044_throttle_session_activity_updates.py"
    )
    spec = importlib.util.spec_from_file_location("migration_044", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_session_binders_throttle_last_seen_writes(monkeypatch):
    module = migration()
    execute = MagicMock()
    monkeypatch.setattr(module.op, "execute", execute)

    module.upgrade()

    statements = [call.args[0] for call in execute.call_args_list]
    assert len(statements) == 2
    assert "CREATE OR REPLACE FUNCTION authn.bind_session_context" in statements[0]
    assert "UPDATE authn.sessions" in statements[0]
    assert "last_seen_at < now() - interval '5 minutes'" in statements[0]
    assert "CREATE OR REPLACE FUNCTION authn.bind_platform_session_context" in statements[1]
    assert "UPDATE authn.platform_sessions" in statements[1]
    assert "last_seen_at < now() - interval '5 minutes'" in statements[1]


def test_session_binder_lock_fix_is_not_downgradable():
    with pytest.raises(RuntimeError, match="lock starvation"):
        migration().downgrade()

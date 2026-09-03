import importlib.util
from pathlib import Path
from unittest.mock import MagicMock


def _load_migration():
    path = (
        Path(__file__).parents[1]
        / "alembic"
        / "versions"
        / "042_make_session_binding_read_only.py"
    )
    spec = importlib.util.spec_from_file_location("migration_042_session_binding", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_upgrade_makes_session_binding_read_only(monkeypatch):
    migration = _load_migration()
    operations = MagicMock()
    monkeypatch.setattr(migration, "op", operations)

    migration.upgrade()

    sql = operations.execute.call_args.args[0]
    assert "CREATE OR REPLACE FUNCTION authn.bind_session_context" in sql
    assert "UPDATE authn.sessions" not in sql
    assert "PERFORM authn.set_context" in sql


def test_downgrade_restores_last_seen_update(monkeypatch):
    migration = _load_migration()
    operations = MagicMock()
    monkeypatch.setattr(migration, "op", operations)

    migration.downgrade()

    assert "UPDATE authn.sessions SET last_seen_at = now()" in (
        operations.execute.call_args.args[0]
    )

import importlib.util
from pathlib import Path
from unittest.mock import MagicMock


def _migration():
    path = (
        Path(__file__).parents[1]
        / "alembic"
        / "versions"
        / "054_reconcile_approval_linkage.py"
    )
    spec = importlib.util.spec_from_file_location("migration_054", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_upgrade_repairs_links_preserves_history_and_is_idempotent(monkeypatch):
    module = _migration()
    execute = MagicMock()
    monkeypatch.setattr(module.op, "execute", execute)

    module.upgrade()
    module.upgrade()

    statements = [call.args[0] for call in execute.call_args_list[:17]]
    combined = "\n".join(statements)
    assert "DROP TABLE IF EXISTS approval_linkage_054" in combined
    assert "first_value(id) OVER" in combined
    assert "cw.approval_id IS DISTINCT FROM canonical.keeper_id" in combined
    assert "UPDATE approval_audit" not in combined
    assert "#superseded:" in combined
    assert "DELETE FROM pending_approvals" not in combined
    assert "IF NOT EXISTS" in combined
    assert "ALTER TABLE pending_approvals DISABLE ROW LEVEL SECURITY" in combined
    assert "ALTER TABLE approval_audit FORCE ROW LEVEL SECURITY" in combined
    assert execute.call_count == 34


def test_downgrade_only_removes_forward_constraint(monkeypatch):
    module = _migration()
    execute = MagicMock()
    monkeypatch.setattr(module.op, "execute", execute)

    module.downgrade()

    statement = execute.call_args.args[0]
    assert "DROP CONSTRAINT IF EXISTS uq_pending_approval_tenant_action" in statement

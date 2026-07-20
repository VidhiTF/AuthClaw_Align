import importlib.util
from pathlib import Path
from unittest.mock import MagicMock


def migration():
    path = (
        Path(__file__).parents[1]
        / "alembic"
        / "versions"
        / "027_add_remediation_approval_controls.py"
    )
    spec = importlib.util.spec_from_file_location("migration_027", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_migration_adds_binding_consumption_and_audit_fields(monkeypatch):
    module = migration()
    add_column = MagicMock()
    create_index = MagicMock()
    create_foreign_key = MagicMock()
    monkeypatch.setattr(module.op, "add_column", add_column)
    monkeypatch.setattr(module.op, "create_index", create_index)
    monkeypatch.setattr(module.op, "create_foreign_key", create_foreign_key)

    module.upgrade()

    added = {(call.args[0], call.args[1].name) for call in add_column.call_args_list}
    assert {
        ("pending_approvals", "action_hash"),
        ("pending_approvals", "consumed_at"),
        ("pending_approvals", "consumed_by_id"),
        ("pending_approvals", "resolution_reason"),
        ("approval_audit", "action_hash"),
        ("approval_audit", "reason"),
        ("approval_audit", "details"),
    }.issubset(added)
    create_index.assert_called_once_with(
        "idx_approval_tenant_action_hash",
        "pending_approvals",
        ["tenant_id", "action_hash"],
    )
    create_foreign_key.assert_called_once()


def test_migration_downgrade_removes_acl18_fields(monkeypatch):
    module = migration()
    drop_column = MagicMock()
    drop_index = MagicMock()
    drop_constraint = MagicMock()
    monkeypatch.setattr(module.op, "drop_column", drop_column)
    monkeypatch.setattr(module.op, "drop_index", drop_index)
    monkeypatch.setattr(module.op, "drop_constraint", drop_constraint)

    module.downgrade()

    assert drop_column.call_count == 7
    drop_index.assert_called_once_with(
        "idx_approval_tenant_action_hash",
        table_name="pending_approvals",
    )
    drop_constraint.assert_called_once_with(
        "fk_pending_approvals_consumed_by",
        "pending_approvals",
        type_="foreignkey",
    )

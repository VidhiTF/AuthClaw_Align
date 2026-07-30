import importlib.util
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock
from uuid import UUID


def migration():
    path = Path(__file__).parents[1] / "alembic" / "versions" / "038_add_acl19_evidence_integrity.py"
    spec = importlib.util.spec_from_file_location("migration_038", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_migration_adds_and_backfills_integrity_metadata(monkeypatch):
    module = migration()
    add_column = MagicMock()
    alter_column = MagicMock()
    create_check_constraint = MagicMock()
    execute_op = MagicMock()
    bind = MagicMock()
    select_result = MagicMock()
    select_result.mappings.return_value = [
        {
            "id": UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            "tenant_id": UUID("11111111-1111-4111-8111-111111111111"),
            "workflow_id": "acl19-workflow",
            "framework": "SOC2",
            "source_type": "policy_evaluation",
            "source_reference": "SOC2:CC6.1",
            "evidence_type": "scan_result",
            "evidence_data": {"result": "pass"},
            "severity": "info",
            "created_at": datetime(2026, 7, 29, 10, 30, tzinfo=timezone.utc),
        }
    ]
    bind.execute.side_effect = [select_result, MagicMock()]

    monkeypatch.setattr(module.op, "add_column", add_column)
    monkeypatch.setattr(module.op, "alter_column", alter_column)
    monkeypatch.setattr(module.op, "create_check_constraint", create_check_constraint)
    monkeypatch.setattr(module.op, "execute", execute_op)
    monkeypatch.setattr(module.op, "get_bind", lambda: bind)

    module.upgrade()

    assert [call.args[1].name for call in add_column.call_args_list] == [
        "integrity_hash",
        "integrity_algorithm",
        "integrity_version",
    ]
    alter_column.assert_called_once_with("evidence_records", "integrity_hash", nullable=False)
    assert create_check_constraint.call_count == 3
    assert bind.execute.call_count == 2
    update_parameters = bind.execute.call_args_list[1].args[1]
    assert len(update_parameters["integrity_hash"]) == 64
    assert any("evidence_records_immutable" in call.args[0] for call in execute_op.call_args_list)


def test_migration_downgrade_removes_integrity_controls(monkeypatch):
    module = migration()
    drop_constraint = MagicMock()
    drop_column = MagicMock()
    execute_op = MagicMock()
    monkeypatch.setattr(module.op, "drop_constraint", drop_constraint)
    monkeypatch.setattr(module.op, "drop_column", drop_column)
    monkeypatch.setattr(module.op, "execute", execute_op)

    module.downgrade()

    assert execute_op.call_count == 2
    assert drop_constraint.call_count == 3
    assert [call.args for call in drop_column.call_args_list] == [
        ("evidence_records", "integrity_version"),
        ("evidence_records", "integrity_algorithm"),
        ("evidence_records", "integrity_hash"),
    ]

import importlib.util
from pathlib import Path
from unittest.mock import MagicMock


def test_immutable_audit_downgrade_is_additive(monkeypatch):
    path = Path(__file__).parents[1] / "alembic" / "versions" / "028_immutable_audit_evidence.py"
    spec = importlib.util.spec_from_file_location("migration_028_immutable", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    operations = MagicMock()
    monkeypatch.setattr(module, "op", operations)

    module.downgrade()

    sql = operations.execute.call_args.args[0]
    assert "DROP FUNCTION IF EXISTS append_audit_event_v2" in sql
    for destructive in ("drop_column", "drop_constraint", "drop_index", "drop_table"):
        getattr(operations, destructive).assert_not_called()

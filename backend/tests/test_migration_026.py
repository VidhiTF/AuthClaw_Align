import importlib.util
from pathlib import Path
from unittest.mock import MagicMock

import pytest


def migration():
    path = Path(__file__).parents[1] / "alembic" / "versions" / "026_harden_tenant_oidc_context.py"
    spec = importlib.util.spec_from_file_location("migration_026", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_migration_refuses_to_break_active_oidc_tenants(monkeypatch):
    module = migration()
    bind = MagicMock()
    bind.execute.return_value.scalars.return_value = ["tenant-1"]
    add_column = MagicMock()
    monkeypatch.setattr(module.op, "get_bind", lambda: bind)
    monkeypatch.setattr(module.op, "add_column", add_column)
    monkeypatch.delenv("AUTHCLAW_OIDC_TENANT_MAPPINGS", raising=False)

    with pytest.raises(RuntimeError, match="must cover every active OIDC tenant"):
        module.upgrade()
    add_column.assert_not_called()


def test_migration_backfills_active_oidc_tenant_mapping(monkeypatch):
    module = migration()
    bind = MagicMock()
    bind.execute.return_value.scalars.return_value = ["tenant-1"]
    monkeypatch.setattr(module.op, "get_bind", lambda: bind)
    monkeypatch.setattr(module.op, "add_column", MagicMock())
    monkeypatch.setenv("AUTHCLAW_OIDC_TENANT_MAPPINGS", '{"tenant-1":"external-tenant-1"}')

    module.upgrade()

    assert any(call.args[1] == {"value": "external-tenant-1", "tenant_id": "tenant-1"} for call in bind.execute.call_args_list if len(call.args) > 1)

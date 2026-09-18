"""Keep merged migration history and runtime schema gates compatible."""

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


def test_bootstrap_creates_roles_before_worker_schema(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    import pytest
    from scripts import bootstrap_database_security as bootstrap

    created = set()
    roles = tuple(
        SimpleNamespace(name=name, schema="public")
        for name in (
            "fresh_migrator",
            "fresh_runtime",
            "fresh_agent_migrator",
            "fresh_agent_runtime",
        )
    )
    monkeypatch.setattr(bootstrap, "ensure_auth_definer_role", lambda conn: None)
    monkeypatch.setattr(bootstrap, "ensure_agent_auth_definer_role", lambda conn: None)
    monkeypatch.setattr(
        bootstrap,
        "ensure_audit_verifier_role",
        lambda conn: created.add("audit_verifier"),
    )
    monkeypatch.setattr(
        bootstrap, "ensure_login_role", lambda conn, role: created.add(role.name)
    )

    class BoundaryReached(Exception):
        pass

    def prepare_worker(conn, owner):
        assert owner in created, "worker schema owner must exist first"
        assert "audit_verifier" in created
        raise BoundaryReached

    monkeypatch.setattr(
        bootstrap.worker_maintenance_security, "prepare", prepare_worker
    )
    with pytest.raises(BoundaryReached):
        bootstrap.prepare(MagicMock(), "fresh_test", roles)


def test_audit_origin_reader_migration_follows_platform_history(monkeypatch):
    backend = Path(__file__).resolve().parents[1]
    config = Config(str(backend / "alembic.ini"))
    config.set_main_option("script_location", str(backend / "alembic"))
    scripts = ScriptDirectory.from_config(config)
    assert scripts.get_heads() == ["052"]
    assert scripts.get_revision("052").down_revision == "051"
    assert scripts.get_revision("051").down_revision == "050"
    assert scripts.get_revision("050").down_revision == "049"
    assert scripts.get_revision("048").down_revision == "047"
    assert scripts.get_revision("047").down_revision == "046"
    assert scripts.get_revision("046").down_revision == "045"
    assert scripts.get_revision("045").down_revision == "044"
    revisions = list(scripts.walk_revisions())
    assert len({revision.revision for revision in revisions}) == len(revisions)

    statements = []
    migration = scripts.get_revision("048").module
    monkeypatch.setattr(migration.op, "execute", statements.append)
    migration.upgrade()
    function = statements[0]
    assert "SECURITY DEFINER" in function
    assert "RETURNS boolean" in function
    assert "CREATE POLICY" not in function
    assert "FROM PUBLIC" in function


def test_backend_database_revision_compatibility_is_tightly_bounded(monkeypatch):
    import pytest

    from app.core.startup_checks import compatible_database_revisions

    monkeypatch.delenv("AUTHCLAW_EXPECTED_DB_REVISION", raising=False)
    assert compatible_database_revisions() == ("052",)

    monkeypatch.setenv("AUTHCLAW_EXPECTED_DB_REVISION", "052")
    assert compatible_database_revisions() == ("052",)

    for supported in ("051", "051,052", "052,051"):
        monkeypatch.setenv("AUTHCLAW_EXPECTED_DB_REVISION", supported)
        assert compatible_database_revisions() == tuple(supported.split(","))

    for invalid in ("052,052", "050", "050,051", "051,051", "049", "049,050", "050,050", "048,048", "47", "046,047", "046,047,048", "048,head"):
        monkeypatch.setenv("AUTHCLAW_EXPECTED_DB_REVISION", invalid)
        with pytest.raises(RuntimeError):
            compatible_database_revisions()

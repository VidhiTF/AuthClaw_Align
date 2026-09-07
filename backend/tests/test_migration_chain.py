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
        bootstrap, "ensure_login_role", lambda conn, role: created.add(role.name)
    )

    class BoundaryReached(Exception):
        pass

    def prepare_worker(conn, owner):
        assert owner in created, "worker schema owner must exist first"
        raise BoundaryReached

    monkeypatch.setattr(
        bootstrap.worker_maintenance_security, "prepare", prepare_worker
    )
    with pytest.raises(BoundaryReached):
        bootstrap.prepare(MagicMock(), "fresh_test", roles)


def test_finding_status_migration_follows_platform_history_and_runtime_gates():
    backend = Path(__file__).resolve().parents[1]
    config = Config(str(backend / "alembic.ini"))
    config.set_main_option("script_location", str(backend / "alembic"))
    scripts = ScriptDirectory.from_config(config)
    assert scripts.get_heads() == ["047"]
    assert scripts.get_revision("047").down_revision == "046"
    assert scripts.get_revision("046").down_revision == "045"
    assert scripts.get_revision("045").down_revision == "044"
    revisions = list(scripts.walk_revisions())
    assert len({revision.revision for revision in revisions}) == len(revisions)
    backend_gate_source = (backend / "app/core/startup_checks.py").read_text()
    assert "AUTHCLAW_EXPECTED_DB_REVISION" in backend_gate_source
    assert 'or "047"' in backend_gate_source
    gateway_source = (backend.parent / "gateway/db.go").read_text()
    assert 'raw = "047"' in gateway_source
    assert "AUTHCLAW_EXPECTED_DB_REVISION" in gateway_source


def test_backend_database_revision_compatibility_is_tightly_bounded(monkeypatch):
    import pytest

    from app.core.startup_checks import compatible_database_revisions

    monkeypatch.delenv("AUTHCLAW_EXPECTED_DB_REVISION", raising=False)
    assert compatible_database_revisions() == ("047",)

    monkeypatch.setenv("AUTHCLAW_EXPECTED_DB_REVISION", "046, 047")
    assert compatible_database_revisions() == ("046", "047")

    for invalid in ("047,047", "46", "047,048", "045,046,047", "047,head"):
        monkeypatch.setenv("AUTHCLAW_EXPECTED_DB_REVISION", invalid)
        with pytest.raises(RuntimeError):
            compatible_database_revisions()

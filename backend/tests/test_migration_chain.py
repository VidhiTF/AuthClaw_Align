"""Keep merged migration history and runtime schema gates compatible."""

import json
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
import pytest


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
    assert scripts.get_heads() == ["053"]
    assert scripts.get_revision("053").down_revision == "052"
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


def test_platform_invite_resend_migration_qualifies_counter(monkeypatch):
    backend = Path(__file__).resolve().parents[1]
    config = Config(str(backend / "alembic.ini"))
    config.set_main_option("script_location", str(backend / "alembic"))
    migration = ScriptDirectory.from_config(config).get_revision("053").module
    statements = []
    monkeypatch.setattr(migration.op, "execute", statements.append)
    migration.upgrade()
    assert "resend_count = COALESCE(v_invite.resend_count, 0)" in statements[0]
    with pytest.raises(RuntimeError, match="restores broken invitation retries"):
        migration.downgrade()


def test_deployment_revision_defaults_match_database_head():
    root = Path(__file__).resolve().parents[2]
    ci = json.loads((root / "infra/terraform/ci.tfvars.json").read_text())
    example = (root / "infra/terraform/terraform.tfvars.example").read_text()
    assert ci["authclaw_env"] == "ci"
    assert ci["expected_db_revision"] == "053"
    assert "clickhouse_password" not in ci
    assert set(ci["quota_alert_sns_topic_arns"]) == {"primary", "secondary"}
    assert all(ci["quota_alert_sns_topic_arns"].values())
    assert ci["audit_consumer_environment"] == {
        "CLICKHOUSE_SECURE": "true",
        "KAFKA_SECURITY_PROTOCOL": "SASL_SSL",
    }
    assert set(ci["audit_consumer_secret_arns"]) == {
        "AUDIT_POSTGRES_URL",
        "KAFKA_SASL_USERNAME",
        "KAFKA_SASL_PASSWORD",
    }
    assert set(ci["secondary_audit_consumer_secret_arns"]) == set(
        ci["audit_consumer_secret_arns"]
    )
    assert 'expected_db_revision = "053"' in example


def test_backend_database_revision_compatibility_is_tightly_bounded(monkeypatch):
    import pytest

    from app.core.startup_checks import compatible_database_revisions

    monkeypatch.delenv("AUTHCLAW_EXPECTED_DB_REVISION", raising=False)
    assert compatible_database_revisions() == ("053",)

    monkeypatch.setenv("AUTHCLAW_EXPECTED_DB_REVISION", "053")
    assert compatible_database_revisions() == ("053",)

    for supported in ("052", "052,053", "053,052"):
        monkeypatch.setenv("AUTHCLAW_EXPECTED_DB_REVISION", supported)
        assert compatible_database_revisions() == tuple(supported.split(","))

    for invalid in ("053,053", "051", "051,052", "052,052", "050", "050,051", "049", "049,050", "050,050", "048,048", "47", "046,047", "046,047,048", "048,head"):
        monkeypatch.setenv("AUTHCLAW_EXPECTED_DB_REVISION", invalid)
        with pytest.raises(RuntimeError):
            compatible_database_revisions()

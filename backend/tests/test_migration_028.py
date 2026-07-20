import importlib.util
from pathlib import Path
from unittest.mock import MagicMock


def migration():
    path = (
        Path(__file__).parents[1]
        / "alembic"
        / "versions"
        / "028_add_legal_notice_acceptance.py"
    )
    spec = importlib.util.spec_from_file_location("migration_028", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_migration_adds_versioned_legal_acceptance_fields(monkeypatch):
    module = migration()
    add_column = MagicMock()
    monkeypatch.setattr(module.op, "add_column", add_column)

    module.upgrade()

    added = {(call.args[0], call.args[1].name) for call in add_column.call_args_list}
    assert added == {
        ("onboarding_email_otps", "terms_version"),
        ("onboarding_email_otps", "terms_accepted_at"),
        ("onboarding_email_otps", "privacy_notice_version"),
        ("onboarding_email_otps", "privacy_notice_acknowledged_at"),
    }


def test_migration_downgrade_removes_legal_acceptance_fields(monkeypatch):
    module = migration()
    drop_column = MagicMock()
    monkeypatch.setattr(module.op, "drop_column", drop_column)

    module.downgrade()

    assert [call.args for call in drop_column.call_args_list] == [
        ("onboarding_email_otps", "privacy_notice_acknowledged_at"),
        ("onboarding_email_otps", "privacy_notice_version"),
        ("onboarding_email_otps", "terms_accepted_at"),
        ("onboarding_email_otps", "terms_version"),
    ]

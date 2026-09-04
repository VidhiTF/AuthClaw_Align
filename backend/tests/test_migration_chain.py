"""Keep merged migration history and runtime schema gates compatible."""

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


def test_worker_migration_follows_platform_history_and_runtime_gates():
    backend = Path(__file__).resolve().parents[1]
    config = Config(str(backend / "alembic.ini"))
    config.set_main_option("script_location", str(backend / "alembic"))
    scripts = ScriptDirectory.from_config(config)
    assert scripts.get_heads() == ["046"]
    assert scripts.get_revision("046").down_revision == "045"
    assert scripts.get_revision("045").down_revision == "044"
    revisions = list(scripts.walk_revisions())
    assert len({revision.revision for revision in revisions}) == len(revisions)
    assert '"AUTHCLAW_EXPECTED_DB_REVISION", "046"' in (
        backend / "app/core/startup_checks.py"
    ).read_text()
    assert "version_num = '046'" in (backend.parent / "gateway/db.go").read_text()

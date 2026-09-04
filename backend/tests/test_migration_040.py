import importlib.util
from pathlib import Path

from app.core.crypto import decrypt_secret
from tests.legacy_crypto_fixture import encrypt_deterministic


def migration():
    path = Path(__file__).parents[1] / "alembic" / "versions" / "040_migrate_legacy_secret_ciphertext.py"
    spec = importlib.util.spec_from_file_location("migration_040", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_migration_converts_legacy_ciphertext_and_preserves_plaintext(monkeypatch):
    monkeypatch.setenv("ENVELOPE_KEY", "old-test-envelope-key-material-32!!")
    monkeypatch.setenv("AUTHCLAW_SECRET_PROVIDER", "env")
    monkeypatch.setenv("AUTHCLAW_SECRET_KEY_VERSION", "v1")
    module = migration()
    assert module.decrypt_secret.__module__ == "migration_support.secret_crypto_v040"
    legacy = encrypt_deterministic("legacy-secret")

    assert module._ENCRYPTED_COLUMNS == (
        ("provider_credentials", "encrypted_secret"),
        ("tenant_oidc_configs", "encrypted_client_secret"),
        ("cloud_connectors", "encrypted_secret"),
    )

    migrated = module._migrate_ciphertext(legacy)

    assert migrated.startswith("authclaw-secret-v2:env:v1:")
    assert decrypt_secret(migrated) == "legacy-secret"


def test_redaction_blind_index_matches_gateway_contract(monkeypatch):
    monkeypatch.setenv("REDACTION_HASH_SALT", "stable-test-redaction-index-key")
    module = migration()

    assert module._redaction_blind_index("tenant-a", "jane@example.com") == (
        "fc10707a35b6db97d9533e8a9651fdbc299fb94585b5d996cc3c45722ef2fcfb"
    )

import pytest

from app.core.crypto import encrypt_secret
from scripts import verify_secret_retirement as preflight


class Result:
    def __init__(self, values):
        self.values = values

    def scalars(self):
        return self

    def all(self):
        return self.values

    def __iter__(self):
        return iter((value,) for value in self.values)

    def close(self):
        pass


class Connection:
    dialect = type("Dialect", (), {"name": "postgresql"})()

    def __init__(self, values, revision="042"):
        self.values, self.revision = values, revision

    def execution_options(self, **_):
        return self

    def execute(self, statement):
        query = str(statement)
        if "version_num" in query:
            return Result([self.revision])
        for table, column in preflight.INVENTORY_COLUMNS:
            if f"public.{table}" in query:
                return Result(self.values.get(f"{table}.{column}", []))
        return Result([])


def test_preflight_authenticates_every_value_and_reports_versions(monkeypatch):
    monkeypatch.setenv("AUTHCLAW_SECRET_PROVIDER", "env")
    monkeypatch.setenv("AUTHCLAW_SECRET_KEY_VERSION", "v2")
    monkeypatch.setenv("ENVELOPE_KEY_V1", "old-test-envelope-key-material-32!!")
    monkeypatch.setenv("ENVELOPE_KEY_V2", "new-test-envelope-key-material-32!!")
    values = {
        "provider_credentials.encrypted_secret": [encrypt_secret("provider")],
        "tenant_oidc_configs.encrypted_client_secret": [encrypt_secret("oidc")],
        "cloud_connectors.encrypted_secret": [encrypt_secret("cloud")],
        "redaction_tokens.original_value": [encrypt_secret("redaction")],
        "users.mfa_secret": [encrypt_secret("mfa")],
    }
    report = preflight.inventory(Connection(values))
    assert report["passed"] is True
    assert all(column["rows"] == 1 for column in report["columns"].values())
    assert all(
        column["versions"] == {"env:v2": 1} for column in report["columns"].values()
    )


@pytest.mark.parametrize(
    "table,value,failure",
    [
        ("provider_credentials.encrypted_secret", "legacy-cbc", "legacy"),
        ("cloud_connectors.encrypted_secret", "unknown:v9:payload", "legacy"),
        (
            "redaction_tokens.original_value",
            "authclaw-secret-v2:vault:v1:not-base64",
            "gateway_incompatible",
        ),
        (
            "tenant_oidc_configs.encrypted_client_secret",
            "authclaw-secret-v2:unknown:v1:not-base64",
            "invalid_or_unreadable",
        ),
    ],
)
def test_preflight_fails_closed_without_reporting_values(table, value, failure):
    report = preflight.inventory(Connection({table: [value]}))
    assert report["passed"] is False
    assert report["columns"][table][failure] == 1
    assert value not in str(report)


def test_preflight_rejects_pre_migration_database():
    with pytest.raises(RuntimeError, match="040"):
        preflight.inventory(Connection({}, revision="039"))


def test_preflight_rejects_missing_key_used_only_by_mfa(monkeypatch):
    monkeypatch.setenv("AUTHCLAW_SECRET_PROVIDER", "env")
    monkeypatch.setenv("AUTHCLAW_SECRET_KEY_VERSION", "v7")
    monkeypatch.setenv("ENVELOPE_KEY_V7", "mfa-only-retained-key-material-32!!")
    ciphertext = encrypt_secret("synthetic-mfa-secret")
    monkeypatch.delenv("ENVELOPE_KEY_V7")
    report = preflight.inventory(Connection({"users.mfa_secret": [ciphertext]}))
    assert report["passed"] is False
    assert report["columns"]["users.mfa_secret"]["invalid_or_unreadable"] == 1


def test_runtime_has_no_cbc_compatibility_symbols():
    import app.core.crypto as crypto

    assert not hasattr(crypto, "encrypt_deterministic")
    assert not hasattr(crypto, "decrypt_deterministic")

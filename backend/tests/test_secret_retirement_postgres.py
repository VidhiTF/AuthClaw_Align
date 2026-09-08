"""Populated pre-040 upgrade and failure recovery on disposable PostgreSQL DBs."""

import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from app.core.crypto import decrypt_secret
from scripts.verify_secret_retirement import COLUMNS, inventory
from tests.db_safety import destructive_test_urls
from tests.legacy_crypto_fixture import encrypt_deterministic


@pytest.mark.parametrize("interrupted", [False, True])
def test_populated_pre040_upgrade_through_head_and_recovery(monkeypatch, interrupted):
    owner_url, app_url = destructive_test_urls()
    name = "authclaw_crypto_" + uuid.uuid4().hex + "_test"
    assert re.fullmatch(r"authclaw_crypto_[0-9a-f]{32}_test", name)
    admin = create_engine(owner_url, isolation_level="AUTOCOMMIT")
    database_url = (
        make_url(owner_url).set(database=name).render_as_string(hide_password=False)
    )
    engine = None
    created = False
    monkeypatch.setenv("ENVELOPE_KEY", "migration-test-envelope-key-32-bytes")
    monkeypatch.setenv("AUTHCLAW_SECRET_PROVIDER", "env")
    monkeypatch.setenv("AUTHCLAW_SECRET_KEY_VERSION", "v1")
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("ENVELOPE_KEY_V1", raising=False)
    environment = {
        **os.environ,
        "DATABASE_URL": database_url,
        "OWNER_DATABASE_URL": database_url,
        "BOOTSTRAP_DATABASE_URL": database_url,
        "POSTGRES_DB": name,
    }

    def migrate(revision):
        return subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", revision],
            cwd=Path(__file__).parents[1],
            env=environment,
            capture_output=True,
            text=True,
            timeout=120,
        )

    try:
        with admin.connect() as connection:
            connection.execute(text(f'CREATE DATABASE "{name}"'))
        created = True
        engine = create_engine(database_url)
        prepared = subprocess.run(
            [sys.executable, "scripts/bootstrap_database_security.py", "prepare"],
            cwd=Path(__file__).parents[1],
            env=environment,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert prepared.returncode == 0, prepared.stderr
        result = migrate("039")
        assert result.returncode == 0, result.stderr
        tenant, user = uuid.uuid4(), uuid.uuid4()
        legacy = encrypt_deterministic("synthetic-migration-secret")
        with engine.begin() as connection:
            connection.execute(
                text("INSERT INTO tenants (id, name) VALUES (:id, 'Migration tenant')"),
                {"id": tenant},
            )
            connection.execute(
                text(
                    "INSERT INTO users (id, tenant_id, email, platform_role) VALUES (:id, :tenant, 'migration@example.com', 'NONE')"
                ),
                {"id": user, "tenant": tenant},
            )
            connection.execute(
                text(
                    "INSERT INTO provider_credentials (id, tenant_id, provider, display_name, encrypted_secret, created_by) VALUES (:id, :tenant, 'openai', 'Migration', :secret, :user)"
                ),
                {"id": uuid.uuid4(), "tenant": tenant, "secret": legacy, "user": user},
            )
            connection.execute(
                text(
                    "INSERT INTO tenant_oidc_configs (id, tenant_id, issuer, client_id, encrypted_client_secret, redirect_uri) VALUES (:id, :tenant, 'https://idp.example', 'test', :secret, 'https://app.example/callback')"
                ),
                {"id": uuid.uuid4(), "tenant": tenant, "secret": legacy},
            )
            connection.execute(
                text(
                    "INSERT INTO cloud_connectors (id, tenant_id, provider, display_name, auth_type, encrypted_secret, created_by) VALUES (:id, :tenant, 'github', 'Migration', 'token', :secret, :user)"
                ),
                {"id": uuid.uuid4(), "tenant": tenant, "secret": legacy, "user": user},
            )
            connection.execute(
                text(
                    "INSERT INTO redaction_tokens (id, tenant_id, original_value, token_hash, token_value, strategy) VALUES (:id, :tenant, :secret, 'test-token-hash', 'MASKED', 'mask')"
                ),
                {
                    "id": uuid.uuid4(),
                    "tenant": tenant,
                    "secret": "corrupt" if interrupted else legacy,
                },
            )
        if interrupted:
            result = migrate("head")
            assert result.returncode != 0
            with engine.begin() as connection:
                assert (
                    connection.execute(
                        text("SELECT version_num FROM alembic_version")
                    ).scalar_one()
                    == "039"
                )
                # Failure after earlier columns were processed must roll them back.
                for table, column in COLUMNS[:-1]:
                    assert (
                        connection.execute(
                            text(f"SELECT {column} FROM {table}")
                        ).scalar_one()
                        == legacy
                    )
                connection.execute(
                    text("UPDATE redaction_tokens SET original_value = :secret"),
                    {"secret": legacy},
                )
        result = migrate("head")
        assert result.returncode == 0, result.stderr
        with engine.begin() as connection:
            for table, column in COLUMNS:
                value = connection.execute(
                    text(f"SELECT {column} FROM {table}")
                ).scalar_one()
                assert value.startswith("authclaw-secret-v2:")
                assert decrypt_secret(value) == "synthetic-migration-secret"
            assert (
                connection.execute(
                    text(
                        "SELECT length(original_value_blind_index) FROM redaction_tokens"
                    )
                ).scalar_one()
                == 64
            )
        with engine.connect() as connection, connection.begin():
            report = inventory(connection)
        assert report["passed"] is True
        assert all(
            report["columns"][f"{table}.{column}"]["rows"] == 1
            and report["columns"][f"{table}.{column}"]["legacy"] == 0
            for table, column in COLUMNS
        )
        monkeypatch.setenv("ENVELOPE_KEY", "wrong-test-envelope-key-material")
        with engine.connect() as connection, connection.begin():
            assert inventory(connection)["passed"] is False
        # The runtime role must error rather than certify invisible tenant rows.
        restricted = create_engine(make_url(app_url).set(database=name))
        try:
            with pytest.raises(DBAPIError):
                with restricted.connect() as connection, connection.begin():
                    inventory(connection)
        finally:
            restricted.dispose()
    finally:
        if engine is not None:
            engine.dispose()
        if created:
            # This exact random database was created above by this test only.
            assert re.fullmatch(r"authclaw_crypto_[0-9a-f]{32}_test", name)
            with admin.connect() as connection:
                connection.execute(text(f'DROP DATABASE "{name}"'))
        admin.dispose()

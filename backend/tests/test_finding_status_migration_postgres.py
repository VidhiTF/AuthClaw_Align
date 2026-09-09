"""Exercise revision 047 against real PostgreSQL, including its fail-closed path."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import uuid

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from tests.db_safety import destructive_test_urls


def test_revision_047_rejects_invalid_existing_status_then_recovers():
    owner_url, _ = destructive_test_urls()
    database_name = f"authclaw_finding_status_{uuid.uuid4().hex}_test"
    admin = create_engine(owner_url, isolation_level="AUTOCOMMIT")
    database_url = make_url(owner_url).set(database=database_name)
    owner = create_engine(database_url)
    environment = {
        **os.environ,
        "DATABASE_URL": database_url.render_as_string(hide_password=False),
        "BOOTSTRAP_DATABASE_URL": database_url.render_as_string(hide_password=False),
        "POSTGRES_DB": database_name,
    }

    def run_command(
        *arguments: str, succeeds: bool
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, *arguments],
            cwd=Path(__file__).parents[1],
            env=environment,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert (result.returncode == 0) is succeeds, result.stderr
        return result

    def run_alembic(revision: str, *, succeeds: bool) -> subprocess.CompletedProcess[str]:
        return run_command("-m", "alembic", "upgrade", revision, succeeds=succeeds)

    with admin.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{database_name}"'))
    try:
        run_command("scripts/bootstrap_database_security.py", "prepare", succeeds=True)
        run_alembic("046", succeeds=True)
        tenant_id = uuid.uuid4()
        finding_id = uuid.uuid4()
        with owner.begin() as connection:
            connection.execute(
                text("INSERT INTO tenants (id, name) VALUES (:id, :name)"),
                {"id": tenant_id, "name": "Finding migration regression"},
            )
            connection.execute(
                text(
                    """INSERT INTO findings
                    (id, tenant_id, framework, finding_key, title, severity,
                     status, finding_type, risk_score)
                    VALUES
                    (:id, :tenant_id, 'SOC2', 'migration|invalid-status',
                     'Invalid legacy status', 'medium', 'BANANA', 'AUDIT_GAP', 4.0)"""
                ),
                {"id": finding_id, "tenant_id": tenant_id},
            )

        failed = run_alembic("047", succeeds=False)
        assert "Cannot enforce finding status constraint" in failed.stderr
        with owner.connect() as connection:
            assert connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one() == "046"
            assert connection.execute(
                text(
                    """SELECT count(*) FROM pg_constraint
                       WHERE conname = 'ck_findings_status'"""
                )
            ).scalar_one() == 0

        with owner.begin() as connection:
            connection.execute(
                text("DELETE FROM findings WHERE id = :id"), {"id": finding_id}
            )
        run_alembic("047", succeeds=True)
        with owner.connect() as connection:
            assert connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one() == "047"
            assert connection.execute(
                text(
                    """SELECT convalidated FROM pg_constraint
                       WHERE conname = 'ck_findings_status'"""
                )
            ).scalar_one() is True
    finally:
        owner.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE "{database_name}"'))
        admin.dispose()

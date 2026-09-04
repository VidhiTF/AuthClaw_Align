"""Read-only deployment gate: inventory all migration-040 encrypted columns.

Run with a database role capable of reading every tenant, using the same key
configuration as the candidate backend/gateway images. Never print row values.
"""

import json
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text

from app.core.crypto import decrypt_secret

COLUMNS = (
    ("provider_credentials", "encrypted_secret"),
    ("tenant_oidc_configs", "encrypted_client_secret"),
    ("cloud_connectors", "encrypted_secret"),
    ("redaction_tokens", "original_value"),
)
# MFA is already AES-GCM (migration 039), but shares the runtime key ring.
# A missing retained key must not pass the gate merely because only MFA uses it.
INVENTORY_COLUMNS = COLUMNS + (("users", "mfa_secret"),)
GATEWAY_TABLES = {"provider_credentials", "redaction_tokens"}


def inventory(connection) -> dict:
    if connection.dialect.name != "postgresql":
        raise RuntimeError("PostgreSQL inventory is required")
    # row_security=off raises when RLS would hide rows; it does not grant bypass.
    # A restricted runtime role must never produce a false zero-row certificate.
    connection.execute(
        text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
    )
    connection.execute(text("SET LOCAL row_security = off"))
    revisions = (
        connection.execute(text("SELECT version_num FROM public.alembic_version"))
        .scalars()
        .all()
    )
    if len(revisions) != 1:
        raise RuntimeError("A single known database revision is required")
    config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    config.set_main_option(
        "script_location", str(Path(__file__).resolve().parents[1] / "alembic")
    )
    chain = ScriptDirectory.from_config(config).walk_revisions(
        base="base", head=revisions[0]
    )
    if "040" not in {revision.revision for revision in chain}:
        raise RuntimeError("Database must be migrated through 040")
    report = {"revision": revisions[0], "passed": True, "columns": {}}
    for table, column in INVENTORY_COLUMNS:
        counts = {
            "rows": 0,
            "legacy": 0,
            "invalid_or_unreadable": 0,
            "gateway_incompatible": 0,
            "versions": {},
        }
        rows = connection.execution_options(stream_results=True).execute(
            text(f"SELECT {column} FROM public.{table} WHERE {column} IS NOT NULL")
        )
        for (ciphertext,) in rows:
            counts["rows"] += 1
            if ciphertext.startswith("authclaw-secret-v1:"):
                provider, version = "env", "legacy-gcm-v1"
            elif ciphertext.startswith("authclaw-secret-v2:"):
                parts = ciphertext.split(":", 3)
                if len(parts) != 4 or not re.fullmatch(
                    r"[A-Za-z0-9_-]{1,32}", parts[2]
                ):
                    counts["invalid_or_unreadable"] += 1
                    continue
                provider, version = parts[1:3]
                if provider not in {"env", "vault", "aws_kms"}:
                    counts["invalid_or_unreadable"] += 1
                    continue
            else:
                counts["legacy"] += 1
                continue
            label = f"{provider}:{version}"
            counts["versions"][label] = counts["versions"].get(label, 0) + 1
            if table in GATEWAY_TABLES and provider != "env":
                counts["gateway_incompatible"] += 1
            try:
                # Authenticated decryption verifies actual key availability,
                # including retained key versions, not just their env names.
                decrypt_secret(ciphertext)
            except Exception:
                counts["invalid_or_unreadable"] += 1
        rows.close()
        if (
            counts["legacy"]
            or counts["invalid_or_unreadable"]
            or counts["gateway_incompatible"]
        ):
            report["passed"] = False
        report["columns"][f"{table}.{column}"] = counts
    return report


def main() -> int:
    try:
        engine = create_engine(os.environ["DATABASE_URL"], echo=False)
        try:
            with engine.connect() as connection, connection.begin():
                report = inventory(connection)
        finally:
            engine.dispose()
    except Exception as exc:
        report = {"passed": False, "error_type": type(exc).__name__}
    print(json.dumps(report, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

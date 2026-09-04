"""Migrate legacy AES-CBC ciphertext to versioned AES-GCM envelopes.

Revision ID: 040
Revises: 039
"""

import hashlib
import hmac
import os

from alembic import op
import sqlalchemy as sa

from migration_support.secret_crypto_v040 import (
    SECRET_ENVELOPE_PREFIX,
    SECRET_ENVELOPE_V2_PREFIX,
    decrypt_secret,
    encrypt_secret,
)


revision = "040"
down_revision = "039"
branch_labels = None
depends_on = None

_ENCRYPTED_COLUMNS = (
    ("provider_credentials", "encrypted_secret"),
    ("tenant_oidc_configs", "encrypted_client_secret"),
    ("cloud_connectors", "encrypted_secret"),
)
_DEFAULT_REDACTION_HASH_SALT = "authclaw_redaction_salt_v1"


def _is_legacy(ciphertext: str) -> bool:
    return not ciphertext.startswith((SECRET_ENVELOPE_PREFIX, SECRET_ENVELOPE_V2_PREFIX))


def _migrate_ciphertext(ciphertext: str) -> str:
    return encrypt_secret(decrypt_secret(ciphertext)) if _is_legacy(ciphertext) else ciphertext


def _redaction_blind_index(tenant_id: str, plaintext: str) -> str:
    salt = os.getenv("REDACTION_HASH_SALT", _DEFAULT_REDACTION_HASH_SALT).encode()
    derived = hmac.new(salt, b"authclaw-redaction-blind-index-v1", hashlib.sha256).digest()
    return hmac.new(derived, tenant_id.encode() + b"\0" + plaintext.encode(), hashlib.sha256).hexdigest()


def upgrade():
    bind = op.get_bind()

    for table, column in _ENCRYPTED_COLUMNS:
        rows = list(
            bind.execute(
                sa.text(f"SELECT id, {column} FROM {table} WHERE {column} IS NOT NULL")
            )
        )
        for row_id, ciphertext in rows:
            if _is_legacy(ciphertext):
                bind.execute(
                    sa.text(f"UPDATE {table} SET {column} = :ciphertext WHERE id = :id"),
                    {"id": row_id, "ciphertext": _migrate_ciphertext(ciphertext)},
                )

    redaction_rows = list(
        bind.execute(
            sa.text(
                "SELECT id, tenant_id, original_value, strategy FROM redaction_tokens"
            )
        )
    )
    seen = set()
    for row_id, tenant_id, ciphertext, strategy in redaction_rows:
        plaintext = decrypt_secret(ciphertext)
        blind_index = _redaction_blind_index(str(tenant_id), plaintext)
        identity = (str(tenant_id), blind_index, strategy)
        if identity in seen:
            raise RuntimeError("Duplicate redaction token prevents blind-index migration")
        seen.add(identity)
        bind.execute(
            sa.text(
                "UPDATE redaction_tokens SET original_value = :ciphertext, "
                "original_value_blind_index = :blind_index WHERE id = :id"
            ),
            {
                "id": row_id,
                "ciphertext": _migrate_ciphertext(ciphertext),
                "blind_index": blind_index,
            },
        )

    for table, column in (*_ENCRYPTED_COLUMNS, ("redaction_tokens", "original_value")):
        remaining = bind.execute(
            sa.text(
                f"SELECT COUNT(*) FROM {table} WHERE {column} IS NOT NULL "
                f"AND {column} NOT LIKE :v1 AND {column} NOT LIKE :v2"
            ),
            {"v1": f"{SECRET_ENVELOPE_PREFIX}%", "v2": f"{SECRET_ENVELOPE_V2_PREFIX}%"},
        ).scalar_one()
        if remaining:
            raise RuntimeError(f"Legacy ciphertext remains in {table}.{column}")

    op.alter_column(
        "redaction_tokens",
        "original_value_blind_index",
        existing_type=sa.String(length=64),
        nullable=False,
    )


def downgrade():
    # Ciphertext remains in the stronger envelope format; revision 038 can read it.
    op.alter_column(
        "redaction_tokens",
        "original_value_blind_index",
        existing_type=sa.String(length=64),
        nullable=True,
    )

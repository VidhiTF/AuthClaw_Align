"""Encrypt MFA secrets and hash backup codes.

Revision ID: 039
Revises: 038
"""

from alembic import op
import sqlalchemy as sa

from app.core.crypto import (
    SECRET_ENVELOPE_PREFIX,
    SECRET_ENVELOPE_V2_PREFIX,
    decrypt_secret,
    encrypt_secret,
)
from app.core.auth import hash_key


revision = "039"
down_revision = "038"
branch_labels = None
depends_on = None


def upgrade():
    # Some local databases received this column from the old role bootstrap.
    op.execute(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_backup_codes VARCHAR[]"
    )
    op.alter_column(
        "users",
        "mfa_secret",
        existing_type=sa.String(length=32),
        type_=sa.Text(),
    )
    bind = op.get_bind()
    rows = bind.execute(
        sa.text(
            "SELECT id, mfa_secret, mfa_backup_codes "
            "FROM users WHERE mfa_secret IS NOT NULL"
        )
    )
    for user_id, secret, backup_codes in rows:
        encrypted = secret.startswith(
            (SECRET_ENVELOPE_PREFIX, SECRET_ENVELOPE_V2_PREFIX)
        )
        hashed_codes = [
            code if len(code) == 64 else hash_key(f"mfa-backup:{code.lower()}")
            for code in (backup_codes or [])
        ]
        bind.execute(
            sa.text(
                "UPDATE users SET mfa_secret = :secret, "
                "mfa_backup_codes = :codes WHERE id = :id"
            ),
            {
                "id": user_id,
                "secret": secret if encrypted else encrypt_secret(secret),
                "codes": hashed_codes,
            },
        )


def downgrade():
    bind = op.get_bind()
    rows = bind.execute(
        sa.text("SELECT id, mfa_secret FROM users WHERE mfa_secret IS NOT NULL")
    )
    for user_id, secret in rows:
        encrypted = secret.startswith(
            (SECRET_ENVELOPE_PREFIX, SECRET_ENVELOPE_V2_PREFIX)
        )
        bind.execute(
            sa.text(
                "UPDATE users SET mfa_secret = :secret, "
                "mfa_backup_codes = NULL WHERE id = :id"
            ),
            {
                "id": user_id,
                "secret": decrypt_secret(secret) if encrypted else secret,
            },
        )
    op.alter_column(
        "users",
        "mfa_secret",
        existing_type=sa.Text(),
        type_=sa.String(length=32),
    )
    op.drop_column("users", "mfa_backup_codes")

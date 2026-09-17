"""Prevent replay of accepted TOTP time-steps.

Revision ID: 050
Revises: 049
"""

import sqlalchemy as sa
from alembic import op


revision = "050"
down_revision = "049"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("mfa_last_totp_counter", sa.BigInteger(), nullable=True),
    )
    op.add_column("users", sa.Column("mfa_pending_secret", sa.Text(), nullable=True))
    op.add_column(
        "users",
        sa.Column("mfa_pending_backup_codes", sa.ARRAY(sa.String()), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column("mfa_pending_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column("mfa_enrolled_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("users", "mfa_enrolled_at")
    op.drop_column("users", "mfa_pending_expires_at")
    op.drop_column("users", "mfa_pending_backup_codes")
    op.drop_column("users", "mfa_pending_secret")
    op.drop_column("users", "mfa_last_totp_counter")

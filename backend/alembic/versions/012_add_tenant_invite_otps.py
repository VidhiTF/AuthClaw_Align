"""Add tenant invite metadata to OTP table

Revision ID: 012
Revises: 011
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "012"
down_revision = "011"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "onboarding_email_otps" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("onboarding_email_otps")}
    if "purpose" not in columns:
        op.add_column(
            "onboarding_email_otps",
            sa.Column("purpose", sa.String(50), nullable=False, server_default="signup"),
        )
    if "invited_role" not in columns:
        op.add_column("onboarding_email_otps", sa.Column("invited_role", sa.String(50), nullable=True))
    if "invited_by" not in columns:
        op.add_column("onboarding_email_otps", sa.Column("invited_by", postgresql.UUID(as_uuid=True), nullable=True))
        op.create_foreign_key(
            "onboarding_email_otps_invited_by_fkey",
            "onboarding_email_otps",
            "users",
            ["invited_by"],
            ["id"],
            ondelete="SET NULL",
        )
    if "idx_onboarding_otp_purpose" not in {idx["name"] for idx in inspector.get_indexes("onboarding_email_otps")}:
        op.create_index("idx_onboarding_otp_purpose", "onboarding_email_otps", ["purpose"])


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "onboarding_email_otps" not in inspector.get_table_names():
        return

    indexes = {idx["name"] for idx in inspector.get_indexes("onboarding_email_otps")}
    if "idx_onboarding_otp_purpose" in indexes:
        op.drop_index("idx_onboarding_otp_purpose", table_name="onboarding_email_otps")

    columns = {column["name"] for column in inspector.get_columns("onboarding_email_otps")}
    if "invited_by" in columns:
        op.drop_constraint("onboarding_email_otps_invited_by_fkey", "onboarding_email_otps", type_="foreignkey")
        op.drop_column("onboarding_email_otps", "invited_by")
    if "invited_role" in columns:
        op.drop_column("onboarding_email_otps", "invited_role")
    if "purpose" in columns:
        op.drop_column("onboarding_email_otps", "purpose")

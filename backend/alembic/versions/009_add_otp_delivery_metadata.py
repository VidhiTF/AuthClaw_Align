"""Add OTP delivery metadata

Revision ID: 009
Revises: 008
"""
from alembic import op
import sqlalchemy as sa


revision = "009"
down_revision = "008"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "onboarding_email_otps" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("onboarding_email_otps")}
    if "sent_at" not in columns:
        op.add_column("onboarding_email_otps", sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True))
    if "resend_count" not in columns:
        op.add_column(
            "onboarding_email_otps",
            sa.Column("resend_count", sa.Integer(), nullable=False, server_default="0"),
        )
    if "last_delivery" not in columns:
        op.add_column("onboarding_email_otps", sa.Column("last_delivery", sa.String(50), nullable=True))
    if "delivery_error" not in columns:
        op.add_column("onboarding_email_otps", sa.Column("delivery_error", sa.Text(), nullable=True))


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "onboarding_email_otps" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("onboarding_email_otps")}
    for column_name in ("delivery_error", "last_delivery", "resend_count", "sent_at"):
        if column_name in columns:
            op.drop_column("onboarding_email_otps", column_name)

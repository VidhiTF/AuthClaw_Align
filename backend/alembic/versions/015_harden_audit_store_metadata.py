"""Harden audit store metadata coverage

Revision ID: 015
Revises: 014
"""

from alembic import op
import sqlalchemy as sa


revision = "015"
down_revision = "014"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "audit_log_metadata" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("audit_log_metadata")}
    if "actor_type" not in columns:
        op.add_column(
            "audit_log_metadata",
            sa.Column("actor_type", sa.String(100), nullable=False, server_default="gateway"),
        )
    if "execution_trace" not in columns:
        op.add_column(
            "audit_log_metadata",
            sa.Column("execution_trace", sa.Text(), nullable=False, server_default="[]"),
        )


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "audit_log_metadata" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("audit_log_metadata")}
    if "execution_trace" in columns:
        op.drop_column("audit_log_metadata", "execution_trace")
    if "actor_type" in columns:
        op.drop_column("audit_log_metadata", "actor_type")

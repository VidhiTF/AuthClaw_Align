"""Add Postgres audit hash chain fields

Revision ID: 011
Revises: 010
"""
from alembic import op
import sqlalchemy as sa


revision = "011"
down_revision = "010"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "audit_log_metadata" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("audit_log_metadata")}
    if "prior_hash" not in columns:
        op.add_column("audit_log_metadata", sa.Column("prior_hash", sa.String(64), nullable=True))
    if "integrity_hash" not in columns:
        op.add_column("audit_log_metadata", sa.Column("integrity_hash", sa.String(64), nullable=True))


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "audit_log_metadata" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("audit_log_metadata")}
    if "integrity_hash" in columns:
        op.drop_column("audit_log_metadata", "integrity_hash")
    if "prior_hash" in columns:
        op.drop_column("audit_log_metadata", "prior_hash")

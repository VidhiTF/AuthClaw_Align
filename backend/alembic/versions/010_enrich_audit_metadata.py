"""Enrich Postgres audit metadata fallback

Revision ID: 010
Revises: 009
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "010"
down_revision = "009"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "audit_log_metadata" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("audit_log_metadata")}
    additions = [
        ("request_id", sa.String(255), True),
        ("policy_id", postgresql.UUID(as_uuid=True), True),
        ("provider", sa.String(100), True),
        ("model", sa.String(255), True),
        ("reason", sa.Text(), True),
        ("prompt_count", sa.Integer(), False),
        ("request_size", sa.Integer(), False),
        ("response_status", sa.Integer(), False),
        ("duration_ms", sa.Integer(), False),
    ]
    for name, column_type, nullable in additions:
        if name not in columns:
            if nullable:
                op.add_column("audit_log_metadata", sa.Column(name, column_type, nullable=True))
            else:
                op.add_column(
                    "audit_log_metadata",
                    sa.Column(name, column_type, nullable=False, server_default="0"),
                )


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "audit_log_metadata" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("audit_log_metadata")}
    for name in (
        "duration_ms",
        "response_status",
        "request_size",
        "prompt_count",
        "reason",
        "model",
        "provider",
        "policy_id",
        "request_id",
    ):
        if name in columns:
            op.drop_column("audit_log_metadata", name)

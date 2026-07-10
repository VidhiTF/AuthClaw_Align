"""Harden redaction engine retention metadata

Revision ID: 017
Revises: 016
Create Date: 2026-06-30 13:30:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "017"
down_revision = "016"
branch_labels = None
depends_on = None


def _columns(table_name: str) -> set[str]:
    bind = op.get_bind()
    rows = bind.execute(
        sa.text(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = :table_name
            """
        ),
        {"table_name": table_name},
    )
    return {row[0] for row in rows}


def upgrade():
    gateway_columns = _columns("gateway_configs")
    token_columns = _columns("redaction_tokens")

    if "redaction_token_retention_days" not in gateway_columns:
        op.add_column(
            "gateway_configs",
            sa.Column(
                "redaction_token_retention_days",
                sa.Integer(),
                nullable=False,
                server_default="90",
            ),
        )

    if "entity_type" not in token_columns:
        op.add_column("redaction_tokens", sa.Column("entity_type", sa.String(length=100), nullable=True))
    if "expires_at" not in token_columns:
        op.add_column("redaction_tokens", sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))
    if "last_used_at" not in token_columns:
        op.add_column("redaction_tokens", sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True))
    if "use_count" not in token_columns:
        op.add_column("redaction_tokens", sa.Column("use_count", sa.Integer(), nullable=False, server_default="0"))
    if "purged_at" not in token_columns:
        op.add_column("redaction_tokens", sa.Column("purged_at", sa.DateTime(timezone=True), nullable=True))

    op.execute(
        """
        UPDATE redaction_tokens
        SET expires_at = COALESCE(expires_at, created_at + INTERVAL '90 days'),
            last_used_at = COALESCE(last_used_at, created_at),
            use_count = COALESCE(use_count, 0)
        """
    )

    op.create_index("idx_redaction_expires", "redaction_tokens", ["tenant_id", "expires_at"], if_not_exists=True)
    op.create_index("idx_redaction_purged", "redaction_tokens", ["tenant_id", "purged_at"], if_not_exists=True)
    op.create_index("idx_redaction_entity", "redaction_tokens", ["tenant_id", "entity_type"], if_not_exists=True)


def downgrade():
    for index_name in ["idx_redaction_entity", "idx_redaction_purged", "idx_redaction_expires"]:
        op.drop_index(index_name, table_name="redaction_tokens", if_exists=True)

    token_columns = _columns("redaction_tokens")
    for column_name in ["purged_at", "use_count", "last_used_at", "expires_at", "entity_type"]:
        if column_name in token_columns:
            op.drop_column("redaction_tokens", column_name)

    gateway_columns = _columns("gateway_configs")
    if "redaction_token_retention_days" in gateway_columns:
        op.drop_column("gateway_configs", "redaction_token_retention_days")

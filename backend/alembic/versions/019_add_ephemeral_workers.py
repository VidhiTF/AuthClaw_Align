"""Add ephemeral worker token tables

Revision ID: 019
Revises: 018
Create Date: 2026-06-30 18:30:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "019"
down_revision = "018"
branch_labels = None
depends_on = None


def _tenant_rls(table_name: str) -> None:
    op.execute(f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY;")
    op.execute(f"ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY;")
    op.execute(
        f"""
        CREATE POLICY {table_name}_tenant_isolation
        ON {table_name}
        USING (
            tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
        );
        """
    )


def upgrade():
    op.create_table(
        "ephemeral_worker_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("workflow_id", sa.String(length=255), nullable=True),
        sa.Column("action_id", sa.String(length=255), nullable=False),
        sa.Column("connector", sa.String(length=50), nullable=False),
        sa.Column("purpose", sa.String(length=50), nullable=False),
        sa.Column("scopes", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("permission_boundary", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("token_prefix", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="active"),
        sa.Column("issued_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_action", sa.String(length=255), nullable=True),
        sa.Column("use_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("metadata_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.UniqueConstraint("token_hash", name="uq_ephemeral_worker_token_hash"),
    )
    op.create_index("idx_ephemeral_worker_token_tenant", "ephemeral_worker_tokens", ["tenant_id"])
    op.create_index("idx_ephemeral_worker_token_status", "ephemeral_worker_tokens", ["tenant_id", "status", "expires_at"])
    op.create_index("idx_ephemeral_worker_token_workflow", "ephemeral_worker_tokens", ["tenant_id", "workflow_id"])
    op.create_index("idx_ephemeral_worker_token_prefix", "ephemeral_worker_tokens", ["token_prefix"])

    op.create_table(
        "ephemeral_worker_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("worker_token_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("ephemeral_worker_tokens.id"), nullable=True),
        sa.Column("connector", sa.String(length=50), nullable=False),
        sa.Column("action", sa.String(length=255), nullable=False),
        sa.Column("required_scope", sa.String(length=255), nullable=False),
        sa.Column("destructive", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.create_index("idx_ephemeral_worker_run_tenant", "ephemeral_worker_runs", ["tenant_id", "started_at"])
    op.create_index("idx_ephemeral_worker_run_token", "ephemeral_worker_runs", ["worker_token_id"])
    op.create_index("idx_ephemeral_worker_run_status", "ephemeral_worker_runs", ["tenant_id", "status"])
    op.create_index("idx_ephemeral_worker_run_connector", "ephemeral_worker_runs", ["tenant_id", "connector"])

    _tenant_rls("ephemeral_worker_tokens")
    _tenant_rls("ephemeral_worker_runs")


def downgrade():
    for table in ("ephemeral_worker_runs", "ephemeral_worker_tokens"):
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY;")

    op.drop_index("idx_ephemeral_worker_run_connector", table_name="ephemeral_worker_runs")
    op.drop_index("idx_ephemeral_worker_run_status", table_name="ephemeral_worker_runs")
    op.drop_index("idx_ephemeral_worker_run_token", table_name="ephemeral_worker_runs")
    op.drop_index("idx_ephemeral_worker_run_tenant", table_name="ephemeral_worker_runs")
    op.drop_table("ephemeral_worker_runs")

    op.drop_index("idx_ephemeral_worker_token_prefix", table_name="ephemeral_worker_tokens")
    op.drop_index("idx_ephemeral_worker_token_workflow", table_name="ephemeral_worker_tokens")
    op.drop_index("idx_ephemeral_worker_token_status", table_name="ephemeral_worker_tokens")
    op.drop_index("idx_ephemeral_worker_token_tenant", table_name="ephemeral_worker_tokens")
    op.drop_table("ephemeral_worker_tokens")

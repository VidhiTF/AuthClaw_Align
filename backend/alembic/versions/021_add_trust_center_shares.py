"""Add Trust Center shares

Revision ID: 021
Revises: 020
Create Date: 2026-07-01 11:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "021"
down_revision = "020"
branch_labels = None
depends_on = None


def _tenant_rls(table: str) -> None:
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
    op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")
    op.execute(
        f"""
        CREATE POLICY {table}_tenant_isolation
        ON {table}
        USING (
            tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
        );
        """
    )


def upgrade():
    op.create_table(
        "trust_center_shares",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("label", sa.String(length=255), nullable=False),
        sa.Column("auditor_email", sa.String(length=255), nullable=True),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("token_prefix", sa.String(length=32), nullable=False),
        sa.Column("frameworks", postgresql.ARRAY(sa.String()), nullable=False, server_default=sa.text("'{}'::varchar[]")),
        sa.Column("permissions", postgresql.ARRAY(sa.String()), nullable=False, server_default=sa.text("'{}'::varchar[]")),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="active"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_accessed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("access_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("metadata_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.UniqueConstraint("token_hash", name="uq_trust_center_share_token_hash"),
    )
    op.create_index("idx_trust_share_tenant", "trust_center_shares", ["tenant_id"])
    op.create_index("idx_trust_share_status", "trust_center_shares", ["tenant_id", "status", "expires_at"])
    op.create_index("idx_trust_share_prefix", "trust_center_shares", ["token_prefix"])

    op.create_table(
        "trust_center_access_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("share_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("trust_center_shares.id"), nullable=False),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("accessed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
    )
    op.create_index("idx_trust_access_tenant", "trust_center_access_logs", ["tenant_id", "accessed_at"])
    op.create_index("idx_trust_access_share", "trust_center_access_logs", ["share_id"])

    _tenant_rls("trust_center_shares")
    _tenant_rls("trust_center_access_logs")

    op.execute(
        """
        CREATE OR REPLACE FUNCTION resolve_trust_center_share(p_token_hash TEXT)
        RETURNS TABLE(id UUID, tenant_id UUID, status TEXT, expires_at TIMESTAMPTZ)
        LANGUAGE SQL
        SECURITY DEFINER
        SET search_path = public
        AS $$
            SELECT s.id, s.tenant_id, s.status, s.expires_at
            FROM trust_center_shares s
            WHERE s.token_hash = p_token_hash
            LIMIT 1;
        $$;
        """
    )


def downgrade():
    op.execute("DROP FUNCTION IF EXISTS resolve_trust_center_share(TEXT)")

    for table in ("trust_center_access_logs", "trust_center_shares"):
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY;")

    op.drop_index("idx_trust_access_share", table_name="trust_center_access_logs")
    op.drop_index("idx_trust_access_tenant", table_name="trust_center_access_logs")
    op.drop_table("trust_center_access_logs")
    op.drop_index("idx_trust_share_prefix", table_name="trust_center_shares")
    op.drop_index("idx_trust_share_status", table_name="trust_center_shares")
    op.drop_index("idx_trust_share_tenant", table_name="trust_center_shares")
    op.drop_table("trust_center_shares")

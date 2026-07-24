"""Enforce RLS for P0 tenant resources.

Revision ID: 036
Revises: 035
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "036"
down_revision = "035"
branch_labels = None
depends_on = None


def _ensure_tenant_rls(table: str, policy: str) -> None:
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
    op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")
    op.execute(
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies
                WHERE schemaname = 'public'
                  AND tablename = '{table}'
                  AND policyname = '{policy}'
            ) THEN
                CREATE POLICY {policy} ON {table}
                    FOR ALL
                    USING (tenant_id = current_setting('app.current_tenant_id')::uuid)
                    WITH CHECK (tenant_id = current_setting('app.current_tenant_id')::uuid);
            END IF;
        END
        $$;
        """
    )


def upgrade():
    op.execute("ALTER TABLE approval_audit ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE approval_audit FORCE ROW LEVEL SECURITY;")
    op.execute(
        """
        CREATE POLICY approval_audit_tenant_isolation
        ON approval_audit
        USING (
            tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
        );
        """
    )

    op.create_table(
        "aws_usage_limits",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("daily_requests", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("daily_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_daily_requests", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("max_daily_tokens", sa.Integer(), nullable=False, server_default="50000"),
        sa.Column("max_daily_cost_usd", sa.Numeric(10, 4), nullable=False, server_default="1.0000"),
        sa.Column("daily_cost_estimate", sa.Numeric(10, 4), nullable=False, server_default="0.0000"),
        sa.Column("last_reset", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.UniqueConstraint("tenant_id", name="uq_aws_usage_tenant"),
        if_not_exists=True,
    )
    op.create_index("idx_aws_usage_tenant", "aws_usage_limits", ["tenant_id"], if_not_exists=True)

    op.create_table(
        "aws_s3_documents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("bucket_name", sa.String(length=255), nullable=False),
        sa.Column("object_key", sa.Text(), nullable=False),
        sa.Column("file_name", sa.String(length=512), nullable=False),
        sa.Column("file_size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("content_type", sa.String(length=255), nullable=True),
        sa.Column("last_modified", sa.DateTime(timezone=True), nullable=True),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("etag", sa.String(length=255), nullable=True),
        sa.UniqueConstraint("tenant_id", "bucket_name", "object_key", name="uq_s3_doc_tenant_key"),
        if_not_exists=True,
    )
    op.create_index("idx_s3_docs_tenant", "aws_s3_documents", ["tenant_id"], if_not_exists=True)
    op.create_index("idx_s3_docs_synced", "aws_s3_documents", [sa.text("synced_at DESC")], if_not_exists=True)

    _ensure_tenant_rls("aws_usage_limits", "aws_usage_limits_isolation")
    _ensure_tenant_rls("aws_s3_documents", "aws_s3_docs_isolation")


def downgrade():
    for table in ("aws_s3_documents", "aws_usage_limits"):
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY;")

    op.execute("DROP POLICY IF EXISTS approval_audit_tenant_isolation ON approval_audit;")
    op.execute("ALTER TABLE approval_audit NO FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE approval_audit DISABLE ROW LEVEL SECURITY;")

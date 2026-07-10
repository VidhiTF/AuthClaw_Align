"""Add cloud connector credentials

Revision ID: 023
Revises: 022
Create Date: 2026-07-07 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "023"
down_revision = "022"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "cloud_connectors",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("provider", sa.String(length=50), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("auth_type", sa.String(length=50), nullable=False),
        sa.Column("encrypted_secret", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="pending"),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("metadata_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.create_index("idx_cloud_connector_tenant", "cloud_connectors", ["tenant_id"])
    op.create_index("idx_cloud_connector_provider", "cloud_connectors", ["tenant_id", "provider"])
    op.create_index("idx_cloud_connector_status", "cloud_connectors", ["tenant_id", "status"])
    op.execute("ALTER TABLE cloud_connectors ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE cloud_connectors FORCE ROW LEVEL SECURITY;")
    op.execute(
        """
        CREATE POLICY cloud_connectors_tenant_isolation
        ON cloud_connectors
        USING (
            tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
        );
        """
    )


def downgrade():
    op.execute("DROP POLICY IF EXISTS cloud_connectors_tenant_isolation ON cloud_connectors")
    op.execute("ALTER TABLE cloud_connectors NO FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE cloud_connectors DISABLE ROW LEVEL SECURITY;")
    op.drop_index("idx_cloud_connector_status", table_name="cloud_connectors")
    op.drop_index("idx_cloud_connector_provider", table_name="cloud_connectors")
    op.drop_index("idx_cloud_connector_tenant", table_name="cloud_connectors")
    op.drop_table("cloud_connectors")

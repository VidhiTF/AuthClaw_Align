"""Add tenant OIDC SSO configuration

Revision ID: 024
Revises: 023
Create Date: 2026-07-07 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "024"
down_revision = "023"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "tenant_oidc_configs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False, unique=True),
        sa.Column("issuer", sa.String(length=512), nullable=False),
        sa.Column("client_id", sa.String(length=255), nullable=False),
        sa.Column("encrypted_client_secret", sa.Text(), nullable=True),
        sa.Column("redirect_uri", sa.String(length=512), nullable=False),
        sa.Column("scopes", postgresql.ARRAY(sa.String()), nullable=False, server_default=sa.text("ARRAY['openid','email','profile']")),
        sa.Column("authorization_endpoint", sa.String(length=512), nullable=True),
        sa.Column("token_endpoint", sa.String(length=512), nullable=True),
        sa.Column("jwks_uri", sa.String(length=512), nullable=True),
        sa.Column("email_claim", sa.String(length=100), nullable=False, server_default="email"),
        sa.Column("groups_claim", sa.String(length=100), nullable=False, server_default="groups"),
        sa.Column("role_mapping", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("default_role", sa.String(length=50), nullable=False, server_default="viewer"),
        sa.Column("auto_provision", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="disabled"),
        sa.Column("last_tested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
    )
    op.create_index("idx_tenant_oidc_config_tenant", "tenant_oidc_configs", ["tenant_id"])
    op.create_index("idx_tenant_oidc_config_status", "tenant_oidc_configs", ["tenant_id", "status"])
    op.execute("ALTER TABLE tenant_oidc_configs ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE tenant_oidc_configs FORCE ROW LEVEL SECURITY;")
    op.execute(
        """
        CREATE POLICY tenant_oidc_configs_tenant_isolation
        ON tenant_oidc_configs
        USING (
            tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
        );
        """
    )


def downgrade():
    op.execute("DROP POLICY IF EXISTS tenant_oidc_configs_tenant_isolation ON tenant_oidc_configs")
    op.execute("ALTER TABLE tenant_oidc_configs NO FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE tenant_oidc_configs DISABLE ROW LEVEL SECURITY;")
    op.drop_index("idx_tenant_oidc_config_status", table_name="tenant_oidc_configs")
    op.drop_index("idx_tenant_oidc_config_tenant", table_name="tenant_oidc_configs")
    op.drop_table("tenant_oidc_configs")

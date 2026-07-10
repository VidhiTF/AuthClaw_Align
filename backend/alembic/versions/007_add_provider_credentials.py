"""Add provider credentials vault for AuthClaw Lite

Revision ID: 007
Revises: 006
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "007"
down_revision = "006"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "provider_credentials" not in inspector.get_table_names():
        op.create_table(
            "provider_credentials",
            sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("provider", sa.String(50), nullable=False),
            sa.Column("display_name", sa.String(255), nullable=False),
            sa.Column("endpoint", sa.String(512), nullable=True),
            sa.Column("encrypted_secret", sa.Text(), nullable=False),
            sa.Column("auth_scheme", sa.String(50), nullable=False, server_default="api_key"),
            sa.Column("status", sa.String(50), nullable=False, server_default="active"),
            sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("idx_provider_credential_tenant", "provider_credentials", ["tenant_id"])
        op.create_index("idx_provider_credential_provider", "provider_credentials", ["tenant_id", "provider"])
        op.create_index("idx_provider_credential_status", "provider_credentials", ["status"])

    op.execute("ALTER TABLE provider_credentials ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE provider_credentials FORCE ROW LEVEL SECURITY;")
    op.execute("""
    CREATE POLICY provider_credentials_tenant_isolation
    ON provider_credentials
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
    );
    """)


def downgrade():
    op.execute("DROP POLICY IF EXISTS provider_credentials_tenant_isolation ON provider_credentials;")
    op.execute("ALTER TABLE provider_credentials NO FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE provider_credentials DISABLE ROW LEVEL SECURITY;")
    op.drop_table("provider_credentials")

"""Add Lite self-service onboarding

Revision ID: 008
Revises: 007
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "008"
down_revision = "007"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    op.execute("""
    DO $$
    BEGIN
        IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_role') THEN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_enum e
                JOIN pg_type t ON t.oid = e.enumtypid
                WHERE t.typname = 'user_role' AND e.enumlabel = 'owner'
            ) THEN
                ALTER TYPE user_role ADD VALUE 'owner';
            END IF;
            IF NOT EXISTS (
                SELECT 1
                FROM pg_enum e
                JOIN pg_type t ON t.oid = e.enumtypid
                WHERE t.typname = 'user_role' AND e.enumlabel = 'developer'
            ) THEN
                ALTER TYPE user_role ADD VALUE 'developer';
            END IF;
        END IF;
    END
    $$;
    """)

    if "onboarding_email_otps" not in inspector.get_table_names():
        op.create_table(
            "onboarding_email_otps",
            sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("email", sa.String(255), nullable=False),
            sa.Column("tenant_name", sa.String(255), nullable=False),
            sa.Column("otp_hash", sa.String(255), nullable=False),
            sa.Column("status", sa.String(50), nullable=False, server_default="pending"),
            sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("api_key_id", postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["api_key_id"], ["api_keys.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("idx_onboarding_otp_email", "onboarding_email_otps", ["email"])
        op.create_index("idx_onboarding_otp_status", "onboarding_email_otps", ["status"])
        op.create_index("idx_onboarding_otp_expires", "onboarding_email_otps", ["expires_at"])

    if "onboarding_status" not in inspector.get_table_names():
        op.create_table(
            "onboarding_status",
            sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("signup_id", postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("email_verified", sa.Boolean(), nullable=False, server_default="false"),
            sa.Column("tenant_created", sa.Boolean(), nullable=False, server_default="false"),
            sa.Column("api_key_issued", sa.Boolean(), nullable=False, server_default="false"),
            sa.Column("provider_key_saved", sa.Boolean(), nullable=False, server_default="false"),
            sa.Column("route_created", sa.Boolean(), nullable=False, server_default="false"),
            sa.Column("policy_created", sa.Boolean(), nullable=False, server_default="false"),
            sa.Column("snippet_viewed", sa.Boolean(), nullable=False, server_default="false"),
            sa.Column("current_step", sa.String(50), nullable=False, server_default="connect_provider"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["signup_id"], ["onboarding_email_otps.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("tenant_id", name="uq_onboarding_status_tenant"),
        )
        op.create_index("idx_onboarding_status_tenant", "onboarding_status", ["tenant_id"])
        op.create_index("idx_onboarding_status_step", "onboarding_status", ["current_step"])

    for table in ("onboarding_email_otps", "onboarding_status"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")

    op.execute("""
    DROP POLICY IF EXISTS onboarding_email_otps_tenant_isolation ON onboarding_email_otps;
    CREATE POLICY onboarding_email_otps_tenant_isolation
    ON onboarding_email_otps
    USING (
        tenant_id IS NOT NULL
        AND tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
    );
    """)
    op.execute("""
    DROP POLICY IF EXISTS onboarding_status_tenant_isolation ON onboarding_status;
    CREATE POLICY onboarding_status_tenant_isolation
    ON onboarding_status
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
    );
    """)


def downgrade():
    op.execute("DROP POLICY IF EXISTS onboarding_status_tenant_isolation ON onboarding_status;")
    op.execute("DROP POLICY IF EXISTS onboarding_email_otps_tenant_isolation ON onboarding_email_otps;")
    op.drop_table("onboarding_status")
    op.drop_table("onboarding_email_otps")

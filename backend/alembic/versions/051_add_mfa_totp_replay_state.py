"""Persist the last consumed TOTP timestep across protected operations."""

from alembic import op
import sqlalchemy as sa


revision = "051"
down_revision = "050"
branch_labels = None
depends_on = None


def upgrade():
    # Existing credentials have no recorded consumption before this deployment.
    op.add_column("users", sa.Column("mfa_last_totp_step", sa.BigInteger(), nullable=True))


def downgrade():
    # Cover all tenants even though the migration owner obeys forced RLS. The
    # lock prevents consumption racing the guard; PostgreSQL rolls back on failure.
    op.execute("LOCK TABLE users IN ACCESS EXCLUSIVE MODE")
    op.execute("ALTER TABLE users DISABLE ROW LEVEL SECURITY")
    op.execute("""
        DO $$ BEGIN
            IF EXISTS (SELECT 1 FROM users WHERE mfa_last_totp_step IS NOT NULL) THEN
                RAISE EXCEPTION 'Retained MFA replay state requires a forward fix; downgrade refused';
            END IF;
        END $$;
    """)
    op.execute("ALTER TABLE users ENABLE ROW LEVEL SECURITY")
    op.drop_column("users", "mfa_last_totp_step")

"""Recognize invitation onboarding for access-request retention

Revision ID: 034
Revises: 033
"""

from alembic import op


revision = "034"
down_revision = "033"
branch_labels = None
depends_on = None


def _replace_function(purposes: str) -> None:
    op.execute(f"""
        CREATE OR REPLACE FUNCTION access_request_onboarding_started(
            p_email text,
            p_after timestamptz
        )
        RETURNS boolean
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = public, pg_temp
        AS $$
            SELECT EXISTS (
                SELECT 1
                FROM onboarding_email_otps
                WHERE lower(email) = lower(p_email)
                  AND created_at >= p_after
                  AND purpose {purposes}
            );
        $$;
    """)


def upgrade():
    _replace_function("IN ('signup', 'invite')")


def downgrade():
    _replace_function("= 'signup'")

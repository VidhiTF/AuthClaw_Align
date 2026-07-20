"""Add RLS-safe access request onboarding lookup

Revision ID: 032
Revises: 031
"""

import os

from alembic import op

revision = "032"
down_revision = "031"
branch_labels = None
depends_on = None


def upgrade():
    app_role = op.get_bind().dialect.identifier_preparer.quote(
        os.getenv("POSTGRES_APP_USER", "authclaw_app")
    )
    op.execute("""
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
                  AND purpose = 'signup'
            );
        $$;
        """)
    op.execute(
        "REVOKE ALL ON FUNCTION "
        "access_request_onboarding_started(text, timestamptz) FROM PUBLIC"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION "
        f"access_request_onboarding_started(text, timestamptz) TO {app_role}"
    )
    op.execute(f"REVOKE SELECT ON onboarding_email_otps FROM {app_role}")


def downgrade():
    app_role = op.get_bind().dialect.identifier_preparer.quote(
        os.getenv("POSTGRES_APP_USER", "authclaw_app")
    )
    op.execute(f"GRANT SELECT ON onboarding_email_otps TO {app_role}")
    op.execute(
        "REVOKE EXECUTE ON FUNCTION "
        f"access_request_onboarding_started(text, timestamptz) FROM {app_role}"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS "
        "access_request_onboarding_started(text, timestamptz)"
    )

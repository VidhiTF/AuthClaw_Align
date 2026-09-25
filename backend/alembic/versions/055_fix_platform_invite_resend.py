"""Qualify the platform invite resend counter update.

Revision ID: 055
Revises: 054
"""

from alembic import op


revision = "055"
down_revision = "054"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        DO $$
        DECLARE
            definition text;
            legacy constant text := 'resend_count = COALESCE(resend_count, 0) + 1,';
            corrected constant text := 'resend_count = COALESCE(v_invite.resend_count, 0) + 1,';
        BEGIN
            SELECT pg_get_functiondef(
                'authn.create_platform_tenant_owner_invite(uuid,text,text,timestamp with time zone)'::regprocedure
            ) INTO definition;
            IF definition IS NULL THEN
                RAISE EXCEPTION 'platform invite function is missing';
            END IF;
            IF position(corrected IN definition) > 0 THEN
                RETURN;
            END IF;
            IF array_length(string_to_array(definition, legacy), 1) <> 2 THEN
                RAISE EXCEPTION 'platform invite function must contain exactly one legacy resend expression';
            END IF;
            EXECUTE replace(definition, legacy, corrected);
        END $$;
    """)


def downgrade() -> None:
    # Do not restore the ambiguous expression when traversing older revisions.
    pass

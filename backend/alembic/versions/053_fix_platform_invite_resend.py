"""Disambiguate the resend counter in the existing platform invitation function."""
from alembic import op

revision = "053"
down_revision = "052"
branch_labels = depends_on = None


def upgrade() -> None:
    op.execute("""
        DO $$
        DECLARE
            definition text := pg_get_functiondef(
                'authn.create_platform_tenant_owner_invite(uuid,text,text,timestamptz)'::regprocedure
            );
            legacy text := 'resend_count = COALESCE(resend_count, 0)';
            fixed text := 'resend_count = COALESCE(v_invite.resend_count, 0)';
            legacy_count integer := array_length(string_to_array(definition, legacy), 1);
            fixed_count integer := array_length(string_to_array(definition, fixed), 1);
        BEGIN
            IF definition IS NULL THEN
                RAISE EXCEPTION 'Platform invitation function is missing';
            ELSIF legacy_count = 2 AND fixed_count = 1 THEN
                EXECUTE replace(definition, legacy, fixed);
            ELSIF legacy_count <> 1 OR fixed_count <> 2 THEN
                RAISE EXCEPTION 'Expected exactly one legacy or qualified platform invitation resend counter';
            END IF;
        END $$;
    """)


def downgrade() -> None:
    raise RuntimeError("Keep migration 053 when rolling back applications; downgrading restores broken invitation retries")

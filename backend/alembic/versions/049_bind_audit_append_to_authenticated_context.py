"""Bind immutable audit appends to the authenticated tenant context.

Revision ID: 049
Revises: 048
"""

from alembic import op

revision = "049"
down_revision = "048"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        DO $$
        DECLARE
            definition text;
            legacy constant text := 'nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid';
        BEGIN
            SELECT pg_get_functiondef(
                'public.append_audit_event_v2(uuid,uuid,text,timestamptz,uuid,text,text,text,uuid,text,text,text,integer,integer,integer,integer,text[],jsonb)'::regprocedure
            )
            INTO definition;
            IF definition IS NULL OR array_length(string_to_array(definition, legacy), 1) <> 2 THEN
                RAISE EXCEPTION
                    'append_audit_event_v2 must contain exactly one legacy tenant check';
            END IF;
            EXECUTE replace(definition, legacy, 'authn.current_tenant_id()');
        END $$;
        """)


def downgrade() -> None:
    raise RuntimeError(
        "Migration 049 changes an immutable-audit authorization boundary and cannot be safely downgraded"
    )

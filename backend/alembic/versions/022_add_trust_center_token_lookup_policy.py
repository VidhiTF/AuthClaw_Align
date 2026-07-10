"""Add Trust Center token lookup RLS policy

Revision ID: 022
Revises: 021
Create Date: 2026-07-01 12:00:00.000000
"""

from alembic import op


revision = "022"
down_revision = "021"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("DROP FUNCTION IF EXISTS resolve_trust_center_share(TEXT)")
    op.execute(
        """
        CREATE POLICY trust_center_shares_token_lookup
        ON trust_center_shares
        FOR SELECT
        USING (
            token_hash = nullif(current_setting('app.trust_center_token_hash', true), '')
        );
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION resolve_trust_center_share(p_token_hash TEXT)
        RETURNS TABLE(id UUID, tenant_id UUID, status TEXT, expires_at TIMESTAMPTZ)
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = public
        AS $$
        BEGIN
            PERFORM set_config('app.trust_center_token_hash', p_token_hash, true);
            RETURN QUERY
                SELECT s.id, s.tenant_id, s.status::TEXT, s.expires_at
                FROM trust_center_shares s
                WHERE s.token_hash = p_token_hash
                LIMIT 1;
        END;
        $$;
        """
    )


def downgrade():
    op.execute("DROP FUNCTION IF EXISTS resolve_trust_center_share(TEXT)")
    op.execute("DROP POLICY IF EXISTS trust_center_shares_token_lookup ON trust_center_shares")
    op.execute(
        """
        CREATE OR REPLACE FUNCTION resolve_trust_center_share(p_token_hash TEXT)
        RETURNS TABLE(id UUID, tenant_id UUID, status TEXT, expires_at TIMESTAMPTZ)
        LANGUAGE SQL
        SECURITY DEFINER
        SET search_path = public
        AS $$
            SELECT s.id, s.tenant_id, s.status, s.expires_at
            FROM trust_center_shares s
            WHERE s.token_hash = p_token_hash
            LIMIT 1;
        $$;
        """
    )

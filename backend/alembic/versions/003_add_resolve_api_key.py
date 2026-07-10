"""Add resolve_api_key security definer function

Revision ID: 003
Revises: 002
Create Date: 2026-06-15 15:45:00.000000
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '003'
down_revision = '002'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
    CREATE OR REPLACE FUNCTION resolve_api_key(p_key_hash text)
    RETURNS TABLE (
        id uuid,
        tenant_id uuid,
        scopes varchar[],
        created_by uuid
    )
    SECURITY DEFINER
    AS $$
    BEGIN
        RETURN QUERY
        SELECT a.id, a.tenant_id, a.scopes::varchar[], a.created_by
        FROM api_keys a
        WHERE a.key_hash = p_key_hash AND a.is_active = true AND (a.expires_at IS NULL OR a.expires_at > NOW());
    END;
    $$ LANGUAGE plpgsql;
    """)

    # Grant execute permission to non-superuser role
    op.execute("GRANT EXECUTE ON FUNCTION resolve_api_key(text) TO PUBLIC;")


def downgrade():
    op.execute("DROP FUNCTION IF EXISTS resolve_api_key(text);")

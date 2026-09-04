"""Make authentication session binding safe for concurrent reads.

Revision ID: 045
Revises: 044
"""

from alembic import op


revision = "045"
down_revision = "044"
branch_labels = None
depends_on = None


_FUNCTION_PREFIX = """
CREATE OR REPLACE FUNCTION authn.bind_session_context(p_token_hash text)
RETURNS TABLE (
    credential_id uuid, tenant_id uuid, scopes varchar[], user_id uuid,
    role text, platform_role text, user_is_active boolean,
    tenant_status text
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, authn, public
AS $$
DECLARE v record;
BEGIN
    SELECT s.id, s.tenant_id, s.user_id, u.role::text,
           u.platform_role::text, u.is_active, t.status::text
      INTO v
      FROM authn.sessions s
      JOIN public.users u ON u.id = s.user_id
                         AND u.tenant_id = s.tenant_id
      JOIN public.tenants t ON t.id = s.tenant_id
     WHERE s.token_hash = p_token_hash AND s.revoked_at IS NULL
       AND s.expires_at > now() AND u.is_active
     LIMIT 1;
    IF NOT FOUND THEN RETURN; END IF;
"""

_FUNCTION_SUFFIX = """
    PERFORM authn.set_context(v.tenant_id, v.user_id, v.id);
    RETURN QUERY SELECT v.id, v.tenant_id,
        ARRAY['read','write','admin']::varchar[], v.user_id,
        v.role, v.platform_role, v.is_active, v.status;
END;
$$;
"""


def upgrade() -> None:
    # Binding runs in middleware, dependencies, and pooled-session hooks. It must
    # not take a row lock that can deadlock concurrent reads for the same session.
    op.execute(_FUNCTION_PREFIX + _FUNCTION_SUFFIX)


def downgrade() -> None:
    op.execute(
        _FUNCTION_PREFIX
        + "    UPDATE authn.sessions SET last_seen_at = now() WHERE id = v.id\n"
        + "       AND last_seen_at < now() - interval '5 minutes';\n"
        + _FUNCTION_SUFFIX
    )

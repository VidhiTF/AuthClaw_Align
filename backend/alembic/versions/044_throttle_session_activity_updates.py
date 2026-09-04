"""Throttle authentication session activity updates.

Revision ID: 044
Revises: 043
"""

from alembic import op


revision = "044"
down_revision = "043"
branch_labels = None
depends_on = None


_TENANT_BINDER = """
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
    UPDATE authn.sessions
       SET last_seen_at = now()
     WHERE id = v.id
       AND last_seen_at < now() - interval '5 minutes';
    PERFORM authn.set_context(v.tenant_id, v.user_id, v.id);
    RETURN QUERY SELECT v.id, v.tenant_id,
        ARRAY['read','write','admin']::varchar[], v.user_id,
        v.role, v.platform_role, v.is_active, v.status;
END;
$$;
"""


_PLATFORM_BINDER = """
CREATE OR REPLACE FUNCTION authn.bind_platform_session_context(p_token_hash text)
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
    SELECT s.id, s.platform_admin_id, p.role::text, p.is_active
      INTO v
      FROM authn.platform_sessions s
      JOIN authn.platform_admins p ON p.id = s.platform_admin_id
     WHERE s.token_hash = p_token_hash
       AND s.revoked_at IS NULL
       AND s.expires_at > now()
       AND p.is_active
       AND p.role = 'ADMIN'
     LIMIT 1;
    IF NOT FOUND THEN RETURN; END IF;
    UPDATE authn.platform_sessions
       SET last_seen_at = now()
     WHERE id = v.id
       AND last_seen_at < now() - interval '5 minutes';
    PERFORM authn.set_platform_context(v.platform_admin_id, v.id);
    RETURN QUERY SELECT v.id, NULL::uuid,
        ARRAY['platform.admin']::varchar[], v.platform_admin_id,
        'platform_admin'::text, 'ADMIN'::text, v.is_active, 'active'::text;
END;
$$;
"""


def upgrade() -> None:
    op.execute(_TENANT_BINDER)
    op.execute(_PLATFORM_BINDER)


def downgrade() -> None:
    raise RuntimeError(
        "Migration 044 prevents request-pool lock starvation and cannot be safely downgraded"
    )

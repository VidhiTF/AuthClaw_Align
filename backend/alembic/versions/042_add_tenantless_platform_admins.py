"""Add tenantless platform administrator authentication.

Revision ID: 042
Revises: 041
"""

import os

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "042"
down_revision = "041"
branch_labels = None
depends_on = None


def _app_role() -> str:
    return op.get_bind().dialect.identifier_preparer.quote(
        os.getenv("POSTGRES_APP_USER", "authclaw_app")
    )


def upgrade() -> None:
    op.create_table(
        "platform_admins",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=False, server_default="AuthClaw Developer"),
        sa.Column("role", sa.String(length=50), nullable=False, server_default="ADMIN"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("role = 'ADMIN'", name="ck_platform_admin_role"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email", name="uq_platform_admin_email"),
        schema="authn",
    )
    op.create_index("idx_platform_admin_active", "platform_admins", ["is_active"], schema="authn")
    op.create_table(
        "platform_sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("platform_admin_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("authentication_method", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.CheckConstraint("length(token_hash) = 64", name="ck_platform_session_token_hash"),
        sa.ForeignKeyConstraint(["platform_admin_id"], ["authn.platform_admins.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash", name="uq_platform_session_token_hash"),
        schema="authn",
    )
    op.create_index(
        "ix_platform_sessions_admin",
        "platform_sessions",
        ["platform_admin_id"],
        schema="authn",
    )
    op.create_index(
        "ix_platform_sessions_expiry",
        "platform_sessions",
        ["expires_at"],
        schema="authn",
        postgresql_where=sa.text("revoked_at IS NULL"),
    )
    op.execute(
        """
        CREATE FUNCTION authn.set_platform_context(
            p_platform_admin_id uuid, p_credential_id uuid
        ) RETURNS void
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
        DECLARE v_payload text; v_signature text; v_secret bytea;
        BEGIN
            SELECT secret INTO STRICT v_secret
              FROM authn.context_secret WHERE singleton;
            v_payload := p_platform_admin_id::text || '|' ||
                p_credential_id::text || '|' || txid_current()::text;
            v_signature := encode(
                public.hmac(v_payload::bytea, v_secret, 'sha256'), 'hex'
            );
            PERFORM set_config(
                'app.platform_auth_context', v_payload || '|' || v_signature, true
            );
        END;
        $$;

        CREATE FUNCTION authn.current_platform_admin_id() RETURNS uuid
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
        DECLARE
            v_context text := current_setting('app.platform_auth_context', true);
            v_payload text; v_expected text; v_secret bytea;
        BEGIN
            IF v_context IS NULL OR v_context = '' THEN RETURN NULL; END IF;
            v_payload := split_part(v_context, '|', 1) || '|' ||
                split_part(v_context, '|', 2) || '|' ||
                split_part(v_context, '|', 3);
            IF split_part(v_context, '|', 3) <> txid_current()::text THEN
                RETURN NULL;
            END IF;
            SELECT secret INTO STRICT v_secret
              FROM authn.context_secret WHERE singleton;
            v_expected := encode(
                public.hmac(v_payload::bytea, v_secret, 'sha256'), 'hex'
            );
            IF v_expected <> split_part(v_context, '|', 4) THEN RETURN NULL; END IF;
            RETURN split_part(v_context, '|', 1)::uuid;
        EXCEPTION WHEN OTHERS THEN RETURN NULL;
        END;
        $$;

        CREATE FUNCTION authn.lookup_platform_password_identity(p_email text)
        RETURNS TABLE (
            platform_admin_id uuid, email text, password_hash text,
            role text, is_active boolean
        )
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
            SELECT p.id, p.email::text, p.password_hash::text,
                   p.role::text, p.is_active
              FROM authn.platform_admins p
             WHERE lower(p.email) = lower(trim(p_email))
               AND p.is_active
             LIMIT 1
        $$;

        CREATE FUNCTION authn.create_platform_session(
            p_token_hash text, p_platform_admin_id uuid, p_method text,
            p_expires_at timestamptz, p_metadata jsonb DEFAULT '{}'::jsonb
        ) RETURNS uuid
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
        DECLARE v_id uuid;
        BEGIN
            IF length(p_token_hash) <> 64 OR p_expires_at <= now() THEN
                RAISE EXCEPTION 'invalid platform session parameters';
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM authn.platform_admins p
                 WHERE p.id = p_platform_admin_id
                   AND p.is_active
                   AND p.role = 'ADMIN'
            ) THEN RAISE EXCEPTION 'invalid platform principal'; END IF;
            INSERT INTO authn.platform_sessions (
                id, token_hash, platform_admin_id, authentication_method,
                expires_at, metadata
            ) VALUES (
                gen_random_uuid(), p_token_hash, p_platform_admin_id,
                left(p_method, 64), p_expires_at, coalesce(p_metadata, '{}'::jsonb)
            ) RETURNING id INTO v_id;
            PERFORM authn.set_platform_context(p_platform_admin_id, v_id);
            RETURN v_id;
        END;
        $$;

        CREATE FUNCTION authn.bind_platform_session_context(p_token_hash text)
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
            UPDATE authn.platform_sessions SET last_seen_at = now() WHERE id = v.id;
            PERFORM authn.set_platform_context(v.platform_admin_id, v.id);
            RETURN QUERY SELECT v.id, NULL::uuid,
                ARRAY['platform.admin']::varchar[], v.platform_admin_id,
                'platform_admin'::text, 'ADMIN'::text, v.is_active, 'active'::text;
        END;
        $$;

        CREATE FUNCTION authn.platform_admin_profile(p_token_hash text)
        RETURNS TABLE (
            id uuid, email text, role text, platform_role text,
            scopes varchar[], is_active boolean
        )
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
        DECLARE v record;
        BEGIN
            SELECT b.credential_id, b.user_id, p.email::text, p.role::text,
                   b.scopes, b.user_is_active
              INTO v
              FROM authn.bind_platform_session_context(p_token_hash) b
              JOIN authn.platform_admins p ON p.id = b.user_id
             LIMIT 1;
            IF NOT FOUND THEN RETURN; END IF;
            RETURN QUERY SELECT v.user_id, v.email, 'platform_admin'::text,
                v.role, v.scopes, v.user_is_active;
        END;
        $$;

        CREATE FUNCTION authn.revoke_platform_session(p_token_hash text) RETURNS boolean
        LANGUAGE sql SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
            WITH changed AS (
                UPDATE authn.platform_sessions SET revoked_at = now()
                 WHERE token_hash = p_token_hash AND revoked_at IS NULL
                 RETURNING 1
            ) SELECT EXISTS (SELECT 1 FROM changed)
        $$;

        CREATE FUNCTION authn.create_tenant_as_platform_admin(
            p_tenant_id uuid, p_name text, p_tier text
        ) RETURNS TABLE (
            id uuid, name text, tier text, status text,
            created_at timestamptz, updated_at timestamptz
        )
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
        DECLARE v_actor uuid := authn.current_platform_admin_id();
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM authn.platform_admins p
                 WHERE p.id = v_actor
                   AND p.is_active
                   AND p.role = 'ADMIN'
            ) THEN RAISE EXCEPTION 'platform administrator required'; END IF;
            RETURN QUERY
            INSERT INTO public.tenants(id, name, tier, status)
            VALUES (p_tenant_id, trim(p_name), p_tier, 'active')
            RETURNING tenants.id, tenants.name::text, tenants.tier::text,
                tenants.status::text, tenants.created_at, tenants.updated_at;
        END;
        $$;
        """
    )
    app_role = _app_role()
    op.execute(f"GRANT USAGE ON SCHEMA authn TO {app_role}")
    op.execute(
        f"""
        GRANT EXECUTE ON FUNCTION authn.lookup_platform_password_identity(text) TO {app_role};
        GRANT EXECUTE ON FUNCTION authn.create_platform_session(text, uuid, text, timestamptz, jsonb) TO {app_role};
        GRANT EXECUTE ON FUNCTION authn.bind_platform_session_context(text) TO {app_role};
        GRANT EXECUTE ON FUNCTION authn.platform_admin_profile(text) TO {app_role};
        GRANT EXECUTE ON FUNCTION authn.revoke_platform_session(text) TO {app_role};
        GRANT EXECUTE ON FUNCTION authn.create_tenant_as_platform_admin(uuid, text, text) TO {app_role};
        """
    )


def downgrade() -> None:
    raise RuntimeError(
        "Migration 042 is security-irreversible; restore a pre-042 backup"
    )

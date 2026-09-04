"""Add platform-created tenant invite function.

Revision ID: 043
Revises: 042
"""

from alembic import op
from sqlalchemy import text


revision = "043"
down_revision = "042"
branch_labels = None
depends_on = None


def _app_role() -> str:
    bind = op.get_bind()
    raw_role = bind.execute(text("SELECT current_setting('authclaw.app_role', true)")).scalar()
    role = (raw_role or "authclaw_app").strip()
    return bind.dialect.identifier_preparer.quote(role)


def upgrade() -> None:
    op.execute(
        """
        CREATE FUNCTION authn.create_platform_tenant_owner_invite(
            p_tenant_id uuid, p_email text, p_otp_hash text,
            p_expires_at timestamptz
        ) RETURNS TABLE (
            invite_id uuid, tenant_name text, resend_count integer
        )
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
        DECLARE
            v_actor uuid := authn.current_platform_admin_id();
            v_tenant public.tenants%ROWTYPE;
            v_invite public.onboarding_email_otps%ROWTYPE;
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM authn.platform_admins p
                 WHERE p.id = v_actor
                   AND p.is_active
                   AND p.role = 'ADMIN'
            ) THEN RAISE EXCEPTION 'platform administrator required'; END IF;

            PERFORM authn.set_context(p_tenant_id, v_actor, v_actor);

            SELECT * INTO v_tenant
              FROM public.tenants t
             WHERE t.id = p_tenant_id AND t.status = 'active';
            IF NOT FOUND THEN RAISE EXCEPTION 'tenant unavailable'; END IF;

            IF EXISTS (
                SELECT 1 FROM public.users u
                 WHERE u.tenant_id = p_tenant_id
                   AND lower(u.email) = lower(trim(p_email))
                   AND u.is_active
            ) THEN RAISE EXCEPTION 'active tenant user already exists'; END IF;

            SELECT * INTO v_invite
              FROM public.onboarding_email_otps o
             WHERE o.tenant_id = p_tenant_id
               AND o.email = lower(trim(p_email))
               AND o.status = 'pending'
               AND o.purpose = 'invite'
             FOR UPDATE;

            IF FOUND THEN
                UPDATE public.onboarding_email_otps
                   SET otp_hash = p_otp_hash,
                       attempts = 0,
                       expires_at = p_expires_at,
                       sent_at = now(),
                       resend_count = COALESCE(resend_count, 0) + 1,
                       invited_role = 'owner',
                       invited_by = NULL,
                       delivery_error = NULL
                 WHERE id = v_invite.id
                 RETURNING * INTO v_invite;
            ELSE
                INSERT INTO public.onboarding_email_otps (
                    id, email, tenant_name, otp_hash, status, expires_at,
                    sent_at, purpose, invited_role, invited_by, tenant_id,
                    attempts, resend_count
                ) VALUES (
                    gen_random_uuid(), lower(trim(p_email)), v_tenant.name,
                    p_otp_hash, 'pending', p_expires_at, now(), 'invite',
                    'owner', NULL, p_tenant_id, 0, 0
                ) RETURNING * INTO v_invite;
            END IF;

            RETURN QUERY SELECT v_invite.id, v_tenant.name::text,
                COALESCE(v_invite.resend_count, 0);
        END;
        $$;
        """
    )
    app_role = _app_role()
    op.execute(
        f"GRANT EXECUTE ON FUNCTION "
        f"authn.create_platform_tenant_owner_invite(uuid, text, text, timestamptz) "
        f"TO {app_role}"
    )


def downgrade() -> None:
    op.execute(
        "DROP FUNCTION IF EXISTS "
        "authn.create_platform_tenant_owner_invite(uuid, text, text, timestamptz)"
    )

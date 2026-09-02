"""Add the restricted authentication boundary and signed tenant context.

Revision ID: 041
Revises: 040
"""

from alembic import op


revision = "041"
down_revision = "040"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("REVOKE ALL ON SCHEMA authn FROM PUBLIC")
    op.execute(
        """
        CREATE TABLE authn.context_secret (
            singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
            secret bytea NOT NULL DEFAULT gen_random_bytes(32),
            created_at timestamptz NOT NULL DEFAULT now()
        );
        INSERT INTO authn.context_secret (singleton) VALUES (true);
        CREATE TABLE authn.sessions (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            token_hash text NOT NULL UNIQUE CHECK (length(token_hash) = 64),
            tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
            user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
            authentication_method text NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            expires_at timestamptz NOT NULL,
            last_seen_at timestamptz NOT NULL DEFAULT now(),
            revoked_at timestamptz,
            metadata jsonb NOT NULL DEFAULT '{}'::jsonb
        );
        CREATE INDEX ix_authn_sessions_tenant_user
            ON authn.sessions (tenant_id, user_id);
        CREATE INDEX ix_authn_sessions_expiry
            ON authn.sessions (expires_at) WHERE revoked_at IS NULL;
        REVOKE ALL ON ALL TABLES IN SCHEMA authn FROM PUBLIC;
        """
    )
    op.execute(
        """
        CREATE FUNCTION authn.set_context(
            p_tenant_id uuid, p_user_id uuid, p_credential_id uuid
        ) RETURNS void
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
        DECLARE v_payload text; v_signature text; v_secret bytea;
        BEGIN
            SELECT secret INTO STRICT v_secret
              FROM authn.context_secret WHERE singleton;
            v_payload := p_tenant_id::text || '|' || p_user_id::text || '|' ||
                p_credential_id::text || '|' || txid_current()::text;
            v_signature := encode(
                public.hmac(v_payload::bytea, v_secret, 'sha256'), 'hex'
            );
            PERFORM set_config(
                'app.auth_context', v_payload || '|' || v_signature, true
            );
        END;
        $$;

        CREATE FUNCTION authn.current_tenant_id() RETURNS uuid
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
        DECLARE
            v_context text := current_setting('app.auth_context', true);
            v_payload text; v_expected text; v_secret bytea;
        BEGIN
            IF v_context IS NULL OR v_context = '' THEN RETURN NULL; END IF;
            v_payload := split_part(v_context, '|', 1) || '|' ||
                split_part(v_context, '|', 2) || '|' ||
                split_part(v_context, '|', 3) || '|' ||
                split_part(v_context, '|', 4);
            IF split_part(v_context, '|', 4) <> txid_current()::text THEN
                RETURN NULL;
            END IF;
            SELECT secret INTO STRICT v_secret
              FROM authn.context_secret WHERE singleton;
            v_expected := encode(
                public.hmac(v_payload::bytea, v_secret, 'sha256'), 'hex'
            );
            IF v_expected <> split_part(v_context, '|', 5) THEN RETURN NULL; END IF;
            RETURN split_part(v_context, '|', 1)::uuid;
        EXCEPTION WHEN OTHERS THEN RETURN NULL;
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE FUNCTION authn.bind_session_context(p_token_hash text)
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
            UPDATE authn.sessions SET last_seen_at = now() WHERE id = v.id;
            PERFORM authn.set_context(v.tenant_id, v.user_id, v.id);
            RETURN QUERY SELECT v.id, v.tenant_id,
                ARRAY['read','write','admin']::varchar[], v.user_id,
                v.role, v.platform_role, v.is_active, v.status;
        END;
        $$;

        CREATE FUNCTION authn.revoke_session(p_token_hash text) RETURNS boolean
        LANGUAGE sql SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
            WITH changed AS (
                UPDATE authn.sessions SET revoked_at = now()
                 WHERE token_hash = p_token_hash AND revoked_at IS NULL
                 RETURNING 1
            ) SELECT EXISTS (SELECT 1 FROM changed)
        $$;

        CREATE FUNCTION authn.revoke_user_sessions(
            p_tenant_id uuid, p_user_id uuid
        ) RETURNS bigint
        LANGUAGE sql SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
            WITH changed AS (
                UPDATE authn.sessions SET revoked_at = now()
                 WHERE tenant_id = p_tenant_id AND user_id = p_user_id
                   AND revoked_at IS NULL RETURNING 1
            ) SELECT count(*) FROM changed
        $$;

        """
    )
    op.execute(
        """
        CREATE FUNCTION authn.lookup_password_identities(
            p_email text, p_tenant_name text DEFAULT NULL
        ) RETURNS TABLE (
            user_id uuid, tenant_id uuid, tenant_name text, email text,
            password_hash text, role text, platform_role text,
            mfa_enabled boolean
        )
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
            SELECT u.id, u.tenant_id, t.name::text, u.email::text,
                   u.password_hash::text, u.role::text, u.platform_role::text,
                   coalesce(u.mfa_enabled, false)
            FROM public.users u JOIN public.tenants t ON t.id = u.tenant_id
            WHERE lower(u.email) = lower(trim(p_email))
              AND u.is_active AND t.status = 'active'
              AND (p_tenant_name IS NULL OR
                   lower(t.name) = lower(trim(p_tenant_name)))
            ORDER BY t.name, u.id LIMIT 2
        $$;

        CREATE FUNCTION authn.bind_api_key_context(p_key_hash text)
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
            SELECT a.id, a.tenant_id, a.scopes::varchar[], a.created_by,
                   u.role::text, u.platform_role::text, u.is_active,
                   t.status::text
              INTO v
              FROM public.api_keys a
              JOIN public.users u ON u.id = a.created_by
                                 AND u.tenant_id = a.tenant_id
              JOIN public.tenants t ON t.id = a.tenant_id
             WHERE a.key_hash = p_key_hash AND a.is_active
               AND a.revoked_at IS NULL AND a.rotated_at IS NULL
               AND a.expires_at > now()
             LIMIT 1;
            IF NOT FOUND THEN RETURN; END IF;
            PERFORM authn.set_context(v.tenant_id, v.created_by, v.id);
            RETURN QUERY SELECT v.id, v.tenant_id, v.scopes, v.created_by,
                v.role, v.platform_role, v.is_active, v.status;
        END;
        $$;

        CREATE FUNCTION authn.create_session(
            p_token_hash text, p_tenant_id uuid, p_user_id uuid,
            p_method text, p_expires_at timestamptz,
            p_metadata jsonb DEFAULT '{}'::jsonb
        ) RETURNS uuid
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
        DECLARE v_id uuid;
        BEGIN
            IF length(p_token_hash) <> 64 OR p_expires_at <= now() THEN
                RAISE EXCEPTION 'invalid session parameters';
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM public.users u
                JOIN public.tenants t ON t.id = u.tenant_id
                WHERE u.id = p_user_id AND u.tenant_id = p_tenant_id
                  AND u.is_active AND t.status = 'active'
            ) THEN RAISE EXCEPTION 'invalid session principal'; END IF;
            INSERT INTO authn.sessions (
                token_hash, tenant_id, user_id, authentication_method,
                expires_at, metadata
            ) VALUES (
                p_token_hash, p_tenant_id, p_user_id, left(p_method, 64),
                p_expires_at, coalesce(p_metadata, '{}'::jsonb)
            ) RETURNING id INTO v_id;
            PERFORM authn.set_context(p_tenant_id, p_user_id, v_id);
            RETURN v_id;
        END;
        $$;

        CREATE FUNCTION authn.current_user_id() RETURNS uuid
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
        DECLARE v_context text := current_setting('app.auth_context', true);
        BEGIN
            IF authn.current_tenant_id() IS NULL THEN RETURN NULL; END IF;
            RETURN split_part(v_context, '|', 2)::uuid;
        EXCEPTION WHEN OTHERS THEN RETURN NULL;
        END;
        $$;

        CREATE FUNCTION authn.create_tenant(
            p_tenant_id uuid, p_name text, p_tier text
        ) RETURNS TABLE (
            id uuid, name text, tier text, status text,
            created_at timestamptz, updated_at timestamptz
        )
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
        DECLARE v_actor uuid := authn.current_user_id();
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM public.users u
                 WHERE u.id = v_actor
                   AND u.tenant_id = authn.current_tenant_id()
                   AND u.is_active
                   AND upper(u.platform_role::text) = 'ADMIN'
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
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.resolve_api_key(p_key_hash text)
        RETURNS TABLE (id uuid, tenant_id uuid, scopes varchar[], created_by uuid)
        LANGUAGE sql SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
            SELECT credential_id, tenant_id, scopes, user_id
              FROM authn.bind_api_key_context(p_key_hash)
        $$;
        """
    )
    op.execute(
        """
        CREATE FUNCTION authn.lookup_oidc_config(p_tenant_name text)
        RETURNS TABLE (tenant_id uuid, tenant_name text, config jsonb)
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
            SELECT t.id, t.name::text,
                   CASE WHEN c.id IS NULL THEN NULL ELSE to_jsonb(c) END
              FROM public.tenants t
              LEFT JOIN public.tenant_oidc_configs c
                ON c.tenant_id = t.id AND c.status = 'active'
             WHERE lower(t.name) = lower(trim(p_tenant_name))
               AND t.status = 'active'
             LIMIT 1
        $$;

        CREATE FUNCTION authn.issue_oidc_session(
            p_tenant_id uuid, p_email text, p_claimed_role text,
            p_token_hash text, p_expires_at timestamptz,
            p_metadata jsonb DEFAULT '{}'::jsonb
        ) RETURNS TABLE (user_id uuid, email text, role text)
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
        DECLARE v_user public.users%ROWTYPE; v_invited boolean; v_session_id uuid;
        BEGIN
            SELECT * INTO v_user FROM public.users u
             WHERE u.tenant_id = p_tenant_id
               AND lower(u.email) = lower(trim(p_email)) AND u.is_active
             LIMIT 1;
            IF NOT FOUND THEN RAISE EXCEPTION 'OIDC user is not provisioned'; END IF;
            SELECT EXISTS (
                SELECT 1 FROM public.onboarding_email_otps o
                 WHERE o.tenant_id = p_tenant_id
                   AND lower(o.email) = lower(trim(p_email))
                   AND o.purpose = 'invite' AND o.status = 'verified'
            ) INTO v_invited;
            IF NOT v_invited AND (v_user.role::text <> 'owner' OR p_claimed_role = 'owner') THEN
                UPDATE public.users SET role = p_claimed_role::public.user_role
                 WHERE id = v_user.id RETURNING * INTO v_user;
            END IF;
            INSERT INTO authn.sessions (
                token_hash, tenant_id, user_id, authentication_method,
                expires_at, metadata
            ) VALUES (
                p_token_hash, p_tenant_id, v_user.id, 'oidc', p_expires_at,
                coalesce(p_metadata, '{}'::jsonb)
            ) RETURNING id INTO v_session_id;
            UPDATE public.users SET last_login = now() WHERE id = v_user.id;
            PERFORM authn.set_context(p_tenant_id, v_user.id, v_session_id);
            RETURN QUERY SELECT v_user.id, v_user.email::text, v_user.role::text;
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE FUNCTION authn.consume_onboarding_invite_for_otp(
            p_signup_id uuid, p_otp text, p_secrets text[], p_max_attempts integer,
            p_terms_version text, p_privacy_version text
        ) RETURNS TABLE (
            outcome text, tenant_id uuid, email text, tenant_name text,
            invited_role text
        )
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
        DECLARE v public.onboarding_email_otps%ROWTYPE;
        BEGIN
            SELECT * INTO v FROM public.onboarding_email_otps o
             WHERE o.id = p_signup_id FOR UPDATE;
            IF NOT FOUND OR v.purpose <> 'invite' THEN
                RETURN QUERY SELECT 'not_found', NULL::uuid, NULL::text,
                    NULL::text, NULL::text; RETURN;
            END IF;
            IF v.status <> 'pending' THEN
                RETURN QUERY SELECT v.status::text, v.tenant_id, v.email::text,
                    v.tenant_name::text, v.invited_role::text; RETURN;
            END IF;
            IF v.expires_at < now() THEN
                UPDATE public.onboarding_email_otps SET status = 'expired'
                 WHERE id = v.id;
                RETURN QUERY SELECT 'expired', v.tenant_id, v.email::text,
                    v.tenant_name::text, v.invited_role::text; RETURN;
            END IF;
            IF v.attempts >= p_max_attempts THEN
                RETURN QUERY SELECT 'locked', v.tenant_id, v.email::text,
                    v.tenant_name::text, v.invited_role::text; RETURN;
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM unnest(p_secrets) secret
                 WHERE v.otp_hash = encode(public.digest(
                    convert_to(lower(trim(v.email)) || ':' || p_otp || ':' || secret,
                               'UTF8'),
                    'sha256'
                 ), 'hex')
            ) THEN
                UPDATE public.onboarding_email_otps
                   SET attempts = attempts + 1 WHERE id = v.id;
                RETURN QUERY SELECT 'invalid', v.tenant_id, v.email::text,
                    v.tenant_name::text, v.invited_role::text; RETURN;
            END IF;
            UPDATE public.onboarding_email_otps
               SET terms_version = coalesce(terms_version, p_terms_version),
                   terms_accepted_at = coalesce(terms_accepted_at, now()),
                   privacy_notice_version = coalesce(
                       privacy_notice_version, p_privacy_version
                   ),
                   privacy_notice_acknowledged_at = coalesce(
                       privacy_notice_acknowledged_at, now()
                   )
             WHERE id = v.id;
            IF v.tenant_id IS NULL OR NOT EXISTS (
                SELECT 1 FROM public.tenants t
                 WHERE t.id = v.tenant_id AND t.status = 'active'
            ) THEN
                RETURN QUERY SELECT 'tenant_unavailable', v.tenant_id,
                    v.email::text, v.tenant_name::text, v.invited_role::text;
                RETURN;
            END IF;
            PERFORM authn.set_context(v.tenant_id, v.id, v.id);
            RETURN QUERY SELECT 'valid', v.tenant_id, v.email::text,
                v.tenant_name::text, coalesce(v.invited_role::text, 'viewer');
        END;
        $$;

        CREATE FUNCTION authn.prepare_onboarding_invite_resend(
            p_signup_id uuid, p_otp text, p_secret text,
            p_expires_at timestamptz, p_max_resends integer,
            p_cooldown_seconds integer
        ) RETURNS TABLE (
            outcome text, tenant_id uuid, email text, tenant_name text
        )
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
        DECLARE v public.onboarding_email_otps%ROWTYPE;
        BEGIN
            SELECT * INTO v FROM public.onboarding_email_otps o
             WHERE o.id = p_signup_id AND o.purpose = 'invite' FOR UPDATE;
            IF NOT FOUND THEN
                RETURN QUERY SELECT 'not_found', NULL::uuid, NULL::text, NULL::text;
                RETURN;
            END IF;
            IF v.status <> 'pending' THEN
                RETURN QUERY SELECT v.status::text, v.tenant_id,
                    v.email::text, v.tenant_name::text; RETURN;
            END IF;
            IF v.resend_count >= p_max_resends THEN
                RETURN QUERY SELECT 'too_many', v.tenant_id,
                    v.email::text, v.tenant_name::text; RETURN;
            END IF;
            IF v.sent_at + make_interval(secs => p_cooldown_seconds) > now() THEN
                RETURN QUERY SELECT 'cooldown', v.tenant_id,
                    v.email::text, v.tenant_name::text; RETURN;
            END IF;
            IF v.tenant_id IS NULL OR NOT EXISTS (
                SELECT 1 FROM public.tenants t
                 WHERE t.id = v.tenant_id AND t.status = 'active'
            ) THEN
                RETURN QUERY SELECT 'tenant_unavailable', v.tenant_id,
                    v.email::text, v.tenant_name::text; RETURN;
            END IF;
            UPDATE public.onboarding_email_otps
               SET otp_hash = encode(public.digest(convert_to(
                       lower(trim(v.email)) || ':' || p_otp || ':' || p_secret,
                       'UTF8'), 'sha256'), 'hex'),
                   expires_at = p_expires_at, sent_at = now(),
                   resend_count = resend_count + 1, attempts = 0
             WHERE id = v.id;
            PERFORM authn.set_context(v.tenant_id, v.id, v.id);
            RETURN QUERY SELECT 'valid', v.tenant_id, v.email::text,
                v.tenant_name::text;
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE FUNCTION authn.create_password_reset(
            p_email text, p_tenant_id uuid, p_tenant_name text,
            p_otp_hash text, p_expires_at timestamptz
        ) RETURNS uuid
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
        DECLARE v_id uuid;
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM public.users u JOIN public.tenants t
                  ON t.id = u.tenant_id
                 WHERE u.tenant_id = p_tenant_id
                   AND lower(u.email) = lower(trim(p_email))
                   AND u.is_active AND t.status = 'active'
            ) THEN RAISE EXCEPTION 'invalid password reset principal'; END IF;
            INSERT INTO public.onboarding_email_otps (
                id, email, tenant_name, otp_hash, status, expires_at,
                sent_at, purpose, tenant_id, attempts, resend_count
            ) VALUES (
                gen_random_uuid(), lower(trim(p_email)), p_tenant_name,
                p_otp_hash, 'pending', p_expires_at, now(),
                'password_reset', p_tenant_id, 0, 0
            ) RETURNING id INTO v_id;
            RETURN v_id;
        END;
        $$;

        CREATE FUNCTION authn.set_password_reset_delivery(
            p_signup_id uuid, p_delivery text, p_error text DEFAULT NULL
        ) RETURNS void
        LANGUAGE sql SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
            UPDATE public.onboarding_email_otps
               SET last_delivery = p_delivery, delivery_error = p_error
             WHERE id = p_signup_id AND purpose = 'password_reset'
        $$;

        CREATE FUNCTION authn.confirm_password_reset(
            p_signup_id uuid, p_otp text, p_secrets text[],
            p_password_hash text, p_max_attempts integer
        ) RETURNS text
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
        DECLARE v public.onboarding_email_otps%ROWTYPE; v_user_id uuid;
        BEGIN
            SELECT * INTO v FROM public.onboarding_email_otps o
             WHERE o.id = p_signup_id AND o.purpose = 'password_reset'
             FOR UPDATE;
            IF NOT FOUND THEN RETURN 'not_found'; END IF;
            IF v.status <> 'pending' THEN RETURN v.status; END IF;
            IF v.expires_at < now() THEN
                UPDATE public.onboarding_email_otps SET status = 'expired'
                 WHERE id = v.id; RETURN 'expired';
            END IF;
            IF v.attempts >= p_max_attempts THEN RETURN 'locked'; END IF;
            IF NOT EXISTS (
                SELECT 1 FROM unnest(p_secrets) secret
                 WHERE v.otp_hash = encode(public.digest(
                    convert_to(lower(trim(v.email)) || ':' || p_otp || ':' || secret,
                               'UTF8'), 'sha256'
                 ), 'hex')
            ) THEN
                UPDATE public.onboarding_email_otps
                   SET attempts = attempts + 1 WHERE id = v.id;
                RETURN 'invalid';
            END IF;
            UPDATE public.users SET password_hash = p_password_hash
             WHERE tenant_id = v.tenant_id
               AND lower(email) = lower(v.email) AND is_active
             RETURNING id INTO v_user_id;
            IF v_user_id IS NULL THEN RETURN 'not_found'; END IF;
            UPDATE public.onboarding_email_otps
               SET status = 'verified', verified_at = now() WHERE id = v.id;
            UPDATE authn.sessions SET revoked_at = now()
             WHERE tenant_id = v.tenant_id AND user_id = v_user_id
               AND revoked_at IS NULL;
            RETURN 'verified';
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.resolve_trust_center_share(p_token_hash text)
        RETURNS TABLE(id uuid, tenant_id uuid, status text, expires_at timestamptz)
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
        DECLARE v record;
        BEGIN
            SELECT s.id, s.tenant_id, s.status::text, s.expires_at
              INTO v FROM public.trust_center_shares s
             WHERE s.token_hash = p_token_hash LIMIT 1;
            IF NOT FOUND THEN RETURN; END IF;
            PERFORM authn.set_context(v.tenant_id, v.id, v.id);
            RETURN QUERY SELECT v.id, v.tenant_id, v.status, v.expires_at;
        END;
        $$;
        DO $policy$
        DECLARE t record; p record;
        BEGIN
            FOR t IN
                SELECT c.relname AS table_name
                  FROM pg_class c
                  JOIN pg_namespace n ON n.oid = c.relnamespace
                  JOIN pg_attribute a ON a.attrelid = c.oid
                 WHERE n.nspname = 'public' AND c.relkind = 'r'
                   AND a.attname = 'tenant_id' AND NOT a.attisdropped
            LOOP
                FOR p IN SELECT policyname FROM pg_policies
                          WHERE schemaname = 'public'
                            AND tablename = t.table_name
                LOOP
                    EXECUTE format('DROP POLICY %I ON public.%I',
                                   p.policyname, t.table_name);
                END LOOP;
                EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',
                               t.table_name);
                EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',
                               t.table_name);
                EXECUTE format(
                    'CREATE POLICY tenant_isolation ON public.%I FOR ALL '
                    'USING (tenant_id = authn.current_tenant_id()) '
                    'WITH CHECK (tenant_id = authn.current_tenant_id())',
                    t.table_name
                );
            END LOOP;
        END
        $policy$;

        DO $policy$
        DECLARE p record;
        BEGIN
            FOR p IN SELECT policyname FROM pg_policies
                      WHERE schemaname = 'public' AND tablename = 'tenants'
            LOOP
                EXECUTE format('DROP POLICY %I ON public.tenants', p.policyname);
            END LOOP;
            ALTER TABLE public.tenants ENABLE ROW LEVEL SECURITY;
            ALTER TABLE public.tenants FORCE ROW LEVEL SECURITY;
            CREATE POLICY tenant_isolation ON public.tenants FOR ALL
                USING (id = authn.current_tenant_id())
                WITH CHECK (id = authn.current_tenant_id());
        END
        $policy$;

        DO $policy$
        DECLARE p record;
        BEGIN
            IF to_regclass('public.chat_messages') IS NOT NULL THEN
                FOR p IN SELECT policyname FROM pg_policies
                          WHERE schemaname = 'public'
                            AND tablename = 'chat_messages'
                LOOP
                    EXECUTE format(
                        'DROP POLICY %I ON public.chat_messages', p.policyname
                    );
                END LOOP;
                ALTER TABLE public.chat_messages ENABLE ROW LEVEL SECURITY;
                ALTER TABLE public.chat_messages FORCE ROW LEVEL SECURITY;
                CREATE POLICY tenant_isolation ON public.chat_messages FOR ALL
                USING (EXISTS (
                    SELECT 1 FROM public.chat_sessions s
                     WHERE s.id = chat_messages.session_id
                       AND s.tenant_id = authn.current_tenant_id()
                ));
            END IF;
        END
        $policy$;

        REVOKE ALL ON ALL TABLES IN SCHEMA authn FROM PUBLIC;
        REVOKE ALL ON ALL SEQUENCES IN SCHEMA authn FROM PUBLIC;
        REVOKE ALL ON ALL FUNCTIONS IN SCHEMA authn FROM PUBLIC;
        REVOKE ALL ON FUNCTION public.resolve_api_key(text) FROM PUBLIC;
        """
    )


def downgrade() -> None:
    raise RuntimeError(
        "Migration 041 is security-irreversible; restore a pre-041 backup"
    )

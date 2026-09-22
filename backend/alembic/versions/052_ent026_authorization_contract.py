"""ENT-026 canonical roles and database authorization primitives."""

import os

from alembic import op


revision = "052"
down_revision = "051"
branch_labels = None
depends_on = None


def _app_role() -> str:
    return op.get_bind().dialect.identifier_preparer.quote(
        os.getenv("POSTGRES_APP_USER", "authclaw_app")
    )


def upgrade() -> None:
    op.execute(
        """
        ALTER TYPE user_role ADD VALUE IF NOT EXISTS 'tenant_administrator';
        ALTER TYPE user_role ADD VALUE IF NOT EXISTS 'auditor';
        ALTER TYPE user_role ADD VALUE IF NOT EXISTS 'approver';

        CREATE OR REPLACE FUNCTION authn.current_role() RETURNS text
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
        DECLARE v_user uuid := authn.current_user_id();
        DECLARE v_platform uuid := authn.current_platform_admin_id();
        DECLARE v_role text;
        BEGIN
            IF v_platform IS NOT NULL THEN
                RETURN 'platform_administrator';
            END IF;
            IF v_user IS NULL THEN RETURN NULL; END IF;
            SELECT CASE u.role::text
                WHEN 'owner' THEN 'tenant_administrator'
                WHEN 'admin' THEN 'tenant_administrator'
                ELSE u.role::text
            END INTO v_role
              FROM public.users u
             WHERE u.id = v_user
               AND u.tenant_id = authn.current_tenant_id()
               AND u.is_active;
            RETURN v_role;
        EXCEPTION WHEN OTHERS THEN
            RETURN NULL;
        END;
        $$;

        CREATE OR REPLACE FUNCTION authn.enforce_pending_approval_transition()
        RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
        BEGIN
            IF OLD.status NOT IN ('PENDING','APPROVED') THEN
                RAISE EXCEPTION 'approval is not pending';
            END IF;
            IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
               OR NEW.requester_id IS DISTINCT FROM OLD.requester_id
               OR NEW.action_hash IS DISTINCT FROM OLD.action_hash
               OR NEW.action_payload IS DISTINCT FROM OLD.action_payload
               OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
                RAISE EXCEPTION 'approval identity and action are immutable';
            END IF;
            IF NEW.status = 'EXPIRED' THEN
                IF OLD.expires_at IS NULL OR OLD.expires_at >= now()
                   OR NOT authn.authorize_action('tenant.approvals.expire') THEN
                    RAISE EXCEPTION 'approval expiration is not authorized';
                END IF;
            ELSIF NEW.status = 'ALTERED' THEN
                NULL;
            ELSIF OLD.status = 'PENDING' AND NEW.status IN ('APPROVED','CONSUMED','REJECTED') THEN
                IF NOT authn.authorize_action('tenant.high_risk.approve')
                   OR OLD.requester_id IS NULL
                   OR OLD.requester_id = authn.current_user_id()
                   OR NEW.approver_id IS NULL
                   OR NEW.approver_id IS DISTINCT FROM authn.current_user_id() THEN
                    RAISE EXCEPTION 'approval decision is not authorized';
                END IF;
            ELSIF OLD.status = 'APPROVED' AND NEW.status = 'CONSUMED' THEN
                IF NOT authn.authorize_action('tenant.workflow.resume')
                   OR OLD.requester_id IS NULL
                   OR OLD.requester_id = authn.current_user_id()
                   OR OLD.approver_id IS NULL THEN
                    RAISE EXCEPTION 'approval consumption is not authorized';
                END IF;
            ELSE
                RAISE EXCEPTION 'invalid approval transition';
            END IF;
            RETURN NEW;
        END;
        $$;
        DROP TRIGGER IF EXISTS pending_approval_transition_guard ON public.pending_approvals;
        CREATE TRIGGER pending_approval_transition_guard
            BEFORE UPDATE ON public.pending_approvals
            FOR EACH ROW EXECUTE FUNCTION authn.enforce_pending_approval_transition();

        CREATE OR REPLACE FUNCTION authn.enforce_dsr_transition()
        RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
        BEGIN
            IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
               OR NEW.requester_id IS DISTINCT FROM OLD.requester_id
               OR NEW.subject_id IS DISTINCT FROM OLD.subject_id
               OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
                RAISE EXCEPTION 'data-subject request identity is immutable';
            END IF;
            IF OLD.status = 'PENDING' AND NEW.status = 'VERIFIED' THEN
                IF NOT authn.authorize_action('tenant.privacy.verify')
                   OR NEW.requester_id IS NULL
                   OR NEW.requester_id = authn.current_user_id()
                   OR NEW.identity_verified_by IS DISTINCT FROM authn.current_user_id() THEN
                    RAISE EXCEPTION 'data-subject verification is not authorized';
                END IF;
            ELSIF OLD.status = 'VERIFIED' AND NEW.status IN ('APPROVED','REJECTED') THEN
                IF NOT authn.authorize_action('tenant.privacy.decide')
                   OR NEW.decision_by IS NULL
                   OR NEW.decision_by IS DISTINCT FROM authn.current_user_id()
                   OR NEW.identity_verified_by IS NULL
                   OR NEW.identity_verified_by = authn.current_user_id() THEN
                    RAISE EXCEPTION 'data-subject decision is not authorized';
                END IF;
            ELSIF OLD.status = 'VERIFIED'
                  AND NEW.status = 'COMPLETED'
                  AND NEW.request_type = 'ACCESS' THEN
                IF NOT authn.authorize_action('tenant.privacy.decide')
                   OR NEW.decision IS DISTINCT FROM 'APPROVED'
                   OR NEW.decision_by IS NULL
                   OR NEW.decision_by IS DISTINCT FROM authn.current_user_id()
                   OR NEW.identity_verified_by IS NULL
                   OR NEW.identity_verified_by = authn.current_user_id() THEN
                    RAISE EXCEPTION 'data-subject access completion is not authorized';
                END IF;
            ELSIF OLD.status = 'APPROVED' AND NEW.status = 'COMPLETED' THEN
                IF NOT authn.authorize_action('tenant.privacy.execute')
                   OR OLD.decision_by IS NULL
                   OR OLD.decision_by = authn.current_user_id() THEN
                    RAISE EXCEPTION 'data-subject execution is not authorized';
                END IF;
            ELSE
                RAISE EXCEPTION 'invalid data-subject request transition';
            END IF;
            RETURN NEW;
        END;
        $$;
        DROP TRIGGER IF EXISTS data_subject_request_transition_guard ON public.data_subject_requests;
        CREATE TRIGGER data_subject_request_transition_guard
            BEFORE UPDATE ON public.data_subject_requests
            FOR EACH ROW EXECUTE FUNCTION authn.enforce_dsr_transition();

        CREATE OR REPLACE FUNCTION authn.has_role(p_roles text[]) RETURNS boolean
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
            SELECT authn.current_role() = ANY(p_roles)
        $$;

        CREATE OR REPLACE FUNCTION authn.authorize_action(p_action text) RETURNS boolean
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, authn, public
        AS $$
        DECLARE v_role text := authn.current_role();
        BEGIN
            RETURN CASE p_action
                WHEN 'tenant.users.read' THEN v_role IN ('viewer','developer','operator','auditor','approver','tenant_administrator')
                WHEN 'tenant.users.manage' THEN v_role = 'tenant_administrator'
                WHEN 'tenant.credentials.manage' THEN v_role = 'tenant_administrator'
                WHEN 'tenant.credentials.read' THEN v_role = 'tenant_administrator'
                WHEN 'tenant.policies.manage' THEN v_role = 'tenant_administrator'
                WHEN 'tenant.policies.read' THEN v_role = 'tenant_administrator'
                WHEN 'tenant.connectors.manage' THEN v_role = 'tenant_administrator'
                WHEN 'tenant.connectors.read' THEN v_role = 'tenant_administrator'
                WHEN 'tenant.audit.read' THEN v_role IN ('auditor','approver','tenant_administrator')
                WHEN 'tenant.access_review.export' THEN v_role IN ('auditor','tenant_administrator')
                WHEN 'tenant.high_risk.approve' THEN v_role = 'approver'
                WHEN 'tenant.approvals.expire' THEN v_role IN ('operator','approver','tenant_administrator')
                WHEN 'tenant.approvals.read' THEN v_role IN ('viewer','developer','operator','auditor','approver','tenant_administrator')
                WHEN 'tenant.workflow.create' THEN v_role IN ('developer','operator','tenant_administrator')
                WHEN 'tenant.workflow.resume' THEN v_role IN ('operator','tenant_administrator')
                WHEN 'tenant.workflow.remediate' THEN v_role IN ('operator','tenant_administrator')
                WHEN 'tenant.privacy.request' THEN v_role = 'tenant_administrator'
                WHEN 'tenant.privacy.verify' THEN v_role = 'tenant_administrator'
                WHEN 'tenant.privacy.decide' THEN v_role = 'approver'
                WHEN 'tenant.privacy.execute' THEN v_role IN ('operator','tenant_administrator')
                WHEN 'platform.tenant.manage' THEN v_role = 'platform_administrator'
                ELSE false
            END;
        END;
        $$;

        -- Replace the broad tenant-only policies on security-sensitive tables
        -- with independent role checks. Tenant isolation remains mandatory.
        DROP POLICY IF EXISTS tenant_isolation ON public.api_keys;
        CREATE POLICY tenant_isolation ON public.api_keys FOR SELECT
            USING (tenant_id = authn.current_tenant_id()
                   AND authn.authorize_action('tenant.credentials.manage'));
        CREATE POLICY tenant_admin_api_keys_write ON public.api_keys FOR ALL
            USING (tenant_id = authn.current_tenant_id()
                   AND authn.authorize_action('tenant.credentials.manage'))
            WITH CHECK (tenant_id = authn.current_tenant_id()
                        AND authn.authorize_action('tenant.credentials.manage'));
        CREATE POLICY tenant_access_review_api_keys_read ON public.api_keys FOR SELECT
            USING (tenant_id = authn.current_tenant_id()
                   AND authn.authorize_action('tenant.access_review.export'));

        DROP POLICY IF EXISTS tenant_isolation ON public.users;
        CREATE POLICY tenant_user_read ON public.users FOR SELECT
            USING (tenant_id = authn.current_tenant_id()
                   AND authn.authorize_action('tenant.users.read'));
        CREATE POLICY tenant_user_insert ON public.users FOR INSERT
            WITH CHECK (tenant_id = authn.current_tenant_id()
                        AND authn.authorize_action('tenant.users.manage'));
        CREATE POLICY tenant_user_update ON public.users FOR UPDATE
            USING (tenant_id = authn.current_tenant_id()
                   AND authn.authorize_action('tenant.users.manage'))
            WITH CHECK (tenant_id = authn.current_tenant_id()
                        AND authn.authorize_action('tenant.users.manage'));
        CREATE POLICY tenant_user_delete ON public.users FOR DELETE
            USING (tenant_id = authn.current_tenant_id()
                   AND authn.authorize_action('tenant.users.manage'));

        DROP POLICY IF EXISTS tenant_isolation ON public.policies;
        CREATE POLICY tenant_policy_read ON public.policies FOR SELECT
            USING (tenant_id = authn.current_tenant_id()
                   AND authn.authorize_action('tenant.policies.read'));
        CREATE POLICY tenant_policy_write ON public.policies FOR INSERT
            WITH CHECK (tenant_id = authn.current_tenant_id()
                        AND authn.authorize_action('tenant.policies.manage'));
        CREATE POLICY tenant_policy_update ON public.policies FOR UPDATE
            USING (tenant_id = authn.current_tenant_id()
                   AND authn.authorize_action('tenant.policies.manage'))
            WITH CHECK (tenant_id = authn.current_tenant_id()
                        AND authn.authorize_action('tenant.policies.manage'));
        CREATE POLICY tenant_policy_delete ON public.policies FOR DELETE
            USING (tenant_id = authn.current_tenant_id()
                   AND authn.authorize_action('tenant.policies.manage'));

        DROP POLICY IF EXISTS tenant_isolation ON public.gateway_configs;
        CREATE POLICY tenant_gateway_read ON public.gateway_configs FOR SELECT
            USING (tenant_id = authn.current_tenant_id()
                   AND authn.authorize_action('tenant.connectors.read'));
        CREATE POLICY tenant_gateway_write ON public.gateway_configs FOR INSERT
            WITH CHECK (tenant_id = authn.current_tenant_id()
                        AND authn.authorize_action('tenant.connectors.manage'));
        CREATE POLICY tenant_gateway_update ON public.gateway_configs FOR UPDATE
            USING (tenant_id = authn.current_tenant_id()
                   AND authn.authorize_action('tenant.connectors.manage'))
            WITH CHECK (tenant_id = authn.current_tenant_id()
                        AND authn.authorize_action('tenant.connectors.manage'));
        CREATE POLICY tenant_gateway_delete ON public.gateway_configs FOR DELETE
            USING (tenant_id = authn.current_tenant_id()
                   AND authn.authorize_action('tenant.connectors.manage'));

        DROP POLICY IF EXISTS tenant_isolation ON public.provider_credentials;
        CREATE POLICY tenant_provider_read ON public.provider_credentials FOR SELECT
            USING (tenant_id = authn.current_tenant_id()
                   AND authn.authorize_action('tenant.credentials.read'));
        CREATE POLICY tenant_provider_write ON public.provider_credentials FOR INSERT
            WITH CHECK (tenant_id = authn.current_tenant_id()
                        AND authn.authorize_action('tenant.credentials.manage'));
        CREATE POLICY tenant_provider_update ON public.provider_credentials FOR UPDATE
            USING (tenant_id = authn.current_tenant_id()
                   AND authn.authorize_action('tenant.credentials.manage'))
            WITH CHECK (tenant_id = authn.current_tenant_id()
                        AND authn.authorize_action('tenant.credentials.manage'));
        CREATE POLICY tenant_provider_delete ON public.provider_credentials FOR DELETE
            USING (tenant_id = authn.current_tenant_id()
                   AND authn.authorize_action('tenant.credentials.manage'));

        DROP POLICY IF EXISTS tenant_isolation ON public.pending_approvals;
        CREATE POLICY tenant_approval_read ON public.pending_approvals FOR SELECT
            USING (tenant_id = authn.current_tenant_id()
                   AND authn.authorize_action('tenant.approvals.read'));
        CREATE POLICY tenant_approval_create ON public.pending_approvals FOR INSERT
            WITH CHECK (tenant_id = authn.current_tenant_id()
                        AND authn.current_role() IN ('developer','operator','tenant_administrator'));
        CREATE POLICY tenant_approval_resolve ON public.pending_approvals FOR UPDATE
            USING (tenant_id = authn.current_tenant_id()
                   AND authn.authorize_action('tenant.high_risk.approve')
                   AND requester_id <> authn.current_user_id())
            WITH CHECK (tenant_id = authn.current_tenant_id()
                        AND authn.authorize_action('tenant.high_risk.approve')
                        AND requester_id <> authn.current_user_id());
        CREATE POLICY tenant_approval_expire ON public.pending_approvals FOR UPDATE
            USING (tenant_id = authn.current_tenant_id()
                   AND status = 'PENDING'
                   AND expires_at < now()
                   AND authn.authorize_action('tenant.approvals.expire'))
            WITH CHECK (tenant_id = authn.current_tenant_id()
                        AND status = 'EXPIRED'
                        AND authn.authorize_action('tenant.approvals.expire'));

        ALTER TABLE public.data_subject_requests
            ADD COLUMN IF NOT EXISTS requester_id uuid REFERENCES public.users(id);
        DROP POLICY IF EXISTS data_subject_requests_tenant_isolation ON public.data_subject_requests;
        CREATE POLICY data_subject_requests_read ON public.data_subject_requests FOR SELECT
            USING (tenant_id = authn.current_tenant_id()
                   AND authn.authorize_action('tenant.audit.read'));
        CREATE POLICY data_subject_requests_create ON public.data_subject_requests FOR INSERT
            WITH CHECK (tenant_id = authn.current_tenant_id()
                        AND authn.authorize_action('tenant.privacy.request'));
        CREATE POLICY data_subject_requests_update ON public.data_subject_requests FOR UPDATE
            USING (tenant_id = authn.current_tenant_id()
                   AND (authn.authorize_action('tenant.privacy.verify')
                        OR authn.authorize_action('tenant.privacy.decide')
                        OR authn.authorize_action('tenant.privacy.execute')))
            WITH CHECK (tenant_id = authn.current_tenant_id());

        DROP POLICY IF EXISTS tenant_isolation ON public.audit_log_metadata;
        CREATE POLICY tenant_audit_read ON public.audit_log_metadata FOR SELECT
            USING (tenant_id = authn.current_tenant_id()
                   AND authn.authorize_action('tenant.audit.read'));
        CREATE POLICY tenant_audit_append ON public.audit_log_metadata FOR INSERT
            WITH CHECK (tenant_id = authn.current_tenant_id());
        """
    )
    app_role = _app_role()
    op.execute(f"GRANT USAGE ON SCHEMA authn TO {app_role}")
    op.execute(
        f"""
        REVOKE ALL ON FUNCTION authn.current_role() FROM PUBLIC;
        REVOKE ALL ON FUNCTION authn.has_role(text[]) FROM PUBLIC;
        REVOKE ALL ON FUNCTION authn.authorize_action(text) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION authn.current_role() TO {app_role};
        GRANT EXECUTE ON FUNCTION authn.has_role(text[]) TO {app_role};
        GRANT EXECUTE ON FUNCTION authn.authorize_action(text) TO {app_role};
        REVOKE ALL ON FUNCTION authn.enforce_pending_approval_transition() FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION authn.enforce_pending_approval_transition() TO {app_role};
        """
    )


def downgrade() -> None:
    raise RuntimeError("ENT-026 authorization migration is security-irreversible")

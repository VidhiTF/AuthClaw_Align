"""HMAC cutover barrier and restricted worker maintenance.

Revision ID: 043
Revises: 042
"""

from alembic import op

revision = "043"
down_revision = "042"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        ALTER TABLE public.ephemeral_worker_tokens
          ADD COLUMN hash_algorithm varchar(32) NOT NULL DEFAULT 'sha256',
          ADD COLUMN hash_key_version varchar(16);
        CREATE INDEX idx_worker_global_expiry ON public.ephemeral_worker_tokens (expires_at, id)
          WHERE status = 'active';
        CREATE TABLE worker_maintenance.control (
          singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
          mode text NOT NULL DEFAULT 'paused' CHECK(mode IN ('paused','hmac')),
          paused_at timestamptz,
          activated_at timestamptz
        );
        INSERT INTO worker_maintenance.control(singleton) VALUES (true);
        CREATE TABLE worker_maintenance.heartbeat (
          singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
          last_success timestamptz,
          expired_count integer NOT NULL DEFAULT 0,
          duration_ms integer NOT NULL DEFAULT 0
        );
        INSERT INTO worker_maintenance.heartbeat(singleton) VALUES (true);
        REVOKE ALL ON ALL TABLES IN SCHEMA worker_maintenance FROM PUBLIC;

        CREATE FUNCTION worker_maintenance.guard_token_write() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
        DECLARE v_mode text;
        BEGIN
          IF TG_OP = 'UPDATE' THEN
            IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
               OR NEW.token_hash IS DISTINCT FROM OLD.token_hash
               OR NEW.hash_algorithm IS DISTINCT FROM OLD.hash_algorithm
               OR NEW.hash_key_version IS DISTINCT FROM OLD.hash_key_version
               OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
               OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
               OR (OLD.status <> 'active' AND NEW.status = 'active') THEN
              RAISE EXCEPTION 'Worker token identity and lifetime are immutable' USING ERRCODE='42501';
            END IF;
            RETURN NEW;
          END IF;
          SELECT mode INTO STRICT v_mode FROM worker_maintenance.control WHERE singleton FOR SHARE;
          IF v_mode <> 'hmac' THEN
            RAISE EXCEPTION 'Worker token issuance is paused' USING ERRCODE='55000';
          END IF;
          IF NEW.hash_algorithm <> 'hmac-sha256-v1' OR NEW.hash_key_version IS NULL
             OR NEW.hash_key_version !~ '^v[1-9][0-9]{0,3}$'
             OR NEW.token_hash !~ '^[0-9a-f]{64}$'
             OR NEW.expires_at <= clock_timestamp()
             OR NEW.expires_at > clock_timestamp() + interval '30 minutes' THEN
            RAISE EXCEPTION 'Worker token format or lifetime is invalid' USING ERRCODE='22023';
          END IF;
          RETURN NEW;
        END; $$;
        CREATE TRIGGER worker_token_write_guard BEFORE INSERT OR UPDATE
          ON public.ephemeral_worker_tokens FOR EACH ROW
          EXECUTE FUNCTION worker_maintenance.guard_token_write();

        CREATE FUNCTION worker_maintenance.issuance_ready() RETURNS boolean
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
          SELECT mode = 'hmac' FROM worker_maintenance.control WHERE singleton
        $$;

        CREATE FUNCTION worker_maintenance.expire_tokens(p_limit integer DEFAULT 500)
        RETURNS TABLE(acquired boolean, expired integer, last_success timestamptz)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
        DECLARE r record; n integer := 0; started timestamptz := clock_timestamp();
          previous_tenant text := current_setting('app.current_tenant_id', true);
        BEGIN
          IF p_limit IS NULL OR p_limit < 1 OR p_limit > 500 THEN
            RAISE EXCEPTION 'Invalid cleanup batch bound' USING ERRCODE='22023';
          END IF;
          IF NOT pg_try_advisory_xact_lock(734271, 7) THEN
            RETURN QUERY SELECT false, 0, h.last_success FROM worker_maintenance.heartbeat h WHERE singleton;
            RETURN;
          END IF;
          FOR r IN
            SELECT candidate.* FROM (
              SELECT id, tenant_id, connector, workflow_id FROM public.ephemeral_worker_tokens
               WHERE status = 'active' AND expires_at <= statement_timestamp()
               ORDER BY expires_at, id LIMIT p_limit FOR UPDATE SKIP LOCKED
            ) candidate ORDER BY candidate.tenant_id, candidate.id
          LOOP
            UPDATE public.ephemeral_worker_tokens SET status = 'expired' WHERE id = r.id;
            PERFORM set_config('app.current_tenant_id', r.tenant_id::text, true);
            PERFORM public.append_audit_event_v2(
              p_tenant_id => r.tenant_id, p_record_id => public.gen_random_uuid(),
              p_idempotency_key => 'worker-expiry:' || r.id::text,
              p_occurred_at => started, p_actor_type => 'ephemeral_worker',
              p_action => 'worker:token.expired', p_provider => 'ephemeral-worker',
              p_model => r.connector, p_reason => 'Worker token expired by sweeper',
              p_execution_trace => jsonb_build_array('worker_token_id=' || r.id::text)
            );
            n := n + 1;
          END LOOP;
          PERFORM set_config('app.current_tenant_id', COALESCE(previous_tenant, ''), true);
          UPDATE worker_maintenance.heartbeat h SET last_success = clock_timestamp(),
            expired_count = n, duration_ms = greatest(0, (extract(epoch FROM clock_timestamp() - started)*1000)::integer)
            WHERE singleton;
          RETURN QUERY SELECT true, n, h.last_success FROM worker_maintenance.heartbeat h WHERE singleton;
        END; $$;

        CREATE FUNCTION worker_maintenance.cleanup_health()
        RETURNS TABLE(last_success timestamptz, expired_count integer, duration_ms integer, overdue boolean)
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
          SELECT h.last_success, h.expired_count, h.duration_ms,
            h.last_success IS NULL OR h.last_success < statement_timestamp() - interval '5 minutes'
            FROM worker_maintenance.heartbeat h WHERE singleton
        $$;
        REVOKE ALL ON ALL FUNCTIONS IN SCHEMA worker_maintenance FROM PUBLIC;
    """)


def downgrade():
    raise RuntimeError(
        "Worker-token retirement cannot be downgraded; preserve the issuance barrier"
    )

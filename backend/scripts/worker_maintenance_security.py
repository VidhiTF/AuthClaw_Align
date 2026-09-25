"""Bootstrap-only ownership/ACL wiring. Never loaded by the API."""

from sqlalchemy import text

OWNER = "authclaw_worker_maintenance"


def prepare(conn, migrator):
    quote = conn.dialect.identifier_preparer.quote
    if not conn.execute(
        text("SELECT 1 FROM pg_roles WHERE rolname=:role"), {"role": OWNER}
    ).scalar():
        conn.execute(text(f"CREATE ROLE {OWNER} NOLOGIN"))
    conn.execute(
        text(
            f"ALTER ROLE {OWNER} NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS"
        )
    )
    conn.execute(
        text(
            f"CREATE SCHEMA IF NOT EXISTS worker_maintenance AUTHORIZATION {quote(migrator)}"
        )
    )
    conn.execute(text("REVOKE ALL ON SCHEMA worker_maintenance FROM PUBLIC"))
    # The bootstrap identity, never runtime, owns catalog changes during upgrades.
    conn.execute(
        text(f"GRANT USAGE, CREATE ON SCHEMA worker_maintenance TO {quote(migrator)}")
    )
    # A later migration may need to evolve the cleanup function before the
    # NOLOGIN worker owner is restored by finalize().
    if conn.execute(text("SELECT to_regprocedure('worker_maintenance.expire_tokens(integer)')")).scalar():
        conn.execute(text(
            f"ALTER FUNCTION worker_maintenance.expire_tokens(integer) OWNER TO {quote(migrator)}"
        ))


def finalize(conn, migrator, runtime):
    if not conn.execute(
        text("SELECT to_regclass('worker_maintenance.control')")
    ).scalar():
        return
    quote = conn.dialect.identifier_preparer.quote
    app = quote(runtime)
    for role in (app, quote(migrator)):
        conn.execute(text(f"REVOKE {OWNER} FROM {role}"))
    conn.execute(text(f"GRANT USAGE ON SCHEMA public, worker_maintenance TO {OWNER}"))
    conn.execute(
        text(
            f"GRANT SELECT(id, tenant_id, connector, workflow_id, status, expires_at), UPDATE(status) ON public.ephemeral_worker_tokens TO {OWNER}"
        )
    )
    conn.execute(text(f"GRANT SELECT, INSERT ON public.audit_log_metadata TO {OWNER}"))
    conn.execute(text(f"GRANT INSERT ON public.audit_outbox TO {OWNER}"))
    conn.execute(text(f"GRANT USAGE ON SEQUENCE public.audit_outbox_id_seq TO {OWNER}"))
    # Canonical append reads the audit chain; the function caller never receives it.
    for table in ("ephemeral_worker_tokens", "audit_log_metadata", "audit_outbox"):
        conn.execute(
            text(f"DROP POLICY IF EXISTS worker_maintenance_access ON public.{table}")
        )
        conn.execute(
            text(
                f"CREATE POLICY worker_maintenance_access ON public.{table} TO {OWNER} USING (true) WITH CHECK (true)"
            )
        )
    for signature in conn.execute(
        text(
            "SELECT oid::regprocedure::text FROM pg_proc WHERE pronamespace='public'::regnamespace AND proname IN ('append_audit_event_v2','gen_random_uuid','digest')"
        )
    ).scalars():
        conn.execute(text(f"GRANT EXECUTE ON FUNCTION {signature} TO {OWNER}"))
    for table in ("control", "heartbeat"):
        conn.execute(text(f"ALTER TABLE worker_maintenance.{table} OWNER TO {OWNER}"))
    for signature in conn.execute(
        text(
            "SELECT oid::regprocedure::text FROM pg_proc WHERE pronamespace='worker_maintenance'::regnamespace"
        )
    ).scalars():
        conn.execute(text(f"ALTER FUNCTION {signature} OWNER TO {OWNER}"))
    conn.execute(
        text(
            f"REVOKE ALL ON ALL TABLES IN SCHEMA worker_maintenance FROM PUBLIC, {app}"
        )
    )
    conn.execute(
        text(
            f"REVOKE ALL ON ALL FUNCTIONS IN SCHEMA worker_maintenance FROM PUBLIC, {app}"
        )
    )
    conn.execute(text(f"GRANT USAGE ON SCHEMA worker_maintenance TO {app}"))
    conn.execute(
        text(
            f"GRANT EXECUTE ON FUNCTION worker_maintenance.expire_tokens(integer), worker_maintenance.cleanup_health(), worker_maintenance.issuance_ready() TO {app}"
        )
    )

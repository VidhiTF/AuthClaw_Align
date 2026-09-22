"""Provision shared-Postgres identities, ownership, and runtime grants.

This script is deliberately separate from schema migrations. Run ``prepare``
before migrations and ``finalize`` after both schemas exist.
"""

from __future__ import annotations

import argparse
import os
import re
from dataclasses import dataclass

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
try:
    from scripts import worker_maintenance_security
except ModuleNotFoundError:
    import worker_maintenance_security

IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
BACKEND_RUNTIME_FUNCTIONS = {
    "access_request_onboarding_started",
    "append_audit_event_v2",
    "resolve_api_key",
    "resolve_trust_center_share",
}
AUTH_DEFINER_ROLE = os.getenv("AUTH_DEFINER_ROLE", "authclaw_auth_definer")
AUDIT_VERIFIER_ROLE = os.getenv("AUDIT_VERIFIER_ROLE", "authclaw_audit_verifier")
AGENT_AUTH_DEFINER_ROLE = os.getenv(
    "AGENT_AUTH_DEFINER_ROLE", "authclaw_agent_auth_definer"
)
AUTHN_RUNTIME_FUNCTIONS = {
    "bind_api_key_context",
    "bind_platform_session_context",
    "bind_session_context",
    "current_role",
    "has_role",
    "authorize_action",
    "consume_onboarding_invite_for_otp",
    "confirm_password_reset",
    "create_platform_tenant_owner_invite",
    "create_password_reset",
    "create_session",
    "create_tenant",
    "create_tenant_as_platform_admin",
    "current_platform_admin_id",
    "current_tenant_id",
    "lookup_platform_password_identity",
    "lookup_password_identities",
    "lookup_oidc_config",
    "issue_oidc_session",
    "platform_admin_profile",
    "prepare_onboarding_invite_resend",
    "revoke_platform_session",
    "revoke_session",
    "revoke_user_sessions",
    "set_password_reset_delivery",
}


def acquire_initialization_lock(conn) -> None:
    """Bound catalog waits and serialize every database-security phase."""
    conn.execute(text("SET LOCAL lock_timeout = '15s'"))
    conn.execute(text("SET LOCAL statement_timeout = '120s'"))
    conn.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended('authclaw.database.security', 0))")
    )

@dataclass(frozen=True)
class Role:
    name: str
    password: str
    schema: str


def normalize_database_url(url: str) -> str:
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


def require_identifier(value: str, variable: str) -> str:
    if not IDENTIFIER_RE.fullmatch(value):
        raise ValueError(f"{variable} must be a valid PostgreSQL identifier")
    return value


def quote_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def role_from_env(
    prefix: str, default_name: str, default_password: str, schema: str
) -> Role:
    return Role(
        name=require_identifier(
            os.getenv(f"{prefix}_USER", default_name), f"{prefix}_USER"
        ),
        password=os.getenv(f"{prefix}_PASSWORD", default_password),
        schema=schema,
    )


def role_from_url(
    variable: str, prefix: str, default_name: str, default_password: str, schema: str
) -> Role:
    raw_url = os.getenv(variable, "").strip()
    if not raw_url:
        return role_from_env(prefix, default_name, default_password, schema)
    url = make_url(normalize_database_url(raw_url))
    if not url.username or url.password is None:
        raise ValueError(f"{variable} must include a username and password")
    return Role(
        name=require_identifier(url.username, f"{variable} username"),
        password=url.password,
        schema=schema,
    )


def configured_roles() -> tuple[Role, Role, Role, Role]:
    return (
        role_from_url(
            "BACKEND_MIGRATION_DATABASE_URL",
            "BACKEND_MIGRATOR",
            "authclaw_migrator",
            "authclaw_migrator",
            "public",
        ),
        role_from_url(
            "BACKEND_DATABASE_URL",
            "POSTGRES_APP",
            "authclaw_app",
            "authclaw_app",
            "public",
        ),
        role_from_url(
            "AGENT_MIGRATION_DATABASE_URL",
            "AGENT_MIGRATOR",
            "authclaw_agent_migrator",
            "authclaw_agent_migrator",
            "agent",
        ),
        role_from_url(
            "AGENT_DATABASE_URL",
            "AGENT_RUNTIME",
            "authclaw_agent_runtime",
            "authclaw_agent_runtime",
            "agent",
        ),
    )


def ensure_login_role(conn, role: Role) -> None:
    quoted_role = conn.dialect.identifier_preparer.quote(role.name)
    password = quote_literal(role.password)
    exists = conn.execute(
        text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role.name}
    ).fetchone()
    if not exists:
        conn.execute(text(f"CREATE ROLE {quoted_role} LOGIN PASSWORD {password}"))
    conn.execute(
        text(
            f"ALTER ROLE {quoted_role} LOGIN PASSWORD {password} "
            "NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS"
        )
    )


def ensure_auth_definer_role(conn) -> None:
    require_identifier(AUTH_DEFINER_ROLE, "AUTH_DEFINER_ROLE")
    quote = conn.dialect.identifier_preparer.quote
    role = quote(AUTH_DEFINER_ROLE)
    exists = conn.execute(
        text("SELECT 1 FROM pg_roles WHERE rolname = :role"),
        {"role": AUTH_DEFINER_ROLE},
    ).fetchone()
    if not exists:
        conn.execute(text(f"CREATE ROLE {role} NOLOGIN"))
    conn.execute(
        text(
            f"ALTER ROLE {role} NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB "
            "NOCREATEROLE BYPASSRLS"
        )
    )


def ensure_agent_auth_definer_role(conn) -> None:
    require_identifier(AGENT_AUTH_DEFINER_ROLE, "AGENT_AUTH_DEFINER_ROLE")
    quote = conn.dialect.identifier_preparer.quote
    role = quote(AGENT_AUTH_DEFINER_ROLE)
    exists = conn.execute(
        text("SELECT 1 FROM pg_roles WHERE rolname = :role"),
        {"role": AGENT_AUTH_DEFINER_ROLE},
    ).fetchone()
    if not exists:
        conn.execute(text(f"CREATE ROLE {role} NOLOGIN"))
    conn.execute(
        text(
            f"ALTER ROLE {role} NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB "
            "NOCREATEROLE BYPASSRLS"
        )
    )


def ensure_audit_verifier_role(conn) -> None:
    require_identifier(AUDIT_VERIFIER_ROLE, "AUDIT_VERIFIER_ROLE")
    role = conn.dialect.identifier_preparer.quote(AUDIT_VERIFIER_ROLE)
    exists = conn.execute(
        text("SELECT 1 FROM pg_roles WHERE rolname = :role"),
        {"role": AUDIT_VERIFIER_ROLE},
    ).fetchone()
    if not exists:
        conn.execute(text(f"CREATE ROLE {role} NOLOGIN"))
    conn.execute(
        text(
            f"ALTER ROLE {role} NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB "
            "NOCREATEROLE NOBYPASSRLS"
        )
    )


def configure_default_privileges(conn, migrator: Role, runtime: Role) -> None:
    quote = conn.dialect.identifier_preparer.quote
    owner = quote(migrator.name)
    app = quote(runtime.name)
    schema = quote(migrator.schema)
    for object_type in ("TABLES", "SEQUENCES", "FUNCTIONS"):
        conn.execute(
            text(
                f"ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA {schema} "
                f"REVOKE ALL ON {object_type} FROM PUBLIC"
            )
        )
    conn.execute(
        text(
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA {schema} "
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {app}"
        )
    )
    conn.execute(
        text(
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA {schema} "
            f"GRANT USAGE, SELECT ON SEQUENCES TO {app}"
        )
    )


def prepare_backend_security_objects_for_migration(conn, backend_migrator: Role) -> None:
    """Return finalized auth objects to the migrator before an Alembic upgrade."""
    quote = conn.dialect.identifier_preparer.quote
    migrator = quote(backend_migrator.name)
    tables = conn.execute(
        text(
            "SELECT c.oid::regclass::text FROM pg_class c "
            "JOIN pg_namespace n ON n.oid=c.relnamespace "
            "JOIN pg_roles r ON r.oid=c.relowner "
            "WHERE n.nspname='authn' AND c.relkind IN ('r', 'p') "
            "AND r.rolname=:definer"
        ),
        {"definer": AUTH_DEFINER_ROLE},
    ).scalars()
    for table_name in tables:
        conn.execute(text(f"ALTER TABLE {table_name} OWNER TO {migrator}"))
    signatures = conn.execute(
        text(
            "SELECT p.oid::regprocedure::text FROM pg_proc p "
            "JOIN pg_namespace n ON n.oid=p.pronamespace "
            "JOIN pg_roles r ON r.oid=p.proowner "
            "WHERE n.nspname='authn' AND r.rolname=:definer"
        ),
        {"definer": AUTH_DEFINER_ROLE},
    ).scalars()
    for signature in signatures:
        conn.execute(text(f"ALTER FUNCTION {signature} OWNER TO {migrator}"))


def prepare_agent_security_objects_for_migration(conn, agent_migrator: Role) -> None:
    quote = conn.dialect.identifier_preparer.quote
    migrator = quote(agent_migrator.name)
    table_name = conn.execute(
        text("SELECT to_regclass('agent.auth_context_secret')::text")
    ).scalar_one_or_none()
    if table_name:
        conn.execute(text(f"ALTER TABLE {table_name} OWNER TO {migrator}"))
    signatures = conn.execute(
        text(
            "SELECT p.oid::regprocedure::text FROM pg_proc p "
            "JOIN pg_namespace n ON n.oid=p.pronamespace "
            "JOIN pg_roles r ON r.oid=p.proowner "
            "WHERE n.nspname='agent' AND r.rolname=:definer"
        ),
        {"definer": AGENT_AUTH_DEFINER_ROLE},
    ).scalars()
    for signature in signatures:
        conn.execute(text(f"ALTER FUNCTION {signature} OWNER TO {migrator}"))


def prepare_existing_schema_objects_for_migration(conn, migrator: Role) -> None:
    owner = conn.dialect.identifier_preparer.quote(migrator.name)
    relations = conn.execute(
        text(
            """
            SELECT format('%I.%I', schemaname, tablename)
              FROM pg_tables
             WHERE schemaname = :schema
            UNION ALL
            SELECT format('%I.%I', schemaname, viewname)
              FROM pg_views
             WHERE schemaname = :schema
            UNION ALL
            SELECT format('%I.%I', schemaname, matviewname)
              FROM pg_matviews
             WHERE schemaname = :schema
            """
        ),
        {"schema": migrator.schema},
    ).scalars()
    for relation in relations:
        conn.execute(text(f"ALTER TABLE {relation} OWNER TO {owner}"))

    sequences = conn.execute(
        text(
            """
            SELECT format('%I.%I', schemaname, sequencename)
              FROM pg_sequences
             WHERE schemaname = :schema
            """
        ),
        {"schema": migrator.schema},
    ).scalars()
    for sequence in sequences:
        conn.execute(text(f"ALTER SEQUENCE {sequence} OWNER TO {owner}"))

    signatures = conn.execute(
        text(
            """
            SELECT p.oid::regprocedure::text
              FROM pg_proc p
              JOIN pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname IN (:schema, 'authn')
            """
        ),
        {"schema": migrator.schema},
    ).scalars()
    for signature in signatures:
        conn.execute(text(f"ALTER FUNCTION {signature} OWNER TO {owner}"))


def prepare(conn, database_name: str, roles: tuple[Role, Role, Role, Role]) -> None:
    quote = conn.dialect.identifier_preparer.quote
    database = quote(database_name)
    backend_migrator, backend_runtime, agent_migrator, agent_runtime = roles

    ensure_auth_definer_role(conn)
    ensure_agent_auth_definer_role(conn)
    ensure_audit_verifier_role(conn)

    for role in roles:
        ensure_login_role(conn, role)
        conn.execute(
            text(f"GRANT CONNECT ON DATABASE {database} TO {quote(role.name)}")
        )
        conn.execute(
            text(
                f"ALTER ROLE {quote(role.name)} SET search_path = {quote(role.schema)}, pg_catalog"
            )
        )

    # Schema ownership requires its login role even on a brand-new cluster.
    worker_maintenance_security.prepare(conn, backend_migrator.name)

    conn.execute(
        text(
            f"REVOKE {quote(backend_migrator.name)} FROM {quote(backend_runtime.name)}"
        )
    )
    conn.execute(
        text(f"REVOKE {quote(agent_migrator.name)} FROM {quote(agent_runtime.name)}")
    )

    conn.execute(text("CREATE EXTENSION IF NOT EXISTS pgcrypto"))
    bootstrap_user = conn.execute(text("SELECT session_user")).scalar_one()
    secure_owned_functions(
        conn, bootstrap_user, "public", (backend_migrator.name, backend_runtime.name)
    )
    conn.execute(text("REVOKE CREATE, USAGE ON SCHEMA public FROM PUBLIC"))
    conn.execute(text(f"ALTER SCHEMA public OWNER TO {quote(backend_migrator.name)}"))
    conn.execute(
        text(f"GRANT USAGE, CREATE ON SCHEMA public TO {quote(backend_migrator.name)}")
    )
    conn.execute(text(f"GRANT USAGE ON SCHEMA public TO {quote(backend_runtime.name)}"))
    conn.execute(text(f"GRANT USAGE ON SCHEMA public TO {quote(AUDIT_VERIFIER_ROLE)}"))
    prepare_existing_schema_objects_for_migration(conn, backend_migrator)
    conn.execute(
        text(
            f"CREATE SCHEMA IF NOT EXISTS authn "
            f"AUTHORIZATION {quote(backend_migrator.name)}"
        )
    )
    conn.execute(text(f"ALTER SCHEMA authn OWNER TO {quote(backend_migrator.name)}"))
    conn.execute(text("REVOKE ALL ON SCHEMA authn FROM PUBLIC"))
    conn.execute(
        text(f"GRANT USAGE, CREATE ON SCHEMA authn TO {quote(backend_migrator.name)}")
    )

    conn.execute(
        text(
            f"CREATE SCHEMA IF NOT EXISTS agent AUTHORIZATION {quote(agent_migrator.name)}"
        )
    )
    conn.execute(text(f"ALTER SCHEMA agent OWNER TO {quote(agent_migrator.name)}"))
    conn.execute(text("REVOKE ALL ON SCHEMA agent FROM PUBLIC"))
    conn.execute(
        text(f"GRANT USAGE, CREATE ON SCHEMA agent TO {quote(agent_migrator.name)}")
    )
    conn.execute(text(f"GRANT USAGE ON SCHEMA agent TO {quote(agent_runtime.name)}"))
    prepare_backend_security_objects_for_migration(conn, backend_migrator)
    prepare_agent_security_objects_for_migration(conn, agent_migrator)

    configure_default_privileges(conn, backend_migrator, backend_runtime)
    configure_default_privileges(conn, agent_migrator, agent_runtime)


def secure_owned_functions(
    conn, owner_role: str, schema_name: str, execute_roles: tuple[str, ...]
) -> None:
    signatures = conn.execute(
        text("""
            SELECT function.oid::regprocedure::text
            FROM pg_proc AS function
            JOIN pg_namespace AS namespace ON namespace.oid = function.pronamespace
            JOIN pg_roles AS owner ON owner.oid = function.proowner
            WHERE namespace.nspname = :schema AND owner.rolname = :owner
            """),
        {"schema": schema_name, "owner": owner_role},
    ).scalars()
    quote = conn.dialect.identifier_preparer.quote
    grantees = ", ".join(quote(role) for role in execute_roles)
    for signature in signatures:
        conn.execute(text(f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC"))
        if grantees:
            conn.execute(text(f"GRANT EXECUTE ON FUNCTION {signature} TO {grantees}"))


def grant_runtime_objects(conn, migrator: Role, runtime: Role) -> None:
    quote = conn.dialect.identifier_preparer.quote
    schema = quote(migrator.schema)
    app = quote(runtime.name)
    conn.execute(text(f"REVOKE ALL ON ALL TABLES IN SCHEMA {schema} FROM PUBLIC"))
    conn.execute(text(f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA {schema} FROM PUBLIC"))
    conn.execute(
        text(
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {schema} TO {app}"
        )
    )
    conn.execute(
        text(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {schema} TO {app}")
    )


def grant_backend_functions(conn, backend_runtime: Role) -> None:
    signatures = conn.execute(
        text("""
            SELECT p.oid::regprocedure::text
            FROM pg_proc AS p
            JOIN pg_namespace AS n ON n.oid = p.pronamespace
            WHERE n.nspname = 'public' AND p.proname = ANY(:names)
            """),
        {"names": sorted(BACKEND_RUNTIME_FUNCTIONS)},
    ).scalars()
    quoted_role = conn.dialect.identifier_preparer.quote(backend_runtime.name)
    for signature in signatures:
        conn.execute(text(f"GRANT EXECUTE ON FUNCTION {signature} TO {quoted_role}"))


def secure_authentication_boundary(conn, backend_runtime: Role) -> None:
    worker_maintenance_security.finalize(conn, configured_roles()[0].name, backend_runtime.name)
    quote = conn.dialect.identifier_preparer.quote
    definer = quote(AUTH_DEFINER_ROLE)
    runtime = quote(backend_runtime.name)
    migrator = quote(configured_roles()[0].name)
    issuer = None
    if os.getenv("PLATFORM_AUTH_PASSWORD") or os.getenv("PLATFORM_AUTH_DATABASE_URL"):
        role = role_from_url("PLATFORM_AUTH_DATABASE_URL", "PLATFORM_AUTH", "authclaw_platform_auth", "", "authn")
        if role.name in {r.name for r in configured_roles()} | {AUTH_DEFINER_ROLE, AGENT_AUTH_DEFINER_ROLE}:
            raise ValueError("Platform issuer must be a separate database role")
        ensure_login_role(conn, role)
        issuer = quote(role.name)
        conn.execute(text(f"GRANT CONNECT ON DATABASE {quote(conn.engine.url.database)} TO {issuer}"))
        conn.execute(text(f"GRANT USAGE ON SCHEMA authn TO {issuer}"))
        conn.execute(text(f"REVOKE {issuer} FROM {runtime}"))
        conn.execute(text(f"REVOKE {definer}, {runtime}, {migrator} FROM {issuer}"))
        conn.execute(text(f"REVOKE ALL ON ALL TABLES IN SCHEMA authn, public FROM {issuer}"))

    for role in (runtime, migrator):
        conn.execute(text(f"REVOKE {definer} FROM {role}"))
    conn.execute(text(f"GRANT USAGE ON SCHEMA public, authn TO {definer}"))
    conn.execute(
        text(
            f"GRANT EXECUTE ON FUNCTION public.gen_random_uuid(), "
            f"public.hmac(bytea, bytea, text), "
            f"public.digest(bytea, text) TO {definer}"
        )
    )
    conn.execute(
        text(
            f"GRANT SELECT ON public.tenants, public.users, public.api_keys, "
            f"public.tenant_oidc_configs, public.onboarding_email_otps, "+
            f"public.trust_center_shares, public.audit_log_metadata "
            f"TO {definer}"
        )
    )
    conn.execute(text(f"GRANT INSERT ON public.tenants TO {definer}"))
    conn.execute(
        text(
            f"GRANT SELECT ON authn.platform_admins, authn.platform_sessions, "
            f"authn.context_secret TO {definer}; "
            f"GRANT INSERT, UPDATE ON authn.platform_sessions TO {definer}; "
            f"GRANT UPDATE ON authn.platform_admins TO {definer}"
        )
    )
    conn.execute(
        text(
            f"GRANT INSERT, UPDATE ON public.onboarding_email_otps TO {definer}; "
            f"GRANT INSERT ON public.tenants TO {definer}; "
            f"GRANT UPDATE ON public.users "
            f"TO {definer}"
        )
    )
    conn.execute(text(f"GRANT USAGE ON SCHEMA authn TO {runtime}"))

    tables = conn.execute(
        text(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'authn' "
            "AND tablename IN ('context_secret', 'sessions', 'platform_admins', 'platform_sessions')"
        )
    ).scalars()
    for table_name in tables:
        conn.execute(
            text(f"ALTER TABLE authn.{quote(table_name)} OWNER TO {definer}")
        )

    signatures = conn.execute(
        text(
            "SELECT p.oid::regprocedure::text, p.proname "
            "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = 'authn'"
        )
    ).all()
    for signature, function_name in signatures:
        conn.execute(text(f"ALTER FUNCTION {signature} OWNER TO {definer}"))
        conn.execute(text(f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC"))
        conn.execute(text(f"REVOKE ALL ON FUNCTION {signature} FROM {runtime}"))
        if issuer:
            conn.execute(text(f"REVOKE ALL ON FUNCTION {signature} FROM {issuer}"))
            if function_name == "create_platform_session":
                conn.execute(text(f"GRANT EXECUTE ON FUNCTION {signature} TO {issuer}"))
        if function_name in AUTHN_RUNTIME_FUNCTIONS:
            conn.execute(text(f"GRANT EXECUTE ON FUNCTION {signature} TO {runtime}"))

    definer_functions = (
        "resolve_api_key(text)",
        "resolve_trust_center_share(text)",
        "access_request_onboarding_started(text,timestamptz)",
        "verify_audit_origin(uuid,uuid,text,text,text)",
    )
    for function_signature in definer_functions:
        secured_function = conn.execute(
            text(
                "SELECT to_regprocedure("
                f"'public.{function_signature}')::text"
            )
        ).scalar_one_or_none()
        if secured_function:
            conn.execute(text(f"ALTER FUNCTION {secured_function} OWNER TO {definer}"))
            conn.execute(
                text(f"REVOKE ALL ON FUNCTION {secured_function} FROM PUBLIC")
            )
            verifier = function_signature.startswith("verify_audit_origin")
            grantee = quote(AUDIT_VERIFIER_ROLE) if verifier else runtime
            if verifier:
                conn.execute(
                    text(f"REVOKE ALL ON FUNCTION {secured_function} FROM {runtime}")
                )
            conn.execute(
                text(f"GRANT EXECUTE ON FUNCTION {secured_function} TO {grantee}")
            )

    conn.execute(text("REVOKE ALL ON ALL TABLES IN SCHEMA authn FROM PUBLIC"))
    conn.execute(text(f"REVOKE ALL ON ALL TABLES IN SCHEMA authn FROM {runtime}"))


def secure_agent_authentication_boundary(
    conn, agent_migrator: Role, agent_runtime: Role
) -> None:
    quote = conn.dialect.identifier_preparer.quote
    definer = quote(AGENT_AUTH_DEFINER_ROLE)
    runtime = quote(agent_runtime.name)
    migrator = quote(agent_migrator.name)
    for role in (runtime, migrator):
        conn.execute(text(f"REVOKE {definer} FROM {role}"))
    conn.execute(text(f"GRANT USAGE ON SCHEMA agent, public TO {definer}"))
    conn.execute(
        text(f"GRANT EXECUTE ON FUNCTION public.hmac(bytea, bytea, text) TO {definer}")
    )
    conn.execute(
        text(
            "GRANT SELECT ON agent.tenant_api_keys, agent.tenants, "
            "agent.oidc_login_states, agent.oidc_jwks_cache "
            f"TO {definer}"
        )
    )
    conn.execute(
        text(
            "GRANT INSERT, UPDATE ON agent.tenants TO " + definer
        )
    )
    conn.execute(
        text("GRANT UPDATE ON agent.tenant_api_keys TO " + definer)
    )
    conn.execute(
        text("GRANT USAGE, SELECT ON SEQUENCE agent.tenants_id_seq TO " + definer)
    )
    context_secret = conn.execute(
        text("SELECT to_regclass('agent.auth_context_secret')::text")
    ).scalar_one_or_none()
    if context_secret:
        conn.execute(text(f"ALTER TABLE {context_secret} OWNER TO {definer}"))
        conn.execute(text(f"REVOKE ALL ON {context_secret} FROM {runtime}"))
    function_names = {
        "set_agent_context",
        "bind_agent_context",
        "agent_current_tenant_id",
        "resolve_tenant_api_key",
        "resolve_api_key_principal",
        "resolve_tenant_domain",
        "upsert_control_plane_tenant",
        "load_oidc_login_state",
        "load_oidc_jwks",
    }
    signatures = conn.execute(
        text(
            "SELECT p.oid::regprocedure::text, p.proname FROM pg_proc p "
            "JOIN pg_namespace n ON n.oid=p.pronamespace "
            "WHERE n.nspname='agent' AND p.proname=ANY(:names)"
        ),
        {"names": sorted(function_names)},
    ).all()
    for signature, function_name in signatures:
        conn.execute(text(f"ALTER FUNCTION {signature} OWNER TO {definer}"))
        conn.execute(text(f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC"))
        if function_name != "set_agent_context":
            conn.execute(text(f"GRANT EXECUTE ON FUNCTION {signature} TO {runtime}"))
    conn.execute(
        text(f"REVOKE ALL ON agent.onboarding_registrations FROM {runtime}")
    )


def finalize(conn, roles: tuple[Role, Role, Role, Role]) -> None:
    quote = conn.dialect.identifier_preparer.quote
    backend_migrator, backend_runtime, agent_migrator, agent_runtime = roles
    grant_runtime_objects(conn, backend_migrator, backend_runtime)
    grant_runtime_objects(conn, agent_migrator, agent_runtime)
    secure_owned_functions(
        conn, backend_migrator.name, "public", (backend_runtime.name,)
    )
    secure_owned_functions(conn, agent_migrator.name, "agent", ())
    grant_backend_functions(conn, backend_runtime)
    secure_authentication_boundary(conn, backend_runtime)
    secure_agent_authentication_boundary(conn, agent_migrator, agent_runtime)

    for role in (backend_runtime, agent_runtime):
        other_schema = "agent" if role.schema == "public" else "public"
        conn.execute(
            text(f"REVOKE ALL ON SCHEMA {quote(other_schema)} FROM {quote(role.name)}")
        )
        conn.execute(
            text(
                f"REVOKE ALL ON ALL TABLES IN SCHEMA {quote(other_schema)} FROM {quote(role.name)}"
            )
        )
        conn.execute(
            text(
                f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA {quote(other_schema)} FROM {quote(role.name)}"
            )
        )
        conn.execute(
            text(
                f"REVOKE ALL ON ALL FUNCTIONS IN SCHEMA {quote(other_schema)} FROM {quote(role.name)}"
            )
        )


def finalize_backend(conn, roles: tuple[Role, Role, Role, Role]) -> None:
    """Finalize only the backend boundary for isolated backend deployments and CI."""
    backend_migrator, backend_runtime, _, _ = roles
    grant_runtime_objects(conn, backend_migrator, backend_runtime)
    secure_owned_functions(
        conn, backend_migrator.name, "public", (backend_runtime.name,)
    )
    grant_backend_functions(conn, backend_runtime)
    secure_authentication_boundary(conn, backend_runtime)

    quote = conn.dialect.identifier_preparer.quote
    conn.execute(text(f"REVOKE ALL ON SCHEMA agent FROM {quote(backend_runtime.name)}"))
    conn.execute(
        text(
            "REVOKE ALL ON ALL TABLES IN SCHEMA agent FROM "
            f"{quote(backend_runtime.name)}"
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "phase", choices=("prepare", "finalize", "finalize-backend")
    )
    args = parser.parse_args()
    database_url = normalize_database_url(
        os.getenv("BOOTSTRAP_DATABASE_URL")
        or os.getenv(
            "DATABASE_URL",
            "postgresql+psycopg://authclaw:authclaw@localhost:5432/authclaw",
        )
    )
    database_name = require_identifier(
        os.getenv("POSTGRES_DB", "authclaw"), "POSTGRES_DB"
    )
    roles = configured_roles()
    engine = create_engine(database_url, pool_pre_ping=True)
    with engine.begin() as conn:
        acquire_initialization_lock(conn)
        if args.phase == "prepare":
            prepare(conn, database_name, roles)
        elif args.phase == "finalize-backend":
            finalize_backend(conn, roles)
        else:
            finalize(conn, roles)
    print(f"Database security {args.phase} complete.")


if __name__ == "__main__":
    main()

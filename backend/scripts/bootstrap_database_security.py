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

IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
BACKEND_RUNTIME_FUNCTIONS = {
    "access_request_onboarding_started",
    "append_audit_event_v2",
    "resolve_api_key",
    "resolve_trust_center_share",
}


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


def prepare(conn, database_name: str, roles: tuple[Role, Role, Role, Role]) -> None:
    quote = conn.dialect.identifier_preparer.quote
    database = quote(database_name)
    backend_migrator, backend_runtime, agent_migrator, agent_runtime = roles

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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("prepare", "finalize"))
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
        if args.phase == "prepare":
            prepare(conn, database_name, roles)
        else:
            finalize(conn, roles)
    print(f"Database security {args.phase} complete.")


if __name__ == "__main__":
    main()

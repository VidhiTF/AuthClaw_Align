"""Verify shared-Postgres runtime identities and isolation boundaries."""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterable

from bootstrap_database_security import normalize_database_url
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

RLS_EXCEPTIONS = {
    (
        "agent",
        "onboarding_registrations",
    ): "Pre-tenant authentication workflow; tenant_id is nullable until activation.",
}


def required_url(variable: str) -> str:
    value = os.getenv(variable, "").strip()
    if not value:
        raise RuntimeError(f"{variable} is required")
    return normalize_database_url(value)


def expect_denied(conn, statement: str, parameters: dict | None = None) -> None:
    try:
        conn.execute(text(statement), parameters or {})
    except DBAPIError:
        conn.rollback()
        return
    conn.rollback()
    raise AssertionError(f"Expected database statement to be denied: {statement}")


def verify_runtime(
    database_url: str,
    expected_role: str,
    migrator_role: str,
    own_schema: str,
    other_schema: str,
) -> None:
    engine = create_engine(database_url, pool_pre_ping=True)
    with engine.connect() as conn:
        session_user, current_user = conn.execute(
            text("SELECT session_user, current_user")
        ).one()
        assert session_user == expected_role, (session_user, expected_role)
        assert current_user == expected_role, (current_user, expected_role)

        flags = conn.execute(
            text("""
                SELECT rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolbypassrls
                FROM pg_roles WHERE rolname = :role
                """),
            {"role": expected_role},
        ).one()
        assert flags == (False, False, False, False, False), flags

        memberships = (
            conn.execute(
                text("""
                SELECT parent.rolname
                FROM pg_auth_members AS membership
                JOIN pg_roles AS member ON member.oid = membership.member
                JOIN pg_roles AS parent ON parent.oid = membership.roleid
                WHERE member.rolname = :role
                """),
                {"role": expected_role},
            )
            .scalars()
            .all()
        )
        assert memberships == [], memberships

        can_use_own, can_create_own, can_use_other = conn.execute(
            text("""
                SELECT
                    has_schema_privilege(:role, :own_schema, 'USAGE'),
                    has_schema_privilege(:role, :own_schema, 'CREATE'),
                    has_schema_privilege(:role, :other_schema, 'USAGE')
                """),
            {
                "role": expected_role,
                "own_schema": own_schema,
                "other_schema": other_schema,
            },
        ).one()
        assert can_use_own is True
        assert can_create_own is False
        assert can_use_other is False

        conn.execute(text(f"SELECT 1 FROM {own_schema}.tenants LIMIT 1"))
        conn.rollback()
        expect_denied(conn, f"SELECT 1 FROM {other_schema}.tenants LIMIT 1")
        expect_denied(
            conn, f"CREATE TABLE {own_schema}.__authclaw_security_probe(id integer)"
        )
        expect_denied(conn, "CREATE ROLE authclaw_security_probe")
        expect_denied(conn, f"SET ROLE {migrator_role}")
        expect_denied(conn, "SET ROLE authclaw")


def verify_rls(bootstrap_url: str, schemas: Iterable[str]) -> None:
    engine = create_engine(bootstrap_url, pool_pre_ping=True)
    with engine.connect() as conn:
        rows = conn.execute(
            text("""
                SELECT namespace.nspname, table_class.relname,
                       table_class.relrowsecurity, table_class.relforcerowsecurity
                FROM pg_class AS table_class
                JOIN pg_namespace AS namespace ON namespace.oid = table_class.relnamespace
                WHERE namespace.nspname = ANY(:schemas)
                  AND table_class.relkind = 'r'
                  AND EXISTS (
                      SELECT 1 FROM pg_attribute AS attribute
                      WHERE attribute.attrelid = table_class.oid
                        AND attribute.attname = 'tenant_id'
                        AND NOT attribute.attisdropped
                  )
                ORDER BY namespace.nspname, table_class.relname
                """),
            {"schemas": list(schemas)},
        ).all()

    seen_exceptions: set[tuple[str, str]] = set()
    for schema, table_name, enabled, forced in rows:
        key = (schema, table_name)
        if key in RLS_EXCEPTIONS:
            seen_exceptions.add(key)
            continue
        assert enabled and forced, f"{schema}.{table_name} must ENABLE and FORCE RLS"
    assert seen_exceptions == set(
        RLS_EXCEPTIONS
    ), "Configured RLS exception was not found in the schema"


def verify_cross_tenant(bootstrap_url: str, backend_url: str, agent_url: str) -> None:
    marker = uuid.uuid4().hex
    backend_tenant_a = uuid.uuid4()
    backend_tenant_b = uuid.uuid4()
    backend_denied_id = uuid.uuid4()
    bootstrap_engine = create_engine(bootstrap_url, pool_pre_ping=True)

    with bootstrap_engine.begin() as conn:
        for tenant_id, suffix in ((backend_tenant_a, "a"), (backend_tenant_b, "b")):
            conn.execute(
                text(
                    "INSERT INTO public.tenants (id, name, tier, status) VALUES (:id, :name, 'starter', 'active')"
                ),
                {"id": tenant_id, "name": f"security-{marker}-{suffix}"},
            )
        agent_tenant_a = conn.execute(
            text(
                "INSERT INTO agent.tenants (name, status) VALUES (:name, 'active') RETURNING id"
            ),
            {"name": f"security-{marker}-a"},
        ).scalar_one()
        agent_tenant_b = conn.execute(
            text(
                "INSERT INTO agent.tenants (name, status) VALUES (:name, 'active') RETURNING id"
            ),
            {"name": f"security-{marker}-b"},
        ).scalar_one()
        for tenant_id, suffix in ((agent_tenant_a, "a"), (agent_tenant_b, "b")):
            conn.execute(
                text(
                    "INSERT INTO agent.policies (name, type, rules, tenant_id) "
                    "VALUES (:name, 'security-test', '{}', :tenant_id)"
                ),
                {"name": f"security-{marker}-{suffix}", "tenant_id": tenant_id},
            )

    try:
        backend_engine = create_engine(backend_url, pool_pre_ping=True)
        with backend_engine.connect() as conn:
            conn.execute(
                text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
                {"tenant_id": str(backend_tenant_a)},
            )
            own, other = conn.execute(
                text(
                    "SELECT "
                    "(SELECT count(*) FROM public.tenants WHERE id = :own), "
                    "(SELECT count(*) FROM public.tenants WHERE id = :other)"
                ),
                {"own": backend_tenant_a, "other": backend_tenant_b},
            ).one()
            assert (own, other) == (1, 0), (own, other)
            expect_denied(
                conn,
                "INSERT INTO public.tenants (id, name, tier, status) "
                "VALUES (:id, :name, 'starter', 'active')",
                {"id": backend_denied_id, "name": f"security-{marker}-denied"},
            )

        agent_engine = create_engine(agent_url, pool_pre_ping=True)
        with agent_engine.connect() as conn:
            conn.execute(
                text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
                {"tenant_id": str(agent_tenant_a)},
            )
            own, other = conn.execute(
                text(
                    "SELECT "
                    "(SELECT count(*) FROM agent.policies WHERE tenant_id = :own), "
                    "(SELECT count(*) FROM agent.policies WHERE tenant_id = :other)"
                ),
                {"own": agent_tenant_a, "other": agent_tenant_b},
            ).one()
            assert (own, other) == (1, 0), (own, other)
            expect_denied(
                conn,
                "INSERT INTO agent.policies (name, type, rules, tenant_id) "
                "VALUES (:name, 'security-test', '{}', :tenant_id)",
                {"name": f"security-{marker}-denied", "tenant_id": agent_tenant_b},
            )
    finally:
        with bootstrap_engine.begin() as conn:
            conn.execute(
                text(
                    "DELETE FROM public.tenants WHERE id IN (:tenant_a, :tenant_b, :denied_id)"
                ),
                {
                    "tenant_a": backend_tenant_a,
                    "tenant_b": backend_tenant_b,
                    "denied_id": backend_denied_id,
                },
            )
            conn.execute(
                text("DELETE FROM agent.tenants WHERE id IN (:tenant_a, :tenant_b)"),
                {"tenant_a": agent_tenant_a, "tenant_b": agent_tenant_b},
            )


def main() -> None:
    backend_role = os.getenv("POSTGRES_APP_USER", "authclaw_app")
    backend_migrator = os.getenv("BACKEND_MIGRATOR_USER", "authclaw_migrator")
    agent_role = os.getenv("AGENT_RUNTIME_USER", "authclaw_agent_runtime")
    agent_migrator = os.getenv("AGENT_MIGRATOR_USER", "authclaw_agent_migrator")
    bootstrap_url = required_url("BOOTSTRAP_DATABASE_URL")
    backend_url = required_url("BACKEND_DATABASE_URL")
    agent_url = required_url("AGENT_DATABASE_URL")
    verify_runtime(backend_url, backend_role, backend_migrator, "public", "agent")
    verify_runtime(agent_url, agent_role, agent_migrator, "agent", "public")
    verify_rls(bootstrap_url, ("public", "agent"))
    verify_cross_tenant(bootstrap_url, backend_url, agent_url)
    print("Database identity, privilege, cross-schema, and RLS verification passed.")


if __name__ == "__main__":
    main()

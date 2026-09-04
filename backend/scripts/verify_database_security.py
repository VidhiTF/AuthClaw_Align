"""Verify shared-Postgres runtime identities and isolation boundaries."""

from __future__ import annotations

import hashlib
import hmac
import os
import uuid
from collections.abc import Iterable

from bootstrap_database_security import normalize_database_url
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

RLS_EXCEPTIONS: dict[tuple[str, str], str] = {}


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


def expect_denied_in_transaction(conn, statement: str, parameters: dict | None = None) -> None:
    savepoint = conn.begin_nested()
    try:
        conn.execute(text(statement), parameters or {})
    except DBAPIError:
        savepoint.rollback()
        return
    savepoint.rollback()
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
    backend_tenant_a, backend_tenant_b = uuid.uuid4(), uuid.uuid4()
    backend_user_a, backend_user_b = uuid.uuid4(), uuid.uuid4()
    backend_hash_a, backend_hash_b = "a" * 64, "b" * 64
    reset_otp = "123456"
    reset_secret = f"security-reset-{marker}"
    reset_email = f"security-{marker}-a@example.invalid"
    reset_otp_hash = hashlib.sha256(
        f"{reset_email}:{reset_otp}:{reset_secret}".encode("utf-8")
    ).hexdigest()
    trust_token_hash_a = hashlib.sha256(f"trust-a-{marker}".encode()).hexdigest()
    trust_token_hash_b = hashlib.sha256(f"trust-b-{marker}".encode()).hexdigest()
    trust_share_a, trust_share_b = uuid.uuid4(), uuid.uuid4()
    bootstrap_engine = create_engine(bootstrap_url, pool_pre_ping=True)

    with bootstrap_engine.begin() as conn:
        for tenant_id, suffix in ((backend_tenant_a, "a"), (backend_tenant_b, "b")):
            conn.execute(
                text("INSERT INTO public.tenants (id, name, tier, status) VALUES (:id, :name, 'starter', 'active')"),
                {"id": tenant_id, "name": f"security-{marker}-{suffix}"},
            )
        for user_id, tenant_id, suffix in (
            (backend_user_a, backend_tenant_a, "a"),
            (backend_user_b, backend_tenant_b, "b"),
        ):
            conn.execute(
                text(
                    "INSERT INTO public.users "
                    "(id, tenant_id, email, password_hash, role, platform_role, is_active, created_at, updated_at) "
                    "VALUES (:id, :tenant, :email, 'security-test', 'viewer', 'NONE', true, now(), now())"
                ),
                {"id": user_id, "tenant": tenant_id, "email": f"security-{marker}-{suffix}@example.invalid"},
            )
        for token_hash, tenant_id, user_id in (
            (backend_hash_a, backend_tenant_a, backend_user_a),
            (backend_hash_b, backend_tenant_b, backend_user_b),
        ):
            conn.execute(
                text("SELECT authn.create_session(:hash, :tenant, :user, 'security-test', now() + interval '10 minutes', '{}'::jsonb)"),
                {"hash": token_hash, "tenant": tenant_id, "user": user_id},
            )
        reset_id = conn.execute(
            text(
                "SELECT authn.create_password_reset("
                ":email, :tenant, :tenant_name, :otp_hash, now() + interval '10 minutes'"
                ")"
            ),
            {
                "email": reset_email,
                "tenant": backend_tenant_a,
                "tenant_name": f"security-{marker}-a",
                "otp_hash": reset_otp_hash,
            },
        ).scalar_one()
        for share_id, tenant_id, token_hash, suffix in (
            (trust_share_a, backend_tenant_a, trust_token_hash_a, "a"),
            (trust_share_b, backend_tenant_b, trust_token_hash_b, "b"),
        ):
            conn.execute(
                text(
                    "INSERT INTO public.trust_center_shares "
                    "(id, tenant_id, label, token_hash, token_prefix, frameworks, "
                    "permissions, status, expires_at, metadata_json) "
                    "VALUES (:id, :tenant, :label, :hash, :prefix, ARRAY['SOC2'], "
                    "ARRAY['summary'], 'active', now() + interval '10 minutes', '{}'::jsonb)"
                ),
                {
                    "id": share_id,
                    "tenant": tenant_id,
                    "label": f"security-{marker}-{suffix}",
                    "hash": token_hash,
                    "prefix": f"security-{suffix}",
                },
            )

        agent_tenant_a = conn.execute(
            text("INSERT INTO agent.tenants (name, status) VALUES (:name, 'active') RETURNING id"),
            {"name": f"security-{marker}-a"},
        ).scalar_one()
        agent_tenant_b = conn.execute(
            text("INSERT INTO agent.tenants (name, status) VALUES (:name, 'active') RETURNING id"),
            {"name": f"security-{marker}-b"},
        ).scalar_one()
        for tenant_id, suffix in ((agent_tenant_a, "a"), (agent_tenant_b, "b")):
            conn.execute(
                text("INSERT INTO agent.policies (name, type, rules, tenant_id) VALUES (:name, 'security-test', '{}', :tenant_id)"),
                {"name": f"security-{marker}-{suffix}", "tenant_id": tenant_id},
            )

    try:
        backend_engine = create_engine(backend_url, pool_pre_ping=True)
        with backend_engine.connect() as conn:
            assert conn.execute(text("SELECT count(*) FROM public.users")).scalar_one() == 0
            conn.execute(text("SELECT set_config('app.current_tenant_id', :tenant, true)"), {"tenant": str(backend_tenant_b)})
            assert conn.execute(text("SELECT count(*) FROM public.users")).scalar_one() == 0
            conn.execute(text("SELECT tenant_id FROM authn.bind_session_context(:hash)"), {"hash": backend_hash_a}).one()
            own, other = conn.execute(
                text("SELECT (SELECT count(*) FROM public.users WHERE tenant_id=:own), (SELECT count(*) FROM public.users WHERE tenant_id=:other)"),
                {"own": backend_tenant_a, "other": backend_tenant_b},
            ).one()
            assert (own, other) == (1, 0), (own, other)
            expect_denied_in_transaction(
                conn,
                "INSERT INTO public.users (id, tenant_id, email, password_hash, role, platform_role, is_active) VALUES (:id, :tenant, :email, 'x', 'viewer', 'NONE', true)",
                {"id": uuid.uuid4(), "tenant": backend_tenant_b, "email": f"blocked-{marker}@example.invalid"},
            )
            assert conn.execute(
                text("UPDATE public.users SET role='admin' WHERE id=:id"), {"id": backend_user_b}
            ).rowcount == 0
            assert conn.execute(
                text("DELETE FROM public.users WHERE id=:id"), {"id": backend_user_b}
            ).rowcount == 0
            expect_denied(conn, "SELECT authn.set_context(:tenant, :user, :user)", {"tenant": backend_tenant_b, "user": backend_user_b})
            assert not conn.execute(text(
                "SELECT has_function_privilege(current_user, "
                "'authn.create_platform_session(text,uuid,text,timestamptz,jsonb)', 'EXECUTE')"
            )).scalar_one(), "Runtime must not issue platform sessions"
            expect_denied(
                conn,
                "SELECT authn.set_platform_context(:admin, :credential)",
                {"admin": uuid.uuid4(), "credential": uuid.uuid4()},
            )

        with backend_engine.begin() as conn:
            assert conn.execute(
                text("SELECT tenant_id FROM authn.bind_session_context(:hash)"),
                {"hash": backend_hash_a},
            ).scalar_one() == backend_tenant_a
            outcome = conn.execute(
                text(
                    "SELECT authn.confirm_password_reset("
                    ":reset_id, :otp, :secrets, :password_hash, 5"
                    ")"
                ),
                {
                    "reset_id": reset_id,
                    "otp": reset_otp,
                    "secrets": [reset_secret],
                    "password_hash": "security-reset-password-hash",
                },
            ).scalar_one()
            assert outcome == "verified", outcome
            assert conn.execute(
                text("SELECT tenant_id FROM authn.bind_session_context(:hash)"),
                {"hash": backend_hash_a},
            ).first() is None
            assert conn.execute(
                text("SELECT tenant_id FROM authn.bind_session_context(:hash)"),
                {"hash": backend_hash_b},
            ).scalar_one() == backend_tenant_b

        with bootstrap_engine.connect() as conn:
            password_hash = conn.execute(
                text("SELECT password_hash FROM public.users WHERE id=:id"),
                {"id": backend_user_a},
            ).scalar_one()
            assert password_hash == "security-reset-password-hash"

        with backend_engine.connect() as conn:
            resolved = conn.execute(
                text(
                    "SELECT id, tenant_id FROM public.resolve_trust_center_share(:hash)"
                ),
                {"hash": trust_token_hash_a},
            ).one()
            assert resolved == (trust_share_a, backend_tenant_a), resolved
            own, other = conn.execute(
                text(
                    "SELECT "
                    "(SELECT count(*) FROM public.trust_center_shares WHERE id=:own), "
                    "(SELECT count(*) FROM public.trust_center_shares WHERE id=:other)"
                ),
                {"own": trust_share_a, "other": trust_share_b},
            ).one()
            assert (own, other) == (1, 0), (own, other)
            conn.rollback()
            assert conn.execute(
                text(
                    "SELECT id FROM public.resolve_trust_center_share(:hash)"
                ),
                {"hash": hashlib.sha256(b"unknown-trust-token").hexdigest()},
            ).first() is None

        agent_engine = create_engine(agent_url, pool_pre_ping=True)
        request_id = f"security-{marker}"
        secret = os.getenv("AGENT_RLS_CONTEXT_SECRET", "").strip()
        environment = os.getenv("AUTHCLAW_ENV", "development").lower()
        if not secret:
            if environment in {"production", "prod"}:
                raise RuntimeError("AGENT_RLS_CONTEXT_SECRET is required for verification")
            secret = "authclaw-local-agent-rls-context-secret"
        signing_key = hashlib.sha256(secret.encode()).digest()
        proof = hmac.new(signing_key, f"{agent_tenant_a}|{request_id}".encode(), hashlib.sha256).hexdigest()
        with agent_engine.connect() as conn:
            assert conn.execute(text("SELECT count(*) FROM agent.policies")).scalar_one() == 0
            conn.execute(text("SELECT set_config('app.tenant_id', :tenant, true)"), {"tenant": str(agent_tenant_b)})
            assert conn.execute(text("SELECT count(*) FROM agent.policies")).scalar_one() == 0
            conn.execute(
                text("SELECT agent.bind_agent_context(:tenant, :request, :proof)"),
                {"tenant": str(agent_tenant_a), "request": request_id, "proof": proof},
            )
            own, other = conn.execute(
                text("SELECT (SELECT count(*) FROM agent.policies WHERE tenant_id=:own), (SELECT count(*) FROM agent.policies WHERE tenant_id=:other)"),
                {"own": agent_tenant_a, "other": agent_tenant_b},
            ).one()
            assert (own, other) == (1, 0), (own, other)
            expect_denied_in_transaction(
                conn,
                "INSERT INTO agent.policies (name, type, rules, tenant_id) VALUES (:name, 'security-test', '{}', :tenant)",
                {"name": f"blocked-{marker}", "tenant": agent_tenant_b},
            )
            assert conn.execute(
                text("UPDATE agent.policies SET name='blocked' WHERE tenant_id=:tenant"),
                {"tenant": agent_tenant_b},
            ).rowcount == 0
            assert conn.execute(
                text("DELETE FROM agent.policies WHERE tenant_id=:tenant"),
                {"tenant": agent_tenant_b},
            ).rowcount == 0
            expect_denied(conn, "SELECT agent.bind_agent_context(:tenant, 'forged', repeat('0', 64))", {"tenant": str(agent_tenant_b)})
            expect_denied(conn, "SELECT agent.set_agent_context(:tenant)", {"tenant": str(agent_tenant_b)})
    finally:
        with bootstrap_engine.begin() as conn:
            conn.execute(text("DELETE FROM authn.sessions WHERE token_hash IN (:a, :b)"), {"a": backend_hash_a, "b": backend_hash_b})
            conn.execute(
                text("DELETE FROM public.onboarding_email_otps WHERE id=:id"),
                {"id": reset_id},
            )
            conn.execute(
                text("DELETE FROM public.trust_center_shares WHERE id IN (:a, :b)"),
                {"a": trust_share_a, "b": trust_share_b},
            )
            conn.execute(text("DELETE FROM public.users WHERE id IN (:a, :b)"), {"a": backend_user_a, "b": backend_user_b})
            conn.execute(text("DELETE FROM public.tenants WHERE id IN (:a, :b)"), {"a": backend_tenant_a, "b": backend_tenant_b})
            conn.execute(text("DELETE FROM agent.policies WHERE tenant_id IN (:a, :b)"), {"a": agent_tenant_a, "b": agent_tenant_b})
            conn.execute(text("DELETE FROM agent.tenants WHERE id IN (:a, :b)"), {"a": agent_tenant_a, "b": agent_tenant_b})

def verify_agent_totp_encryption(bootstrap_url: str) -> None:
    engine = create_engine(bootstrap_url, pool_pre_ping=True)
    with engine.connect() as conn:
        plaintext_count = conn.execute(text("""
            SELECT count(*) FROM (
                SELECT totp_secret FROM agent.tenants
                UNION ALL SELECT totp_secret FROM agent.tenant_users
                UNION ALL SELECT totp_secret FROM agent.onboarding_registrations
            ) secrets
            WHERE totp_secret IS NOT NULL
              AND totp_secret NOT LIKE 'v2:aes256gcm:%'
              AND totp_secret NOT LIKE 'v3:envelope:%'
        """)).scalar_one()
    assert plaintext_count == 0, f"{plaintext_count} agent TOTP secrets remain plaintext"

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
    verify_agent_totp_encryption(bootstrap_url)
    verify_cross_tenant(bootstrap_url, backend_url, agent_url)
    print("Database identity, privilege, cross-schema, and RLS verification passed.")


if __name__ == "__main__":
    main()

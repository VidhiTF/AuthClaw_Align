import hashlib
import hmac
import os

from services.tenant_context import (
    get_current_request_id,
    get_current_tenant_id,
    is_tenant_context_required,
)
from sqlalchemy import create_engine, event, text

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:vidhi@localhost:5432/authclaw")
MIGRATION_DATABASE_URL = os.getenv("MIGRATION_DATABASE_URL", DATABASE_URL)
EXPECTED_RUNTIME_DATABASE_ROLE = os.getenv("AUTHCLAW_RUNTIME_DB_ROLE", "").strip()
DATABASE_SCHEMA = os.getenv("AUTHCLAW_DATABASE_SCHEMA", "agent").strip()


def _validate_identifier(value: str, variable: str) -> str:
    if not value or not value.replace("_", "").isalnum() or value[0].isdigit():
        raise RuntimeError(f"{variable} must be a simple PostgreSQL identifier.")
    return value


_validate_identifier(DATABASE_SCHEMA, "AUTHCLAW_DATABASE_SCHEMA")


def _connect_args() -> dict[str, str]:
    # Excluding public prevents an unqualified agent query from falling through
    # to an incompatible backend table in the consolidated database.
    return {"options": f"-csearch_path={DATABASE_SCHEMA},pg_catalog"}


engine = create_engine(DATABASE_URL, connect_args=_connect_args())
migration_engine = create_engine(MIGRATION_DATABASE_URL, connect_args=_connect_args())


def _is_postgres() -> bool:
    return engine.dialect.name == "postgresql"


def validate_database_security() -> None:
    """Refuse startup when agent RLS/authentication invariants are incomplete."""
    if not _is_postgres():
        return
    with engine.connect() as conn:
        secure = conn.execute(text("""
            SELECT
                EXISTS (
                    SELECT 1
                    FROM pg_proc p
                    JOIN pg_namespace n ON n.oid = p.pronamespace
                    JOIN pg_roles r ON r.oid = p.proowner
                    WHERE n.nspname = 'agent'
                      AND p.proname IN ('bind_agent_context', 'agent_current_tenant_id')
                      AND p.prosecdef
                      AND r.rolname = 'authclaw_agent_auth_definer'
                      AND NOT EXISTS (
                          SELECT 1
                          FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl
                          WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
                      )
                    GROUP BY n.nspname
                    HAVING count(*) = 2
                )
                AND NOT EXISTS (
                    SELECT 1 FROM pg_roles
                    WHERE rolname = current_user AND (rolsuper OR rolbypassrls)
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = 'agent' AND c.relkind = 'r'
                      AND EXISTS (
                          SELECT 1 FROM pg_attribute a
                          WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
                      )
                      AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity)
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_policy p
                    JOIN pg_class c ON c.oid = p.polrelid
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = 'agent'
                      AND (
                          COALESCE(pg_get_expr(p.polqual, p.polrelid), '') ILIKE '%auth_lookup%'
                          OR COALESCE(pg_get_expr(p.polqual, p.polrelid), '') ILIKE '%current_setting%'
                      )
                )
        """)).scalar_one()
    if not secure:
        raise RuntimeError("Agent database security validation failed")

def _set_config(cursor, key: str, value: str, *, local: bool = False) -> None:
    cursor.execute("SELECT set_config(%s, %s, %s)", (key, value, local))


@event.listens_for(engine, "checkout")
def _clear_tenant_context_on_checkout(dbapi_connection, connection_record, connection_proxy):
    if not _is_postgres():
        return
    cursor = dbapi_connection.cursor()
    try:
        _set_config(cursor, "app.tenant_id", "")
        _set_config(cursor, "app.current_tenant_id", "")
        _set_config(cursor, "app.agent_auth_context", "")
        _set_config(cursor, "app.request_id", "")
        if EXPECTED_RUNTIME_DATABASE_ROLE:
            _validate_identifier(EXPECTED_RUNTIME_DATABASE_ROLE, "AUTHCLAW_RUNTIME_DB_ROLE")
            cursor.execute("SELECT session_user, current_user")
            session_user, current_user = cursor.fetchone()
            if session_user != EXPECTED_RUNTIME_DATABASE_ROLE or current_user != EXPECTED_RUNTIME_DATABASE_ROLE:
                raise RuntimeError(
                    "Agent database identity mismatch: expected session_user = current_user = "
                    f"{EXPECTED_RUNTIME_DATABASE_ROLE!r}, got {session_user!r} and {current_user!r}."
                )
    finally:
        cursor.close()

@event.listens_for(engine, "before_cursor_execute")
def _apply_tenant_context(conn, cursor, statement, parameters, context, executemany):
    if not _is_postgres():
        return

    normalized = statement.lstrip().upper()
    # Recovery must execute before rebinding context in an aborted transaction.
    if normalized.startswith(("SET ", "RESET ", "SHOW ", "ROLLBACK TO SAVEPOINT ")) or "SET_CONFIG(" in normalized:
        return

    tenant_id = get_current_tenant_id()
    if is_tenant_context_required() and not tenant_id:
        raise RuntimeError("Tenant context is required before executing tenant-scoped database statements.")

    request_id = get_current_request_id() or ""
    if tenant_id is not None:
        context_secret = os.getenv("AGENT_RLS_CONTEXT_SECRET", "").strip()
        environment = os.getenv("AUTHCLAW_ENV", "development").lower()
        if not context_secret:
            if environment in {"production", "prod"}:
                raise RuntimeError("AGENT_RLS_CONTEXT_SECRET is required in production")
            context_secret = "authclaw-local-agent-rls-context-secret"
        signing_key = hashlib.sha256(context_secret.encode("utf-8")).digest()
        proof = hmac.new(
            signing_key,
            f"{tenant_id}|{request_id}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        cursor.execute(
            "SELECT agent.bind_agent_context(%s, %s, %s)",
            (str(tenant_id), request_id, proof),
        )
    _set_config(cursor, "app.request_id", request_id, local=True)

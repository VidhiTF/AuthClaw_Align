import os
from sqlalchemy import create_engine, event, text

from services.tenant_context import (
    get_current_request_id,
    get_current_tenant_id,
    is_auth_lookup_context,
    is_tenant_context_required,
)

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:vidhi@localhost:5432/authclaw")
MIGRATION_DATABASE_URL = os.getenv("MIGRATION_DATABASE_URL", DATABASE_URL)
RUNTIME_DATABASE_ROLE = os.getenv("AUTHCLAW_RUNTIME_DB_ROLE", "").strip()
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


def _quoted_runtime_role() -> str:
    _validate_identifier(RUNTIME_DATABASE_ROLE, "AUTHCLAW_RUNTIME_DB_ROLE")
    return engine.dialect.identifier_preparer.quote(RUNTIME_DATABASE_ROLE)


def _is_postgres() -> bool:
    return engine.dialect.name == "postgresql"


def _set_config(cursor, key: str, value: str, *, local: bool = False) -> None:
    cursor.execute("SELECT set_config(%s, %s, %s)", (key, value, local))


@event.listens_for(engine, "checkout")
def _clear_tenant_context_on_checkout(dbapi_connection, connection_record, connection_proxy):
    if not _is_postgres():
        return
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("RESET ROLE")
        _set_config(cursor, "app.tenant_id", "")
        _set_config(cursor, "app.current_tenant_id", "")
        _set_config(cursor, "app.request_id", "")
        _set_config(cursor, "app.auth_lookup", "")
        if RUNTIME_DATABASE_ROLE:
            cursor.execute(f"SET ROLE {_quoted_runtime_role()}")
    finally:
        cursor.close()


@event.listens_for(engine, "before_cursor_execute")
def _apply_tenant_context(conn, cursor, statement, parameters, context, executemany):
    if not _is_postgres():
        return

    normalized = statement.lstrip().upper()
    if normalized.startswith(("SET ", "RESET ", "SHOW ")) or "SET_CONFIG(" in normalized:
        return

    tenant_id = get_current_tenant_id()
    if is_tenant_context_required() and not tenant_id:
        raise RuntimeError("Tenant context is required before executing tenant-scoped database statements.")

    tenant_value = str(tenant_id) if tenant_id is not None else ""
    # local=True is the parameterized equivalent of SET LOCAL and scopes the
    # tenant boundary to the active transaction.
    _set_config(cursor, "app.current_tenant_id", tenant_value, local=True)
    _set_config(cursor, "app.tenant_id", tenant_value, local=True)
    _set_config(cursor, "app.request_id", get_current_request_id() or "", local=True)
    _set_config(cursor, "app.auth_lookup", "on" if is_auth_lookup_context() else "", local=True)

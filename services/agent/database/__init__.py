import os
from sqlalchemy import create_engine, event, text

from services.tenant_context import (
    get_current_request_id,
    get_current_tenant_id,
    is_auth_lookup_context,
    is_tenant_context_required,
)

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:vidhi@localhost:5432/authclaw")

engine = create_engine(DATABASE_URL)


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
        _set_config(cursor, "app.tenant_id", "")
        _set_config(cursor, "app.current_tenant_id", "")
        _set_config(cursor, "app.request_id", "")
        _set_config(cursor, "app.auth_lookup", "")
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

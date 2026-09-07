"""SQLAlchemy session management"""
from contextlib import contextmanager
from contextvars import ContextVar
import os

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}")
    return value


DB_POOL_SIZE = _bounded_int("BACKEND_DB_POOL_SIZE", 10, 1, 50)
DB_MAX_OVERFLOW = _bounded_int("BACKEND_DB_MAX_OVERFLOW", 5, 0, 50)
DB_POOL_TIMEOUT_SECONDS = _bounded_int("DB_POOL_TIMEOUT_SECONDS", 5, 1, 60)
DB_POOL_RECYCLE_SECONDS = _bounded_int("DB_POOL_RECYCLE_SECONDS", 300, 30, 3600)
DB_CONNECT_TIMEOUT_SECONDS = _bounded_int("DB_CONNECT_TIMEOUT_SECONDS", 5, 1, 30)

engine = create_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_pre_ping=True,
    pool_size=DB_POOL_SIZE,
    max_overflow=DB_MAX_OVERFLOW,
    pool_timeout=DB_POOL_TIMEOUT_SECONDS,
    pool_recycle=DB_POOL_RECYCLE_SECONDS,
    connect_args=(
        {"connect_timeout": DB_CONNECT_TIMEOUT_SECONDS}
        if settings.DATABASE_URL.startswith("postgresql")
        else {}
    ),
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
_database_auth_context: ContextVar[tuple[str, str] | None] = ContextVar(
    "database_auth_context", default=None
)


@contextmanager
def database_auth_context(kind: str, credential_hash: str):
    if kind not in {"api_key", "session", "platform_session"} or not credential_hash:
        raise ValueError("A validated database credential is required")
    token = _database_auth_context.set((kind, credential_hash))
    try:
        yield
    finally:
        _database_auth_context.reset(token)


@event.listens_for(Session, "after_begin")
def bind_authenticated_database_context(_session, _transaction, connection) -> None:
    auth_context = _database_auth_context.get()
    if auth_context is None or connection.dialect.name != "postgresql":
        return
    kind, credential_hash = auth_context
    if kind == "platform_session":
        resolver = "authn.bind_platform_session_context"
    else:
        resolver = (
            "authn.bind_session_context"
            if kind == "session"
            else "authn.bind_api_key_context"
        )
    bound = connection.execute(
        text(f"SELECT tenant_id FROM {resolver}(:credential_hash)"),
        {"credential_hash": credential_hash},
    ).first()
    if not bound:
        raise RuntimeError("Authenticated database context expired")


@event.listens_for(engine, "checkout")
def verify_runtime_database_identity(dbapi_connection, _connection_record, _connection_proxy) -> None:
    expected_role = os.getenv("AUTHCLAW_RUNTIME_DB_ROLE", "").strip()
    if not expected_role or engine.dialect.name != "postgresql":
        return
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("SELECT session_user, current_user")
        session_user, current_user = cursor.fetchone()
        if session_user != expected_role or current_user != expected_role:
            raise RuntimeError(
                "Backend database identity mismatch: expected session_user = current_user = "
                f"{expected_role!r}, got {session_user!r} and {current_user!r}."
            )
    finally:
        cursor.close()

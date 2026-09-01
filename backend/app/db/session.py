"""SQLAlchemy session management"""
import os

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings

engine = create_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


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


@event.listens_for(Session, "after_begin")
def apply_tenant_context(session: Session, _transaction, connection) -> None:
    """Reapply tenant RLS context whenever commit/rollback starts a new transaction."""
    tenant_id = session.info.get("tenant_id")
    if tenant_id:
        connection.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, true)"),
            {"tenant_id": str(tenant_id)},
        )

"""SQLAlchemy session management"""
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


@event.listens_for(Session, "after_begin")
def apply_tenant_context(session: Session, _transaction, connection) -> None:
    """Reapply tenant RLS context whenever commit/rollback starts a new transaction."""
    tenant_id = session.info.get("tenant_id")
    if tenant_id:
        connection.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, true)"),
            {"tenant_id": str(tenant_id)},
        )

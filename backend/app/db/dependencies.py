"""Database dependencies for FastAPI"""
from typing import Generator
from sqlalchemy.orm import Session
from app.db.session import SessionLocal


def get_db() -> Generator[Session, None, None]:
    """Database session dependency for FastAPI"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_score_db() -> Generator[Session, None, None]:
    """Start the scoring view before authentication queries, using one connection."""
    db = SessionLocal()
    try:
        db.connection(execution_options={"isolation_level": "REPEATABLE READ"})
        db.info["compliance_read_transaction"] = True
        yield db
    finally:
        db.close()

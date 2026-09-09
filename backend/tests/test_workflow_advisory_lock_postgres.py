import os
import random
from urllib.parse import urlparse

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.orchestrator.workflow_lock import workflow_advisory_lock


def _test_database_url():
    url = os.getenv("TEST_DATABASE_URL", "")
    database = urlparse(url.replace("postgresql+psycopg://", "postgresql://", 1)).path.strip("/")
    if not url or not database.endswith("_test"):
        pytest.skip("TEST_DATABASE_URL must target an explicit _test database")
    return url


def _unlock(connection, key, count=1):
    for _ in range(count):
        connection.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": key})


def test_orm_commit_returns_lock_owning_session_to_pool():
    engine = create_engine(_test_database_url(), pool_size=2, max_overflow=0)
    session = sessionmaker(bind=engine)()
    key = random.randrange(1, 2**62)
    try:
        owner_pid = session.execute(text("SELECT pg_backend_pid()")).scalar_one()
        assert session.execute(text("SELECT pg_try_advisory_lock(:key)"), {"key": key}).scalar_one() is True
        session.commit()

        with engine.connect() as borrower:
            assert borrower.execute(text("SELECT pg_backend_pid()")).scalar_one() == owner_pid
            assert borrower.execute(text("SELECT pg_try_advisory_lock(:key)"), {"key": key}).scalar_one() is True
            _unlock(borrower, key, count=2)
    finally:
        session.close()
        engine.dispose()


def test_connection_pinned_lock_excludes_competitor_and_releases():
    engine = create_engine(_test_database_url(), pool_size=2, max_overflow=0)
    session = sessionmaker(bind=engine)()
    key = random.randrange(1, 2**62)
    try:
        with workflow_advisory_lock(session, key, "workflow-test"):
            session.execute(text("SELECT 1"))
            session.commit()
            with engine.connect() as competitor:
                assert competitor.execute(
                    text("SELECT pg_try_advisory_lock(:key)"), {"key": key}
                ).scalar_one() is False

        with engine.connect() as competitor:
            assert competitor.execute(
                text("SELECT pg_try_advisory_lock(:key)"), {"key": key}
            ).scalar_one() is True
            _unlock(competitor, key)
    finally:
        session.close()
        engine.dispose()


def test_connection_pinned_lock_releases_after_exception():
    engine = create_engine(_test_database_url(), pool_size=2, max_overflow=0)
    session = sessionmaker(bind=engine)()
    key = random.randrange(1, 2**62)
    try:
        with pytest.raises(RuntimeError, match="injected"):
            with workflow_advisory_lock(session, key, "workflow-test"):
                raise RuntimeError("injected")

        with engine.connect() as competitor:
            assert competitor.execute(
                text("SELECT pg_try_advisory_lock(:key)"), {"key": key}
            ).scalar_one() is True
            _unlock(competitor, key)
    finally:
        session.close()
        engine.dispose()

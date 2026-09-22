"""Connection-pinned PostgreSQL advisory locks for workflow execution."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import text
from sqlalchemy.orm import Session


logger = logging.getLogger("orchestrator.workflow_lock")


class WorkflowBusyError(ValueError):
    """The workflow is already held by another execution worker."""


def _invalidate_connection(connection, workflow_id: str) -> None:
    try:
        connection.invalidate()
    except Exception as exc:
        logger.critical(
            "Failed to invalidate workflow lock connection workflow_id=%s error=%s",
            workflow_id,
            exc,
        )


@contextmanager
def workflow_advisory_lock(db: Session, lock_key: int, workflow_id: str) -> Iterator[None]:
    """Hold a session advisory lock on one checked-out physical connection."""
    bind = db.get_bind()
    engine = getattr(bind, "engine", bind)
    connection = engine.connect()
    acquired = False
    try:
        acquired = bool(
            connection.execute(
                text("SELECT pg_try_advisory_lock(:key)"),
                {"key": lock_key},
            ).scalar()
        )
        if not acquired:
            raise WorkflowBusyError(
                f"Workflow {workflow_id} is currently being processed by another worker"
            )
        yield
    finally:
        if acquired:
            try:
                released = bool(
                    connection.execute(
                        text("SELECT pg_advisory_unlock(:key)"),
                        {"key": lock_key},
                    ).scalar()
                )
            except Exception as exc:
                logger.error(
                    "Workflow advisory unlock failed workflow_id=%s error=%s",
                    workflow_id,
                    exc,
                )
                _invalidate_connection(connection, workflow_id)
            else:
                if not released:
                    logger.error(
                        "Workflow advisory unlock was not confirmed workflow_id=%s",
                        workflow_id,
                    )
                    _invalidate_connection(connection, workflow_id)
        connection.close()

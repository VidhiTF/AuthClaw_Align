"""Real PostgreSQL validation for the Python canonical append wrapper."""

import os
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import text

from app.db.session import SessionLocal, engine
from app.services.audit_store import append_audit_event


pytestmark = pytest.mark.skipif(
    os.getenv("AUTHCLAW_ACL21_DB_TESTS") != "true",
    reason="set AUTHCLAW_ACL21_DB_TESTS=true for PostgreSQL ACL-21 tests",
)


def test_python_wrapper_exact_replay_and_collision():
    tenant_id = str(uuid4())
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO tenants (id, name, tier, status)
                VALUES (CAST(:tenant_id AS uuid), :name, 'starter', 'active')
                """
            ),
            {"tenant_id": tenant_id, "name": f"ACL-21 Python {tenant_id}"},
        )

    event = {
        "id": str(uuid4()),
        "idempotency_key": "python-wrapper-replay",
        "tenant_id": tenant_id,
        "timestamp": datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc),
        "actor_type": "backend",
        "action": "evidence:created",
        "provider": "control-plane",
        "reason": "ACL-21 Python integration",
        "frameworks_affected": ["SOC2"],
        "execution_trace": ["python-wrapper"],
    }
    with SessionLocal() as db:
        first = append_audit_event(db, dict(event))
        db.commit()
    replay = dict(event)
    replay["id"] = str(uuid4())
    with SessionLocal() as db:
        duplicate = append_audit_event(db, replay)
        db.commit()
    assert duplicate["duplicate"] is True
    assert duplicate["record_id"] == first["record_id"]
    assert duplicate["tenant_sequence"] == first["tenant_sequence"]

    collision = dict(event)
    collision["id"] = str(uuid4())
    collision["action"] = "evidence:deleted"
    with SessionLocal() as db:
        with pytest.raises(Exception, match="idempotency-key collision"):
            append_audit_event(db, collision)
        db.rollback()

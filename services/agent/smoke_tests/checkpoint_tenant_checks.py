"""Checkpoint migration and concurrency checks using the existing isolated DB fixture."""
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from fastapi import HTTPException
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError


def assert_restricted_migration_upgrade(owner):
    """Exercise the documented prepare -> migrate -> finalize repeat-upgrade cycle."""
    from unittest.mock import patch
    from bootstrap_database_security import (
        Role, prepare_existing_schema_objects_for_migration,
        prepare_agent_security_objects_for_migration, secure_agent_authentication_boundary,
    )
    from database import migrations, validate_database_security
    migrator = Role("ent019_migrator", "ent019-test-only", "agent")
    runtime = Role("ent019_runtime", "", "agent")
    with owner.begin() as conn:
        if not conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname=:role"), {"role": migrator.name}).scalar():
            conn.execute(text("CREATE ROLE ent019_migrator LOGIN PASSWORD 'ent019-test-only' NOSUPERUSER NOBYPASSRLS"))
        conn.execute(text("GRANT USAGE,CREATE ON SCHEMA agent TO ent019_migrator"))
        prepare_existing_schema_objects_for_migration(conn, migrator)
        secure_agent_authentication_boundary(conn, migrator, runtime)
    restricted = create_engine(owner.url.set(username=migrator.name, password=migrator.password),
                               connect_args={"options": "-csearch_path=agent,pg_catalog"})
    try:
        for _ in range(2):
            with owner.begin() as conn:
                prepare_agent_security_objects_for_migration(conn, migrator)
            with restricted.connect() as conn:
                assert tuple(conn.execute(text("SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user")).one()) == (False, False)
            with patch.object(migrations, "migration_engine", restricted):
                migrations.run_startup_migrations()
            with owner.begin() as conn:
                secure_agent_authentication_boundary(conn, migrator, runtime)
                assert conn.execute(text("SELECT bool_and(relrowsecurity AND relforcerowsecurity) FROM pg_class WHERE oid IN ('agent.gateway_requests'::regclass,'agent.event_consumer_checkpoints'::regclass,'agent.chat_messages'::regclass)")).scalar() is True
            validate_database_security()
    finally:
        restricted.dispose()


def seed_legacy_checkpoint(conn):
    conn.execute(text("""
        CREATE TABLE agent.event_consumer_checkpoints (
            id SERIAL PRIMARY KEY, stream VARCHAR(50) NOT NULL, consumer_group VARCHAR(120) NOT NULL,
            pending_events INTEGER NOT NULL DEFAULT 0, dead_letter_count INTEGER NOT NULL DEFAULT 0,
            lag_seconds INTEGER NOT NULL DEFAULT 0, last_delivered_at TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(stream, consumer_group));
        INSERT INTO agent.event_consumer_checkpoints(stream,consumer_group,pending_events)
            VALUES ('legacy-unattributed','authclaw-analytics-ingestor',99);
    """))


def assert_tenant_checkpoints(owner, engine):
    from services.event_pipeline import EventPipeline
    from services.tenant_context import tenant_context

    stream = "ent019-checkpoint"
    pipeline = EventPipeline()
    with owner.connect() as conn:
        assert conn.execute(text("SELECT tenant_id FROM agent.event_consumer_checkpoints WHERE stream='legacy-unattributed'")).scalar_one() is None
        assert tuple(conn.execute(text("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid='agent.event_consumer_checkpoints'::regclass")).one()) == (True, True)
    for tenant in (7, 8):
        with tenant_context(tenant, request_id="checkpoint-seed", required=True), engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO event_delivery_records(event_id,tenant_id,stream,topic,source,status,payload)
                VALUES (:id,:tenant,:stream,'test','test',:status,'{}')
            """), {"id": f"checkpoint-{tenant}", "tenant": tenant, "stream": stream,
                   "status": "queued" if tenant == 7 else "dead_letter"})

    barrier = Barrier(2)
    def refresh(tenant, simultaneous=False):
        with tenant_context(tenant, request_id="checkpoint-refresh", required=True):
            if simultaneous:
                barrier.wait(timeout=10)
            pipeline.refresh_checkpoint(stream)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(refresh, tenant, True) for tenant in (7, 8)]
        for future in futures:
            future.result(timeout=15)
        for tenant in (7, 8):
            with tenant_context(tenant, request_id="checkpoint-isolation", required=True), engine.begin() as conn:
                checkpoints = pipeline.delivery_metrics()["checkpoints"]
                assert all(row["tenant_id"] == tenant for row in checkpoints)
                row = next(row for row in checkpoints if row["stream"] == stream)
                assert (row["pending_events"], row["dead_letter_count"]) == (1, int(tenant == 8))
                assert conn.execute(text("SELECT count(*) FROM event_consumer_checkpoints WHERE tenant_id != :tenant OR tenant_id IS NULL"), {"tenant": tenant}).scalar_one() == 0
                assert conn.execute(text("UPDATE event_consumer_checkpoints SET pending_events=100 WHERE tenant_id=:other"), {"other": 15 - tenant}).rowcount == 0
                assert conn.execute(text("DELETE FROM event_consumer_checkpoints WHERE tenant_id=:other"), {"other": 15 - tenant}).rowcount == 0
            with tenant_context(tenant, request_id="checkpoint-forgery", required=True):
                try:
                    with engine.begin() as conn:
                        conn.execute(text("INSERT INTO event_consumer_checkpoints(tenant_id,stream,consumer_group) VALUES (:other,'forged','test')"), {"other": 15 - tenant})
                except DBAPIError as exc:
                    assert exc.orig.pgcode == "42501"
                else:
                    raise AssertionError("Cross-tenant checkpoint insert succeeded")

        # Both refreshes must wait before reading. A committed delivery while
        # waiting must be visible, rather than overwritten by stale queued counts.
        with owner.begin() as conn:
            conn.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key,0))"), {"key": f"checkpoint:7:{stream}"})
            waiting = [pool.submit(refresh, 7) for _ in range(2)]
            deadline = time.monotonic() + 10
            while True:
                with owner.connect() as observer:
                    blocked = observer.execute(text("SELECT count(*) FROM pg_stat_activity WHERE wait_event='advisory' AND query LIKE :key"), {"key": f"%checkpoint:7:{stream}%"}).scalar_one()
                if blocked == 2:
                    break
                assert time.monotonic() < deadline, "Refresh workers did not wait for the tenant lock"
                time.sleep(0.02)
            conn.execute(text("UPDATE agent.event_delivery_records SET status='delivered',delivered_at=NOW() WHERE event_id='checkpoint-7'"))
        for future in waiting:
            future.result(timeout=15)
        with tenant_context(7, request_id="checkpoint-delivered", required=True):
            checkpoint = next(row for row in pipeline.delivery_metrics()["checkpoints"] if row["stream"] == stream)
            assert checkpoint["pending_events"] == 0 and checkpoint["last_delivered_at"] is not None

    with tenant_context(None), engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM event_consumer_checkpoints")).scalar_one() == 0
        for operation in (pipeline.delivery_metrics, lambda: pipeline.refresh_checkpoint(stream)):
            try:
                operation()
            except HTTPException as exc:
                assert exc.status_code == 403
            else:
                raise AssertionError("Checkpoint operation accepted missing tenant context")
    for tenant in (7, 8):
        with tenant_context(tenant, request_id="checkpoint-cleanup", required=True), engine.begin() as conn:
            conn.execute(text("DELETE FROM event_consumer_checkpoints WHERE stream=:stream"), {"stream": stream})
            conn.execute(text("DELETE FROM event_delivery_records WHERE stream=:stream"), {"stream": stream})

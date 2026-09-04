"""Supervised bounded maintenance on existing backend containers."""

import asyncio
import logging
import os
import time

from sqlalchemy import create_engine, text

logger = logging.getLogger("authclaw.worker_cleanup")


def enabled() -> bool:
    return os.getenv("WORKER_CLEANUP_ENABLED", "false").lower() == "true"


def sweep(engine) -> dict:
    started = time.monotonic()
    with engine.begin() as connection:
        connection.execute(text("SET LOCAL statement_timeout = '10s'"))
        connection.execute(text("SET LOCAL lock_timeout = '2s'"))
        result = dict(
            connection.execute(
                text("SELECT * FROM worker_maintenance.expire_tokens(500)")
            )
            .mappings()
            .one()
        )
    # No success is published until the transaction actually commits.
    result["duration_ms"] = round((time.monotonic() - started) * 1000)
    return result


async def run(engine, stop: asyncio.Event, *, interval: float = 60) -> None:
    failures = 0
    while not stop.is_set():
        try:
            result = await asyncio.to_thread(sweep, engine)
            failures = 0
            logger.info(
                "worker_cleanup acquired=%s expired=%s duration_ms=%s",
                result["acquired"],
                result["expired"],
                result["duration_ms"],
            )
        except Exception as exc:
            failures += 1
            logger.error(
                "worker_cleanup failed error_type=%s consecutive_failures=%s",
                type(exc).__name__,
                failures,
            )
        delay = min(300, interval * (2 ** min(failures, 3)))
        try:
            await asyncio.wait_for(stop.wait(), timeout=delay)
        except TimeoutError:
            pass


def validate(engine) -> None:
    with engine.connect() as connection:
        safe = connection.execute(text("""
            SELECT count(*) = 4 AND bool_and(
              p.prosecdef AND r.rolname = 'authclaw_worker_maintenance'
              AND NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls
              AND NOT pg_has_role(session_user, r.oid, 'MEMBER')
              AND NOT EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE')
            ) FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner
              WHERE p.pronamespace='worker_maintenance'::regnamespace
                AND p.proname IN ('expire_tokens','cleanup_health','issuance_ready','guard_token_write')
        """)).scalar_one()
        if not safe:
            raise RuntimeError(
                "Worker maintenance ownership or privileges are insecure"
            )


async def start(app, engine) -> None:
    if not enabled():
        return
    cleanup_engine = create_engine(
        engine.url,
        pool_size=1,
        max_overflow=0,
        pool_timeout=3,
        pool_pre_ping=True,
        connect_args={"connect_timeout": 5},
    )
    try:
        validate(cleanup_engine)
    except Exception:
        cleanup_engine.dispose()
        raise
    stop = asyncio.Event()
    app.state.worker_cleanup_stop = stop
    app.state.worker_cleanup_engine = cleanup_engine
    app.state.worker_cleanup_task = asyncio.create_task(
        run(cleanup_engine, stop), name="worker-token-cleanup"
    )


async def shutdown(app) -> None:
    task = getattr(app.state, "worker_cleanup_task", None)
    if task is not None:
        app.state.worker_cleanup_stop.set()
        # SQL timeouts bound work already in flight; do not abandon its transaction.
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=25)
        finally:
            app.state.worker_cleanup_engine.dispose()

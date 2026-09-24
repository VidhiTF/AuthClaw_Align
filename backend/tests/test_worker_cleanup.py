import asyncio
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.services import worker_cleanup


def test_loop_recovers_after_failure_and_stops(monkeypatch):
    calls = []

    async def exercise():
        stop = asyncio.Event()

        def sweep(_):
            calls.append(1)
            if len(calls) == 1:
                raise ConnectionError("synthetic database outage")
            return {"acquired": True, "expired": 0, "duration_ms": 1}

        monkeypatch.setattr(worker_cleanup, "sweep", sweep)
        task = asyncio.create_task(worker_cleanup.run(None, stop, interval=0.005))
        for _ in range(100):
            if len(calls) >= 2:
                break
            await asyncio.sleep(0.005)
        stop.set()
        await asyncio.wait_for(task, 1)

    asyncio.run(exercise())
    assert len(calls) >= 2


def test_backend_lifespan_preserves_startup_order_health_and_shutdown(monkeypatch, caplog):
    import main
    from app.core import worker_tokens

    events = []

    @contextmanager
    def connect():
        events.append("connect")
        yield object()
        events.append("disconnect")

    async def start(app, engine):
        events.append("start")

    async def shutdown(app):
        events.append("shutdown")

    monkeypatch.setattr(main, "engine", SimpleNamespace(connect=connect))
    monkeypatch.setattr(main, "validate_database_security", lambda _: events.append("validate"))
    monkeypatch.setattr(worker_tokens, "active_version", lambda: events.append("version") or "v1")
    monkeypatch.setattr(worker_tokens, "key_for", lambda _: events.append("key"))
    monkeypatch.setattr(worker_cleanup, "start", start)
    monkeypatch.setattr(worker_cleanup, "shutdown", shutdown)
    monkeypatch.setenv("WORKER_TOKEN_ISSUANCE_PAUSED", "false")

    with caplog.at_level("INFO", logger="uvicorn.error"):
        with TestClient(main.app) as client:
            assert events == ["connect", "validate", "disconnect", "version", "key", "start"]
            response = client.get("/health")
            assert response.status_code == 200
            assert response.json() == {"status": "healthy", "service": "authclaw-backend"}
            assert client.get("/metrics").status_code == 401
            assert client.get("/openapi.json").status_code == 200
            assert client.get("/docs").status_code == 200

    assert events[-1] == "shutdown"
    assert events.count("start") == events.count("shutdown") == 1
    assert "event=startup" in caplog.text
    assert "event=shutdown" in caplog.text


@pytest.mark.parametrize("failure", ["database", "token", "cleanup"])
def test_backend_lifespan_rejects_failed_startup(monkeypatch, failure):
    import main
    from app.core import worker_tokens

    events = []

    @contextmanager
    def connect():
        yield object()

    def validate(_):
        events.append("validate")
        if failure == "database":
            raise RuntimeError("database validation failed")

    async def start(app, engine):
        events.append("start")
        if failure == "cleanup":
            raise RuntimeError("cleanup validation failed")

    async def shutdown(app):
        events.append("shutdown")

    def key_for(_):
        events.append("key")
        if failure == "token":
            raise RuntimeError("worker key missing")

    monkeypatch.setattr(main, "engine", SimpleNamespace(connect=connect))
    monkeypatch.setattr(main, "validate_database_security", validate)
    monkeypatch.setattr(worker_tokens, "active_version", lambda: "v1")
    monkeypatch.setattr(worker_tokens, "key_for", key_for)
    monkeypatch.setattr(worker_cleanup, "start", start)
    monkeypatch.setattr(worker_cleanup, "shutdown", shutdown)
    monkeypatch.setenv("WORKER_TOKEN_ISSUANCE_PAUSED", "false")

    with pytest.raises(RuntimeError):
        with TestClient(main.app):
            pass
    assert events == {
        "database": ["validate"],
        "token": ["validate", "key"],
        "cleanup": ["validate", "key", "start"],
    }[failure]


def test_enabled_cleanup_worker_stops_and_disposes_its_engine(monkeypatch):
    events = []
    app = SimpleNamespace(state=SimpleNamespace())
    cleanup_engine = SimpleNamespace(dispose=lambda: events.append("dispose"))
    monkeypatch.setenv("WORKER_CLEANUP_ENABLED", "true")
    monkeypatch.setattr(worker_cleanup, "create_engine", lambda *args, **kwargs: cleanup_engine)
    monkeypatch.setattr(worker_cleanup, "validate", lambda _: events.append("validate"))

    async def run(engine, stop):
        events.append("run")
        await stop.wait()
        events.append("stopped")

    monkeypatch.setattr(worker_cleanup, "run", run)

    async def exercise():
        await worker_cleanup.start(app, SimpleNamespace(url="test://"))
        await asyncio.sleep(0)
        await worker_cleanup.shutdown(app)

    asyncio.run(exercise())
    assert events == ["validate", "run", "stopped", "dispose"]


def test_disabled_cleanup_worker_does_not_create_engine(monkeypatch):
    monkeypatch.setenv("WORKER_CLEANUP_ENABLED", "false")
    monkeypatch.setattr(worker_cleanup, "create_engine", lambda *args, **kwargs: pytest.fail("unexpected engine"))
    app = SimpleNamespace(state=SimpleNamespace())

    async def exercise():
        await worker_cleanup.start(app, SimpleNamespace(url="test://"))
        await worker_cleanup.shutdown(app)

    asyncio.run(exercise())


def test_success_is_not_returned_when_commit_fails():
    import pytest

    class Result:
        def mappings(self):
            return self

        def one(self):
            return {"acquired": True, "expired": 5}

    class Connection:
        def execute(self, _):
            return Result()

        def __enter__(self):
            return self

        def __exit__(self, *_):
            raise ConnectionError("commit failed")

    class Engine:
        def begin(self):
            return Connection()

    with pytest.raises(ConnectionError):
        worker_cleanup.sweep(Engine())


def test_monitor_exports_failure_without_sensitive_error():
    from scripts.check_worker_cleanup import prometheus

    result = prometheus({"healthy": False, "error_type": "ConnectionError"})
    assert "authclaw_worker_cleanup_healthy 0" in result
    assert "authclaw_worker_cleanup_last_success_seconds 0" in result
    assert "ConnectionError" not in result


def test_ec2_rds_requires_verified_tls_and_mounted_ca(tmp_path):
    import pytest
    from scripts.verify_ec2_rds import validate_url

    for raw in (
        "postgresql://app:test@db.example/db",
        "postgresql://app:test@db.example/db?sslmode=require",
        "postgresql://app:test@db.example/db?sslmode=verify-full&sslrootcert=/missing/ca.pem",
    ):
        with pytest.raises(ValueError):
            validate_url(raw)
    bundle = tmp_path / "ca.pem"
    bundle.write_text("synthetic configuration fixture; not a trusted certificate")
    # Actual certificate validity/hostname matching is enforced by libpq on connect.
    url = validate_url(
        f"postgresql://app:test@db.example/db?sslmode=verify-full&sslrootcert={bundle}"
    )
    assert url.query["sslmode"] == "verify-full"

import asyncio

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

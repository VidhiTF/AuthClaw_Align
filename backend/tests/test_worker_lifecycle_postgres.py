"""Real PostgreSQL privileges, cutover barrier, audit atomicity and concurrency."""

import os
from pathlib import Path
import subprocess
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from app.services.worker_cleanup import sweep, validate
from scripts.worker_token_cutover import control
from scripts.check_worker_cleanup import check
from scripts.verify_worker_lifecycle import verify
from tests.db_safety import destructive_test_urls


@pytest.fixture(scope="module")
def database():
    owner_url, app_url = destructive_test_urls()
    name = f"authclaw_worker_{uuid.uuid4().hex}_test"
    admin = create_engine(owner_url, isolation_level="AUTOCOMMIT")
    owner = create_engine(make_url(owner_url).set(database=name))
    app = create_engine(make_url(app_url).set(database=name))
    environment = {
        **os.environ,
        "POSTGRES_DB": name,
        "DATABASE_URL": make_url(owner_url)
        .set(database=name)
        .render_as_string(hide_password=False),
        "BOOTSTRAP_DATABASE_URL": make_url(owner_url)
        .set(database=name)
        .render_as_string(hide_password=False),
    }

    def run(*args):
        result = subprocess.run(
            [sys.executable, *args],
            cwd=Path(__file__).parents[1],
            env=environment,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stderr

    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    try:
        run("scripts/bootstrap_database_security.py", "prepare")
        run("-m", "alembic", "upgrade", "045")
        tenant = uuid.uuid4()
        with owner.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO tenants(id,name) VALUES (:id,'worker lifecycle test')"
                ),
                {"id": tenant},
            )
            for index, lifetime in enumerate(("-1 minute", "30 minutes")):
                conn.execute(
                    text(
                        """INSERT INTO ephemeral_worker_tokens
                    (id,tenant_id,action_id,connector,purpose,scopes,token_hash,token_prefix,expires_at)
                    VALUES (:id,:tenant,'s3.sync','aws','scan',ARRAY['aws:s3:read'],:hash,'test',now()+cast(:life AS interval))"""
                    ),
                    {
                        "id": uuid.uuid4(),
                        "tenant": tenant,
                        "hash": str(index) * 64,
                        "life": lifetime,
                    },
                )
        run("-m", "alembic", "upgrade", "head")
        run("scripts/bootstrap_database_security.py", "finalize-backend")
        yield owner, app, tenant
    finally:
        owner.dispose()
        app.dispose()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE "{name}"'))
        admin.dispose()


def test_privileges_and_atomic_cleanup(database):
    owner, app, tenant = database
    validate(app)
    with app.begin() as conn:
        assert (
            conn.execute(
                text("SELECT count(*) FROM ephemeral_worker_tokens")
            ).scalar_one()
            == 0
        )
        assert check(conn)["healthy"] is False
    for statement in (
        "UPDATE worker_maintenance.control SET mode='hmac'",
        "SELECT * FROM worker_maintenance.control",
        "UPDATE worker_maintenance.heartbeat SET last_success=now()",
        "SET ROLE authclaw_worker_maintenance",
        "SELECT worker_maintenance.expire_tokens(501)",
    ):
        with pytest.raises(DBAPIError), app.begin() as conn:
            conn.execute(text(statement))
    # A rolled-back sweep must not expire tokens or publish audit/heartbeat.
    with app.connect() as conn:
        transaction = conn.begin()
        conn.execute(text("CREATE TEMP TABLE audit_log_metadata (untrusted text)"))
        conn.execute(text("CREATE TEMP TABLE audit_outbox (untrusted text)"))
        assert (
            conn.execute(
                text("SELECT expired FROM worker_maintenance.expire_tokens(500)")
            ).scalar_one()
            == 1
        )
        transaction.rollback()
    with owner.begin() as conn:
        assert (
            conn.execute(
                text(
                    "SELECT count(*) FROM ephemeral_worker_tokens WHERE status='expired'"
                )
            ).scalar_one()
            == 0
        )
        assert (
            conn.execute(
                text(
                    "SELECT count(*) FROM audit_log_metadata WHERE action='worker:token.expired'"
                )
            ).scalar_one()
            == 0
        )
    with owner.begin() as lock:
        lock.execute(text("SELECT pg_advisory_xact_lock(734271,7)"))
        assert sweep(app)["acquired"] is False
        with app.begin() as conn:
            assert check(conn)["healthy"] is False
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: sweep(app), range(2)))
    assert sum(result["expired"] for result in results) == 1
    assert sweep(app)["expired"] == 0
    with owner.begin() as conn:
        assert (
            conn.execute(
                text(
                    "SELECT count(*) FROM audit_log_metadata WHERE action='worker:token.expired'"
                )
            ).scalar_one()
            == 1
        )
        assert conn.execute(text("SELECT count(*) FROM audit_outbox")).scalar_one() == 1
    with app.begin() as conn:
        assert check(conn)["healthy"] is True
    with owner.begin() as conn:
        conn.execute(
            text(
                "UPDATE worker_maintenance.heartbeat SET last_success=now()-interval '6 minutes'"
            )
        )
    with app.begin() as conn:
        assert check(conn)["healthy"] is False


def test_cutover_blocks_old_issuers_and_requires_both_gates(database, monkeypatch):
    monkeypatch.setenv("WORKER_TOKEN_HMAC_ACTIVE_VERSION", "v1")
    monkeypatch.setenv(
        "WORKER_TOKEN_HMAC_KEY_V1", "test-only-worker-hmac-key-material-32"
    )
    owner, app, tenant = database
    insert = text(
        """INSERT INTO ephemeral_worker_tokens
        (id,tenant_id,action_id,connector,purpose,scopes,token_hash,token_prefix,expires_at)
        VALUES (:id,:tenant,'s3.sync','aws','scan',ARRAY['aws:s3:read'],:hash,'test',now()+interval '10 minutes')"""
    )
    params = {"id": uuid.uuid4(), "tenant": tenant, "hash": "f" * 64}
    with pytest.raises(DBAPIError), owner.begin() as conn:
        conn.execute(insert, params)
    with owner.begin() as conn:
        assert control(conn, "pause")["paused"]
        assert verify(conn)["passed"] is False
    with pytest.raises(RuntimeError), owner.begin() as conn:
        control(conn, "activate")
    with owner.begin() as conn:
        conn.execute(
            text(
                "UPDATE worker_maintenance.control SET paused_at=now()-interval '33 minutes'"
            )
        )
    with pytest.raises(RuntimeError), owner.begin() as conn:
        control(conn, "activate")
    with owner.begin() as conn:
        # Simulate no valid legacy credentials remaining without waiting in CI.
        conn.execute(
            text(
                "UPDATE ephemeral_worker_tokens SET status='revoked' WHERE status='active'"
            )
        )
        assert control(conn, "activate")["activated"]
        assert verify(conn)["passed"] is True
    # Even a rolled-back old binary still cannot issue SHA-256 rows.
    with pytest.raises(DBAPIError), owner.begin() as conn:
        conn.execute(insert, params)
    with pytest.raises(DBAPIError), owner.begin() as conn:
        conn.execute(
            text(
                "UPDATE ephemeral_worker_tokens SET status='active' WHERE status='revoked'"
            )
        )
    with app.begin() as conn:
        assert conn.execute(
            text("SELECT worker_maintenance.issuance_ready()")
        ).scalar_one()


def test_hmac_authorization_scope_and_expiry_without_sweeper(database, monkeypatch):
    from sqlalchemy.orm import sessionmaker
    from tests.test_tenant_isolation import IsolationHarness
    from app.services import ephemeral_workers as workers

    owner, app, _ = database
    harness = IsolationHarness(
        owner, app, sessionmaker(bind=app, expire_on_commit=False)
    )
    alice = harness.create_identity("worker-alice")
    bob = harness.create_identity("worker-bob")
    monkeypatch.setenv("WORKER_TOKEN_ISSUANCE_PAUSED", "false")
    monkeypatch.setenv(
        "WORKER_TOKEN_HMAC_KEY_V1", "test-only-worker-hmac-key-material-32"
    )
    monkeypatch.setenv("WORKER_TOKEN_HMAC_ACTIVE_VERSION", "v1")
    with harness.session_for(alice) as db:
        issued = workers.issue_worker_token(
            db,
            tenant_id=alice.tenant_id,
            connector="aws",
            action_id="s3.sync",
            purpose="scan",
            scopes=["aws:s3:read"],
        )
        expires_at = issued.token.expires_at
        assert workers.authorize_worker_action(
            db,
            tenant_id=alice.tenant_id,
            raw_token=issued.raw_token,
            connector="aws",
            action="s3.sync",
        ).allowed
        assert not workers.authorize_worker_action(
            db,
            tenant_id=alice.tenant_id,
            raw_token="ewt_legacy_secret",
            connector="aws",
            action="s3.sync",
        ).allowed
    with harness.session_for(bob) as db:
        assert not workers.authorize_worker_action(
            db,
            tenant_id=bob.tenant_id,
            raw_token=issued.raw_token,
            connector="aws",
            action="s3.sync",
        ).allowed
    # A candidate must retain keys for every still-valid HMAC version.
    monkeypatch.setenv("WORKER_TOKEN_HMAC_ACTIVE_VERSION", "v2")
    monkeypatch.setenv(
        "WORKER_TOKEN_HMAC_KEY_V2", "test-only-worker-second-key-material-32"
    )
    with owner.begin() as conn:
        assert verify(conn)["passed"] is True
    monkeypatch.delenv("WORKER_TOKEN_HMAC_KEY_V1")
    with pytest.raises(RuntimeError), owner.begin() as conn:
        verify(conn)
    monkeypatch.setenv(
        "WORKER_TOKEN_HMAC_KEY_V1", "test-only-worker-hmac-key-material-32"
    )
    # No cleanup call: the exact expiry boundary itself rejects authorization.
    monkeypatch.setattr(workers, "now_utc", lambda: expires_at)
    with harness.session_for(alice) as db:
        outcome = workers.authorize_worker_action(
            db,
            tenant_id=alice.tenant_id,
            raw_token=issued.raw_token,
            connector="aws",
            action="s3.sync",
        )
        assert not outcome.allowed and outcome.status == "expired"

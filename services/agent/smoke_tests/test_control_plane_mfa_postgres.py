"""PostgreSQL/RLS proof for signed control-plane MFA approval and execution."""

import hashlib
import json
import os
import secrets
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace
from uuid import uuid4

import pytest
import redis
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError


OWNER_URL = os.getenv("ENT022_AGENT_POSTGRES_URL", "")
pytestmark = pytest.mark.skipif(not OWNER_URL, reason="ENT022 Agent PostgreSQL URL required")


def _tenant_engine(url, schema, zone, tenant_id=None):
    runtime = create_engine(url, connect_args={"options": f"-csearch_path={schema},pg_catalog -ctimezone={zone}"})

    @event.listens_for(runtime, "begin")
    def bind_tenant(conn):
        from services.tenant_context import get_current_tenant_id
        conn.execute(
            text("SELECT set_config('app.ent022_tenant', :tenant_id, true)"),
            {"tenant_id": str(tenant_id or get_current_tenant_id() or 0)},
        )

    return runtime


@pytest.fixture(params=["UTC", "America/Los_Angeles", "Asia/Kolkata"])
def approval_database(monkeypatch, request):
    import approval_store

    assert make_url(OWNER_URL).database.endswith("_test"), "Disposable test database required"
    schema = "ent022_mfa_" + secrets.token_hex(6)
    role = "ent022_runtime_" + secrets.token_hex(6)
    password = secrets.token_urlsafe(24)
    owner = create_engine(OWNER_URL)
    with owner.begin() as conn:
        conn.execute(text(f'CREATE ROLE "{role}" LOGIN PASSWORD \'{password}\' NOSUPERUSER NOBYPASSRLS'))
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))
        conn.execute(text(f'SET LOCAL search_path TO "{schema}", pg_catalog'))
        conn.execute(text("""
            CREATE TABLE gateway_approvals (
                id SERIAL PRIMARY KEY, approval_id VARCHAR(100) UNIQUE NOT NULL,
                request_id VARCHAR(100), correlation_id VARCHAR(100), tenant_id INTEGER NOT NULL,
                status VARCHAR(50) NOT NULL, requested_by VARCHAR(255), created_at TIMESTAMP,
                expires_at TIMESTAMP, approved_at TIMESTAMP, rejected_at TIMESTAMP,
                executed_at TIMESTAMP, requested_action TEXT, query TEXT, risk_level VARCHAR(20),
                audit_id INTEGER, reason VARCHAR(100), comments TEXT, approved_by VARCHAR(255),
                rejected_by VARCHAR(255), executed_by VARCHAR(255), mfa_verified BOOLEAN DEFAULT FALSE,
                last_action_at TIMESTAMP, metadata TEXT, approval_mfa_verified BOOLEAN DEFAULT FALSE,
                execution_mfa_verified BOOLEAN DEFAULT FALSE, approval_mfa_binding_hash VARCHAR(64),
                execution_mfa_binding_hash VARCHAR(64), approval_mfa_counter BIGINT,
                execution_mfa_counter BIGINT, execution_token_hash VARCHAR(64),
                execution_token_used_at TIMESTAMP, execution_expires_at TIMESTAMP,
                execution_operation_id VARCHAR(100), execution_provider_operation_id VARCHAR(255),
                execution_outcome TEXT, execution_reconcile_after TIMESTAMP
            );
            CREATE TABLE approval_audit_events (
                id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, approval_id VARCHAR(100),
                request_id VARCHAR(100), action VARCHAR(50) NOT NULL, actor VARCHAR(255),
                comment TEXT, mfa_verified BOOLEAN DEFAULT FALSE, reason VARCHAR(100),
                metadata TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE tenants (
                id SERIAL PRIMARY KEY, name TEXT, status TEXT,
                control_plane_id TEXT UNIQUE NOT NULL
            );
            ALTER TABLE gateway_approvals ENABLE ROW LEVEL SECURITY;
            ALTER TABLE gateway_approvals FORCE ROW LEVEL SECURITY;
            CREATE POLICY tenant_gateway_approvals ON gateway_approvals
                USING (tenant_id = current_setting('app.ent022_tenant', true)::integer)
                WITH CHECK (tenant_id = current_setting('app.ent022_tenant', true)::integer);
            ALTER TABLE approval_audit_events ENABLE ROW LEVEL SECURITY;
            ALTER TABLE approval_audit_events FORCE ROW LEVEL SECURITY;
            CREATE POLICY tenant_approval_audit ON approval_audit_events
                USING (tenant_id = current_setting('app.ent022_tenant', true)::integer)
                WITH CHECK (tenant_id = current_setting('app.ent022_tenant', true)::integer);
        """))
        # Exercise the production tenant-mapping function in this isolated schema.
        source = (Path(__file__).parents[1] / "database/migrations.py").read_text()
        mapping_sql = source.split("    CREATE OR REPLACE FUNCTION upsert_control_plane_tenant(", 1)[1].split("    CREATE OR REPLACE FUNCTION load_oidc_login_state", 1)[0]
        conn.execute(text(("CREATE OR REPLACE FUNCTION upsert_control_plane_tenant(" + mapping_sql).replace("agent", schema)))
        conn.execute(text("REVOKE ALL ON FUNCTION upsert_control_plane_tenant(text,text) FROM PUBLIC"))
        conn.execute(text(f'GRANT EXECUTE ON FUNCTION upsert_control_plane_tenant(text,text) TO "{role}"'))
        conn.execute(text(f'GRANT USAGE ON SCHEMA "{schema}" TO "{role}"'))
        conn.execute(text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA "{schema}" TO "{role}"'))
        conn.execute(text(f'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA "{schema}" TO "{role}"'))

    runtime_url = make_url(OWNER_URL).set(username=role, password=password)
    runtime = _tenant_engine(runtime_url, schema, request.param)
    tenant_one = _tenant_engine(runtime_url, schema, request.param, 1)
    tenant_two = _tenant_engine(runtime_url, schema, request.param, 2)
    monkeypatch.setattr(approval_store, "engine", runtime)
    try:
        yield runtime, tenant_one, tenant_two, owner, schema
    finally:
        runtime.dispose()
        tenant_one.dispose()
        tenant_two.dispose()
        with owner.begin() as conn:
            conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
            conn.execute(text(f'DROP ROLE "{role}"'))
        owner.dispose()


def _pending_record():
    now_utc = datetime.now(timezone.utc)
    now = now_utc.replace(tzinfo=None)
    return {
        "approval_id": "approval-postgres-17", "request_id": "request-postgres-17",
        "correlation_id": "correlation-postgres-17", "tenant_id": 1, "status": "pending",
        "requested_by": str(uuid4()), "created_at": now,
        "expires_at": now + timedelta(minutes=30), "requested_action": "delete",
        "query": "delete sensitive records", "risk_level": "HIGH", "reason": "high_risk",
        "comments": [], "metadata": {},
    }


def test_signed_control_plane_principal_completes_mfa_approval_and_execution_under_rls(monkeypatch, approval_database):
    import approval_store
    import database
    import main
    import verify_audit
    from services import control_plane_auth
    from services.tenant_context import tenant_context

    runtime, tenant_one, tenant_two, _, _ = approval_database
    record = _pending_record()
    bundle_path = os.getenv("ENT022_ASSERTION_BUNDLE")
    bundle = json.loads(Path(bundle_path).read_text()) if bundle_path else None
    actor = bundle["actor"] if bundle else str(uuid4())
    tenant = bundle["tenant"] if bundle else str(uuid4())
    actor_role = bundle["role"] if bundle else "owner"
    store = redis.Redis.from_url(os.environ["ENT018_REDIS_URL"])
    assert make_url(os.environ["ENT018_REDIS_URL"]).host in {"localhost", "127.0.0.1"}
    assert store.config_get("maxmemory-policy")["maxmemory-policy"] == "noeviction"
    gate = f"authclaw:service:v2:startup:{store.info('server')['run_id']}:{store.info('replication')['master_replid']}"
    store.set(gate, int(store.time()[0]) - control_plane_auth.NONCE_TTL_SECONDS - 1)
    key = {"secret": secrets.token_hex(32), "service": "console", "audience": "agent",
           "endpoints": ["POST /approve/*", "POST /execute/*"]}
    ring = {"active_key_id": "v1", "keys": {"v1": key}}
    monkeypatch.setenv("AUTHCLAW_INTERNAL_SERVICE_SECRET", json.dumps(ring))
    monkeypatch.setenv("AUTHCLAW_ENABLE_RBAC_ENFORCEMENT", "true")
    monkeypatch.setattr(control_plane_auth, "_replay_store", lambda _: store)
    monkeypatch.setattr(database, "engine", runtime)
    # External quota/provider/blockchain adapters are outside this MFA proof.
    monkeypatch.setattr(main, "admit", lambda *args, **kwargs: None)
    monkeypatch.setattr(main, "_tenant_tier_limit", lambda _: 100)
    monkeypatch.setattr(verify_audit, "create_audit_block", lambda **kwargs: None)
    monkeypatch.setattr(main, "get_gateway_service", lambda: SimpleNamespace(
        execute_approval=lambda **kwargs: SimpleNamespace(
            result={"response": "test execution"}, request_id="execution-test", provider="test",
            provider_operation_id="execution-test", model="test", route_id="test",
            decision="ALLOW", trace=[], outcome=main.GatewayExecutionOutcome.SUCCEEDED,
        ),
    ))
    monkeypatch.setattr(main, "get_policy", lambda: {"approval": {
        "require_mfa": True, "require_separate_approver": True,
    }})
    with tenant_context(1, request_id=record["request_id"], required=True):
        approval_store._persist_record(record)

    assertion_keys = set()

    def signed(stage, *, user=actor, tenant_id=tenant, role=actor_role, assertion=None):
        path = f"/{stage}/{record['approval_id']}"
        assertion = assertion or (bundle[stage] if bundle else {
            "verified_at": int(time.time()), "operation": f"POST {path}",
            "body_sha256": hashlib.sha256(b"{}").hexdigest(), "assertion_id": secrets.token_hex(16),
        })
        assertion_keys.add(f"authclaw:mfa-assertion:v1:{assertion['assertion_id']}")
        script = """
          import { controlPlaneHeaders } from './src/lib/control-plane-auth.ts';
          const input = JSON.parse(process.env.ENT022_SIGN_INPUT);
          console.log(JSON.stringify(controlPlaneHeaders(new URL('http://agent' + input.path),
            'POST', '{}', 'application/json', input.principal, input.assertion)));
        """
        result = subprocess.run(["node", "--experimental-strip-types", "--input-type=module", "-e", script],
            cwd=Path(__file__).parents[3] / "console", capture_output=True, text=True, check=True,
            env={**os.environ, "ENT022_SIGN_INPUT": json.dumps({"path": path, "assertion": assertion,
                "principal": {"tenantId": tenant_id, "userId": user, "role": role}})})
        return {**json.loads(result.stdout), "content-type": "application/json"}

    client = TestClient(main.app)  # No lifespan: do not start unrelated provider/monitor services.
    try:
        approve_path = f"/approve/{record['approval_id']}"
        execute_path = f"/execute/{record['approval_id']}"
        headers = signed("approve")
        assert client.post(approve_path, content=b'{"changed":true}', headers=headers).status_code == 401
        assert client.post(execute_path, content=b"{}", headers=headers).status_code == 401
        response = client.post(approve_path, content=b"{}", headers=headers)
        assert response.status_code == 200, response.text
        assert response.json()["data"]["approved_by"] == actor
        assert response.headers["x-tenant-id"] == "1"
        assert client.post(approve_path, content=b"{}", headers=headers).status_code == 401
        # Re-signing the same assertion with a fresh request nonce still fails.
        replay = {name.removeprefix("X-AuthClaw-MFA-"): value for name, value in headers.items() if name.startswith("X-AuthClaw-MFA-")}
        assertion = {"verified_at": int(replay["Verified-At"]), "operation": replay["Operation"],
                     "body_sha256": replay["Body-SHA256"], "assertion_id": replay["Assertion-ID"]}
        assert client.post(approve_path, content=b"{}", headers=signed("approve", assertion=assertion)).status_code == 401
        response = client.post(execute_path, content=b"{}", headers=signed("execute"))
        assert response.status_code == 200, response.text
        with tenant_one.connect() as conn:
            assert conn.execute(text("SELECT array_agg(action ORDER BY id) FROM approval_audit_events")).scalar() == ["approved", "executing", "executed"]
            execution = conn.execute(text(
                "SELECT status, execution_outcome FROM gateway_approvals"
            )).mappings().one()
            assert execution["status"] == "executed"
            assert json.loads(execution["execution_outcome"])["outcome"] == "succeeded"
            assert json.loads(execution["execution_outcome"])["executed"] is True
            assert conn.execute(text("SELECT count(*) FROM approval_audit_events WHERE actor=:actor AND mfa_verified"), {"actor": actor}).scalar_one() == 3
            if evidence_dir := os.getenv("ENT022_EVIDENCE_DIR"):
                zone = conn.execute(text("SHOW timezone")).scalar_one().replace("/", "-")
                events = [dict(row) for row in conn.execute(text(
                    "SELECT action, actor, tenant_id, approval_id, mfa_verified, created_at "
                    "FROM approval_audit_events ORDER BY id"
                )).mappings()]
                Path(evidence_dir, f"agent-{zone}-audit.json").write_text(
                    json.dumps({
                        "gateway_approval": {
                            "status": execution["status"],
                            "execution_outcome": json.loads(execution["execution_outcome"]),
                        },
                        "audit_events": events,
                    }, indent=2, default=str), encoding="utf-8",
                )
        # RBAC and tenant checks are exercised through the same signed HTTP boundary.
        for options, expected in [({"role": "viewer"}, 403), ({"tenant_id": str(uuid4())}, 404)]:
            assert client.post(approve_path, content=b"{}", headers=signed("approve", assertion={
                **assertion, "assertion_id": secrets.token_hex(16)}, **options)).status_code == expected
        with tenant_two.connect() as conn:
            assert conn.execute(text("SELECT count(*) FROM gateway_approvals")).scalar_one() == 0
            assert conn.execute(text("SELECT count(*) FROM approval_audit_events")).scalar_one() == 0
            denied = conn.execute(text(
                "UPDATE gateway_approvals SET status = 'rejected' "
                "WHERE approval_id = 'approval-postgres-17'"
            ))
            assert denied.rowcount == 0
        with pytest.raises(DBAPIError), tenant_two.begin() as conn:
            conn.execute(text("""
                INSERT INTO gateway_approvals (approval_id, tenant_id, status)
                VALUES ('cross-tenant-insert', 1, 'pending')
            """))
    finally:
        client.close()
        # Each timezone is an isolated deployment rehearsal. Remove only this
        # test's random assertion keys after proving replay denial within it.
        if assertion_keys:
            store.delete(*assertion_keys)
        store.close()


def test_concurrent_approval_is_single_use_and_audit_failure_rolls_back(approval_database):
    import approval_store
    from services.tenant_context import tenant_context

    _, tenant_one, _, owner, schema = approval_database
    record = _pending_record()
    with tenant_context(1, request_id=record["request_id"], required=True):
        approval_store._persist_record(record)
    barrier = Barrier(2)

    def approve(actor):
        with tenant_context(1, request_id=record["request_id"], required=True):
            barrier.wait(timeout=10)
            try:
                return approval_store.approve_approval_atomic(
                    record, approver=actor, approved_at=datetime.now(timezone.utc), mfa_verified=True,
                    mfa_binding_hash="a" * 64, mfa_counter=1,
                    execution_expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
                )["approved_by"]
            except approval_store.ApprovalStateConflict:
                return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(approve, [str(uuid4()), str(uuid4())]))
    winners = [actor for actor in results if actor]
    assert len(winners) == 1
    with tenant_one.connect() as conn:
        assert conn.execute(text("SELECT approved_by FROM gateway_approvals")).scalar_one() == winners[0]
        assert conn.execute(text("SELECT actor FROM approval_audit_events WHERE action='approved'")).scalar_one() == winners[0]
    # A database-denied audit insert must roll the state transition back as well.
    with owner.begin() as conn:
        conn.execute(text(f'ALTER TABLE "{schema}".approval_audit_events ADD CONSTRAINT reject_execution_audit CHECK (action <> \'executing\')'))
    with tenant_context(1, request_id=record["request_id"], required=True):
        approved = approval_store.get_approval(record["approval_id"], fresh=True)
        with pytest.raises(approval_store.ApprovalPersistenceError):
            approval_store.begin_approval_execution_atomic(
                approved, actor=winners[0], transition_at=datetime.now(timezone.utc),
                execution_token_hash="b" * 64, execution_operation_id="operation-17",
                reconcile_after=datetime.now(timezone.utc) + timedelta(minutes=1),
                mfa_binding_hash="c" * 64, mfa_counter=2,
            )
    with tenant_one.connect() as conn:
        assert conn.execute(text("SELECT status FROM gateway_approvals")).scalar_one() == "approved"


def test_rejection_after_expiry_records_expiry_instead(approval_database):
    import approval_store
    from services.tenant_context import tenant_context

    _, tenant_one, _, _, _ = approval_database
    record = _pending_record()
    record["approval_id"] = "approval-expired-before-reject"
    record["expires_at"] = datetime.now(timezone.utc) - timedelta(seconds=1)
    rejected_at = datetime.now(timezone.utc)
    with tenant_context(1, request_id=record["request_id"], required=True):
        approval_store._persist_record(record)
        with pytest.raises(approval_store.ApprovalStateConflict) as raised:
            approval_store.reject_approval_atomic(
                record,
                actor=str(uuid4()),
                rejected_at=rejected_at,
            )

    assert raised.value.current_status == "expired"
    with tenant_one.connect() as conn:
        assert conn.execute(text(
            "SELECT status FROM gateway_approvals WHERE approval_id=:approval_id"
        ), {"approval_id": record["approval_id"]}).scalar_one() == "expired"
        assert conn.execute(text(
            "SELECT action FROM approval_audit_events WHERE approval_id=:approval_id"
            " ORDER BY id DESC LIMIT 1"
        ), {"approval_id": record["approval_id"]}).scalar_one() == "expired"

"""PostgreSQL/RLS proof for signed control-plane MFA approval and execution."""

import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError


OWNER_URL = os.getenv("ENT022_AGENT_POSTGRES_URL", "")
pytestmark = pytest.mark.skipif(not OWNER_URL, reason="ENT022 Agent PostgreSQL URL required")


def _tenant_engine(url, tenant_id: int):
    runtime = create_engine(url, connect_args={"options": "-csearch_path=ent022_mfa,pg_catalog"})

    @event.listens_for(runtime, "begin")
    def bind_tenant(conn):
        conn.execute(
            text("SELECT set_config('app.ent022_tenant', :tenant_id, true)"),
            {"tenant_id": str(tenant_id)},
        )

    return runtime


def test_signed_control_plane_principal_completes_mfa_approval_and_execution_under_rls(monkeypatch):
    import approval_store
    import main
    from services import control_plane_auth

    role = "ent022_runtime_" + secrets.token_hex(6)
    password = secrets.token_urlsafe(24)
    owner = create_engine(OWNER_URL)
    with owner.begin() as conn:
        conn.execute(text(f'CREATE ROLE "{role}" LOGIN PASSWORD \'{password}\' NOSUPERUSER NOBYPASSRLS'))
        conn.execute(text("DROP SCHEMA IF EXISTS ent022_mfa CASCADE"))
        conn.execute(text(f'CREATE SCHEMA ent022_mfa AUTHORIZATION "{role}"'))
        conn.execute(text("SET LOCAL search_path TO ent022_mfa, pg_catalog"))
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
                execution_token_used_at TIMESTAMP, execution_expires_at TIMESTAMP
            );
            CREATE TABLE approval_audit_events (
                id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, approval_id VARCHAR(100),
                request_id VARCHAR(100), action VARCHAR(50) NOT NULL, actor VARCHAR(255),
                comment TEXT, mfa_verified BOOLEAN DEFAULT FALSE, reason VARCHAR(100),
                metadata TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
        conn.execute(text(f'GRANT USAGE ON SCHEMA ent022_mfa TO "{role}"'))
        conn.execute(text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ent022_mfa TO "{role}"'))
        conn.execute(text(f'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ent022_mfa TO "{role}"'))

    runtime_url = make_url(OWNER_URL).set(username=role, password=password)
    tenant_one = _tenant_engine(runtime_url, 1)
    tenant_two = _tenant_engine(runtime_url, 2)
    now_utc = datetime.now(timezone.utc)
    now = now_utc.replace(tzinfo=None)
    record = {
        "approval_id": "approval-postgres-17", "request_id": "request-postgres-17",
        "correlation_id": "correlation-postgres-17", "tenant_id": 1, "status": "pending",
        "requested_by": "backend-requester-uuid", "created_at": now,
        "expires_at": now + timedelta(minutes=30), "requested_action": "delete",
        "query": "delete sensitive records", "risk_level": "HIGH", "reason": "high_risk",
        "comments": [], "metadata": {},
    }
    try:
        monkeypatch.setattr(approval_store, "engine", tenant_one)
        approval_store._persist_record(record)
        body = b"{}"
        headers = {
            "x-authclaw-version": "3", "x-authclaw-timestamp": str(int(now_utc.timestamp())),
            "x-authclaw-nonce": "a" * 32, "x-authclaw-service": "console",
            "x-authclaw-audience": "agent", "x-authclaw-key-id": "v1",
            "x-authclaw-tenant-id": "backend-tenant-uuid",
            "x-authclaw-user-id": "backend-approver-uuid", "x-authclaw-role": "owner",
            "x-authclaw-mfa-verified-at": str(int(now_utc.timestamp())),
            "x-authclaw-mfa-operation": "POST /approve/approval-postgres-17",
            "x-authclaw-mfa-body-sha256": hashlib.sha256(body).hexdigest(),
            "x-authclaw-mfa-assertion-id": "b" * 32, "content-type": "application/json",
        }
        key = {"secret": "test-only-32-byte-signing-secret!!", "service": "console",
               "audience": "agent", "endpoints": ["POST /approve/*", "POST /execute/*"]}
        headers["x-authclaw-signature"] = control_plane_auth.sign_control_plane_request(
            key["secret"], headers, "POST", "/approve/approval-postgres-17", body=body
        )
        principal = control_plane_auth.verify_control_plane_request(
            headers, "POST", "/approve/approval-postgres-17", {"keys": {"v1": key}},
            lambda *_: True, body=body, now=now_utc.timestamp(),
        )
        identity = {
            "auth_source": "control_plane", "tenant_id": 1, "sub": principal.user_id,
            "mfa_assertion_id": principal.mfa_assertion_id,
            "mfa_operation": principal.mfa_operation,
        }
        verified, binding, counter = main._verify_approval_stage_mfa(
            record, identity, {}, "approval", record["expires_at"].isoformat()
        )
        approved = approval_store.approve_approval_atomic(
            record, approver=principal.user_id, approved_at=now, mfa_verified=verified,
            mfa_binding_hash=binding, mfa_counter=counter,
            execution_expires_at=now + timedelta(minutes=10),
        )
        identity.update({
            "mfa_assertion_id": "c" * 32,
            "mfa_operation": "POST /execute/approval-postgres-17",
        })
        verified, binding, counter = main._verify_approval_stage_mfa(
            approved, identity, {}, "execution", (now + timedelta(minutes=10)).isoformat()
        )
        executing = approval_store.begin_approval_execution_atomic(
            approved, actor=principal.user_id, transition_at=now + timedelta(seconds=1),
            execution_token_hash="d" * 64, mfa_binding_hash=binding, mfa_counter=counter,
        )
        completed = approval_store.finish_approval_execution_atomic(
            executing, actor=principal.user_id, final_status="executed",
            transition_at=now + timedelta(seconds=2), mfa_verified=verified,
        )
        assert completed["status"] == "executed"
        with tenant_one.connect() as conn:
            assert conn.execute(text("SELECT array_agg(action ORDER BY id) FROM approval_audit_events")).scalar() == ["approved", "executing", "executed"]
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
        tenant_one.dispose()
        tenant_two.dispose()
        with owner.begin() as conn:
            conn.execute(text("DROP SCHEMA IF EXISTS ent022_mfa CASCADE"))
            conn.execute(text(f'DROP ROLE IF EXISTS "{role}"'))
        owner.dispose()

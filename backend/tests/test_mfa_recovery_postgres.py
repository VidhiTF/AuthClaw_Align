"""Recovery contract through real credential binding, restricted PostgreSQL/RLS and Redis."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
from threading import Event
from time import monotonic, sleep
from types import SimpleNamespace
from uuid import uuid4

import pyotp
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.api.v1.endpoints import apikeys, auth, users
from app.core import auth as authentication
from app.db.dependencies import get_db
from app.db import session as database_session
from app.db.models import APIKey, AuditOutbox, User
from app.schemas.models import APIKeyCreate, APIKeyRevoke, APIKeyRotate
from tests.test_t10_postgres import postgres, reviewer


def request_for(identity, kind="session", credential_hash=None):
    return SimpleNamespace(state=SimpleNamespace(
        tenant_id=identity.tenant_id, user_id=identity.user_id,
        credential_kind=kind, credential_hash=credential_hash or identity.session_hash),
        headers={"x-request-id": uuid4().hex})


@pytest.fixture
def recovery_case(postgres, monkeypatch):
    harness, _, _ = postgres
    owner = harness.create_identity("recovery-owner")
    target = reviewer(harness, owner)
    outsider = harness.create_identity("other-tenant")
    secrets = {}
    tokens = {}
    keys = {}
    for identity in (owner, target, outsider):
        token = "acl_session_" + uuid4().hex
        tokens[identity.user_id] = token
        with harness.owner_engine.begin() as conn:
            conn.execute(text("UPDATE users SET role='owner' WHERE id=:id"), {"id": identity.user_id})
            conn.execute(text("""SELECT authn.create_session(:hash,:tenant,:user,
                'recovery-test',now()+interval '10 minutes','{}'::jsonb)"""),
                {"hash": authentication.hash_key(token), "tenant": identity.tenant_id, "user": identity.user_id})
        with harness.session_for(identity) as db:
            secret = pyotp.random_base32()
            secrets[identity.user_id] = secret
            authentication.set_mfa_credentials(db.get(User, identity.user_id), secret, [])
            raw_key = "ak_" + uuid4().hex
            keys[identity.user_id] = raw_key
            db.add(APIKey(id=uuid4(), tenant_id=identity.tenant_id,
                         created_by=identity.user_id, name="recovery-regression",
                         key_hash=authentication.hash_key(raw_key), scopes=["admin"], is_active=True))
            db.commit()

    monkeypatch.setattr(authentication, "SessionLocal", harness.testing_session_local)
    monkeypatch.setattr(database_session, "SessionLocal", harness.testing_session_local)
    app = FastAPI()
    app.add_middleware(authentication.AuthMiddleware)
    app.include_router(users.router, prefix="/v1/users")
    app.include_router(auth.router, prefix="/v1/auth")
    app.include_router(apikeys.router, prefix="/v1/apikeys")

    def database():
        with harness.testing_session_local() as db:
            yield db

    app.dependency_overrides[get_db] = database
    with TestClient(app) as client:
        yield SimpleNamespace(harness=harness, owner=owner, target=target, outsider=outsider,
                              secrets=secrets, tokens=tokens, keys=keys, client=client)


def headers(token):
    return {"Authorization": f"Bearer {token}"}


def reset(case):
    return case.client.post(f"/v1/users/{case.target.user_id}/mfa/reset",
        headers=headers(case.tokens[case.owner.user_id]),
        json={"code": pyotp.TOTP(case.secrets[case.owner.user_id]).now()})


def test_api_keys_cannot_manage_factors_and_recovery_revokes_only_target(recovery_case, tmp_path):
    case = recovery_case
    target, owner = case.target, case.owner
    paths = ["/v1/users/me/mfa/setup", "/v1/users/me/mfa/confirm",
             "/v1/users/me/mfa/disable", "/v1/users/me/mfa/recovery-codes",
             f"/v1/users/{owner.user_id}/mfa/reset", "/v1/auth/mfa/agent-assertion"]
    for path in paths:
        payload = {"code": pyotp.TOTP(case.secrets[target.user_id]).now()}
        if path.endswith("agent-assertion"):
            payload.update(method="POST", path="/approve/test", body_sha256="a" * 64)
        response = case.client.post(path, headers=headers(case.keys[target.user_id]), json=payload)
        assert response.status_code == 403, response.text
        assert response.json()["detail"] == "Interactive tenant session required"
    assert reset(case).status_code == 200
    for credential in (case.keys[target.user_id], case.tokens[target.user_id]):
        for path in paths[:2]:
            response = case.client.post(path, headers=headers(credential), json={"code": "654321"})
            assert response.status_code == 401, response.text

    with case.harness.session_for(owner) as db:
        user = db.get(User, target.user_id)
        assert not user.mfa_enabled and user.mfa_secret is None
        revoked = db.query(APIKey).filter(APIKey.created_by == target.user_id).one()
        assert not revoked.is_active and revoked.revoked_at is not None
        assert db.query(APIKey).filter(APIKey.created_by == owner.user_id).one().is_active
        assert db.query(APIKey).filter(APIKey.tenant_id == case.outsider.tenant_id).count() == 0
        events = [row.event_payload for row in db.query(AuditOutbox).all()]
        recovery = [item for item in events if item.get("action") == "mfa:recovery_reset"]
        assert len(recovery) == 1
        assert recovery[0]["actor_id"] == str(owner.user_id)
        assert f"subject_id:{target.user_id}" in recovery[0]["execution_trace"]
        assert all(secret not in str(events) for secret in case.secrets.values())
    evidence_dir = Path(os.getenv("ENT022_EVIDENCE_DIR", str(tmp_path)))
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "backend-recovery-audit.json").write_text(
        json.dumps(recovery, indent=2, default=str), encoding="utf-8")
    for identity in (owner, case.outsider):
        assert case.client.get("/v1/users/me/security", headers=headers(case.keys[identity.user_id])).status_code == 200
    cross_tenant = case.client.post(f"/v1/users/{case.outsider.user_id}/mfa/reset",
        headers=headers(case.tokens[owner.user_id]), json={"code": "654321"})
    assert cross_tenant.status_code == 404

    # A newly authenticated interactive session can recover normal operation.
    token = "acl_session_" + uuid4().hex
    with case.harness.owner_engine.begin() as conn:
        conn.execute(text("""SELECT authn.create_session(:hash,:tenant,:user,
            'fresh-interactive-login',now()+interval '10 minutes','{}'::jsonb)"""),
            {"hash": authentication.hash_key(token), "tenant": target.tenant_id, "user": target.user_id})
    setup = case.client.post(paths[0], headers=headers(token))
    assert setup.status_code == 200, setup.text
    confirmed = case.client.post(paths[1], headers=headers(token),
        json={"code": pyotp.TOTP(setup.json()["mfa_secret"]).now()})
    assert confirmed.status_code == 200, confirmed.text
    rotated = case.client.post(paths[3], headers=headers(token),
        json={"code": setup.json()["backup_codes"][0]})
    assert rotated.status_code == 200, rotated.text
    issued = case.client.post(paths[5], headers=headers(token), json={
        "code": rotated.json()["backup_codes"][0], "method": "POST", "path": "/approve/test",
        "body_sha256": "a" * 64})
    assert issued.status_code == 200, issued.text


def test_recovery_audit_failure_rolls_back_credentials(recovery_case, monkeypatch):
    case = recovery_case
    # Fail the real SQL outbox append rather than replace the commit helper.
    from app.services import audit_store
    def unavailable(db, _event):
        db.execute(text("SELECT * FROM ent022_missing_audit_table"))
    monkeypatch.setattr(audit_store, "append_audit_event", unavailable)
    assert reset(case).status_code == 503
    with case.harness.session_for(case.target) as db:
        assert db.get(User, case.target.user_id).mfa_enabled
        assert db.query(APIKey).filter(APIKey.created_by == case.target.user_id).one().is_active
    for credential in (case.tokens[case.target.user_id], case.keys[case.target.user_id]):
        assert case.client.get("/v1/users/me/security", headers=headers(credential)).status_code == 200


@pytest.mark.parametrize("operation,kind", [
    ("setup", "session"), ("assertion", "session"),
    ("issue", "session"), ("rotate", "session"),
])
def test_recovery_rejects_pre_authenticated_requests_after_lock(recovery_case, operation, kind, monkeypatch):
    case = recovery_case
    target = case.target
    credential_hash = target.session_hash if kind == "session" else authentication.hash_key(case.keys[target.user_id])
    request = request_for(target, kind, credential_hash)
    ready, proceed = Event(), Event()
    worker = {}
    original_audit = users._commit_mfa_audit

    def audit_after_waiter_blocks(*args, **kwargs):
        if kwargs.get("action") == "recovery_reset":
            # Recovery holds the actor/target locks and has revoked credentials
            # without committing. Resume the old request and observe its actual
            # PostgreSQL lock wait before allowing recovery to commit.
            proceed.set()
            deadline = monotonic() + 5
            with case.harness.owner_engine.connect() as connection:
                while monotonic() < deadline:
                    blocked = connection.execute(text(
                        "SELECT cardinality(pg_blocking_pids(:pid)) > 0"), worker).scalar_one()
                    if blocked:
                        break
                    sleep(0.01)
                assert blocked, "Pre-authenticated request never waited on recovery's lock"
        return original_audit(*args, **kwargs)

    monkeypatch.setattr(users, "_commit_mfa_audit", audit_after_waiter_blocks)

    def pending_request():
        with case.harness.session_for(target) as db:
            authentication.revalidate_tenant_credential(request, db)
            worker["pid"] = db.execute(text("SELECT pg_backend_pid()")).scalar_one()
            with case.harness.owner_engine.connect() as connection:
                key_id = connection.execute(text("SELECT id FROM api_keys WHERE created_by=:id"), {"id": target.user_id}).scalar_one()
            ready.set()
            assert proceed.wait(10)
            try:
                if operation == "setup":
                    users.setup_my_mfa(request, None, db)
                elif operation == "assertion":
                    auth.create_agent_mfa_assertion(auth.AgentMFAAssertionRequest(
                        code=pyotp.TOTP(case.secrets[target.user_id]).now(), method="POST",
                        path="/approve/test", body_sha256="a" * 64), request, db)
                elif operation == "issue":
                    apikeys.generate_api_key(
                        request,
                        APIKeyCreate(
                            name="racing-key", scopes=["read"],
                            mfa_code=pyotp.TOTP(case.secrets[target.user_id]).now(),
                        ),
                        db,
                    )
                else:
                    apikeys.rotate_api_key(
                        key_id,
                        request,
                        APIKeyRotate(mfa_code=pyotp.TOTP(case.secrets[target.user_id]).now()),
                        db,
                    )
            except HTTPException as exc:
                return exc.status_code
            return 200

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(pending_request)
        assert ready.wait(10)
        try:
            assert reset(case).status_code == 200
        finally:
            proceed.set()
        assert future.result(timeout=15) == 401
    with case.harness.session_for(case.owner) as db:
        assert db.query(APIKey).filter(APIKey.created_by == target.user_id, APIKey.is_active.is_(True)).count() == 0
        assert db.get(User, target.user_id).mfa_pending_secret is None


@pytest.mark.parametrize("operation", ["issue", "rotate", "revoke"])
def test_api_key_credentials_cannot_administer_api_keys(recovery_case, operation):
    case = recovery_case
    target = case.target
    request = request_for(
        target,
        "api_key",
        authentication.hash_key(case.keys[target.user_id]),
    )
    with case.harness.session_for(target) as db:
        key = db.query(APIKey).filter(APIKey.created_by == target.user_id).one()
        with pytest.raises(HTTPException, match="Interactive tenant session") as exc:
            if operation == "issue":
                apikeys.generate_api_key(
                    request,
                    APIKeyCreate(name="denied-key", scopes=["read"], mfa_code="654321"),
                    db,
                )
            elif operation == "rotate":
                apikeys.rotate_api_key(
                    key.id,
                    request,
                    APIKeyRotate(mfa_code="654321"),
                    db,
                )
            else:
                apikeys.revoke_api_key(
                    key.id,
                    request,
                    APIKeyRevoke(mfa_code="654321"),
                    db,
                )
        assert exc.value.status_code == 403
        assert db.query(APIKey).filter(APIKey.created_by == target.user_id).count() == 1
        assert key.is_active

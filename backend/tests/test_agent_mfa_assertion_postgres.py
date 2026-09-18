"""Real backend factor -> console signer -> agent HTTP/Redis/PostgreSQL proof.

The agent runs in its own interpreter so each service keeps its dependency pins.
Only assertion metadata crosses this process boundary; no factor material does.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from types import SimpleNamespace

import pyotp
import pytest
from fastapi import HTTPException

from app.api.v1.endpoints import auth
from app.core.auth import set_mfa_credentials
from app.db.models import AuditOutbox, User
from app.db import session as database_session
from tests.test_t10_postgres import postgres  # Reuse migrated, authenticated RLS harness.


def test_backend_totp_assertions_complete_signed_agent_actions(postgres, monkeypatch, tmp_path):
    harness, _, _ = postgres
    identity = harness.create_identity("ent022-agent-actor")
    other_tenant = harness.create_identity("ent022-other-tenant")
    secret = pyotp.random_base32()
    monkeypatch.setattr(database_session, "SessionLocal", harness.testing_session_local)
    with harness.session_for(identity) as db:
        user = db.get(User, identity.user_id)
        role = user.role
        set_mfa_credentials(user, secret, [])
        db.commit()

    request = SimpleNamespace(
        state=SimpleNamespace(user_id=identity.user_id, tenant_id=identity.tenant_id,
                              credential_kind="session", credential_hash=identity.session_hash),
        headers={"x-request-id": "ent022-cross-service"},
    )
    bundle = {"actor": str(identity.user_id), "tenant": str(identity.tenant_id), "role": role}
    now = int(time.time())
    for stage, offset in (("approve", 0), ("execute", 30)):
        # Current and next-window OTPs exercise the real verifier without sleeps.
        code = pyotp.TOTP(secret).at(now + offset)
        payload = auth.AgentMFAAssertionRequest(
            code=code, method="POST", path=f"/{stage}/approval-postgres-17",
            body_sha256=hashlib.sha256(b"{}").hexdigest(),
        )
        with harness.session_for(identity) as db:
            bundle[stage] = auth.create_agent_mfa_assertion(payload, request, db).model_dump()
        with harness.session_for(identity) as db:
            with pytest.raises(HTTPException) as replay:
                auth.create_agent_mfa_assertion(payload, request, db)
            assert replay.value.status_code == 400

    with harness.session_for(identity) as db:
        user = db.get(User, identity.user_id)
        assert user.mfa_secret != secret
        events = [row.event_payload for row in db.query(AuditOutbox).all()
                  if row.event_payload.get("action") == "mfa:agent_assertion_issued"]
        assert len(events) == 2
        assert all(event["actor_id"] == str(identity.user_id) for event in events)
        assert secret not in json.dumps(events)
        assert code not in json.dumps(events)
    with harness.session_for(other_tenant) as db:
        assert db.get(User, identity.user_id) is None
        assert db.query(AuditOutbox).filter(AuditOutbox.tenant_id == identity.tenant_id).count() == 0

    evidence_dir = Path(os.getenv("ENT022_EVIDENCE_DIR", str(tmp_path)))
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "backend-assertion-audit.json").write_text(
        json.dumps(events, indent=2, default=str), encoding="utf-8",
    )
    bundle_file = tmp_path / "assertions.json"
    bundle_file.write_text(json.dumps(bundle), encoding="utf-8")
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run([
        os.environ["ENT022_AGENT_PYTHON"], "-m", "pytest", "--noconftest", "-p", "no:cacheprovider",
        "smoke_tests/test_control_plane_mfa_postgres.py", "-k", "signed_control_plane", "-q",
    ], cwd=root / "services/agent", capture_output=True, text=True, timeout=90,
        env={**os.environ, "ENT022_ASSERTION_BUNDLE": str(bundle_file),
             "ENT022_EVIDENCE_DIR": str(evidence_dir),
             # The services pin different PostgreSQL drivers in CI.
             "DATABASE_URL": os.environ["ENT022_AGENT_POSTGRES_URL"],
             "MIGRATION_DATABASE_URL": os.environ["ENT022_AGENT_POSTGRES_URL"],
             "PYTHONPATH": str(root / "services/agent"),
             "AUTHCLAW_ENV": "test"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "3 passed" in result.stdout, result.stdout

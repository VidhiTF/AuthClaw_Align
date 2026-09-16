import base64
import json
import hashlib
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.services import audit_export, trust_center
from tests.test_audit_export import _artifact, _chain, _trusted_registry


@pytest.mark.parametrize("environment", ["prod", " PROD ", "production", "staging"])
def test_shared_signing_never_uses_development_key(monkeypatch, environment):
    monkeypatch.setenv("AUTHCLAW_ENV", environment)
    for name in ("AUDIT_EXPORT_SIGNING_PRIVATE_KEY", "AUDIT_EXPORT_SIGNING_PRIVATE_KEY_PEM", "AUDIT_EXPORT_TRUSTED_KEYS_JSON"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(RuntimeError):
        audit_export.signing_key_metadata()
    assert audit_export.trusted_signing_keys_from_env() == {}


def test_scoped_export_hides_intervening_payload_and_verifies(monkeypatch):
    monkeypatch.setenv("AUTHCLAW_ENV", "test")
    records = _chain(str(uuid4()), ("allow", "block", "allow"))
    records[1].update(frameworks_affected=["HIPAA"], reason="private HIPAA detail")
    records[1]["canonical_payload"] = json.dumps({"reason": "private HIPAA detail", "frameworks_affected": ["HIPAA"]})
    for index, record in enumerate(records):
        record["prior_hash"] = records[index - 1]["integrity_hash"] if index else "GENESIS"
        record["integrity_hash"] = hashlib.sha256((record["canonical_payload"] + record["prior_hash"]).encode()).hexdigest()
    monkeypatch.setattr(audit_export, "get_postgres_records", lambda *_: records)
    share = SimpleNamespace(tenant_id=records[0]["tenant_id"], frameworks=["SOC2"])
    artifact = trust_center.build_share_export(object(), share, framework="SOC2")
    serialized = json.dumps(artifact)
    assert "private HIPAA detail" not in serialized and "HIPAA" not in serialized
    assert artifact["records"][1]["proof_only"] is True
    assert "canonical_payload" not in artifact["records"][1]
    assert audit_export.verify_signed_audit_export(artifact, trusted_keys=_trusted_registry()).verified
    assert not audit_export.verify_signed_audit_export(artifact, trusted_keys={}).verified
    artifact["records"][1]["integrity_hash"] = "0" * 64
    assert not audit_export.verify_signed_audit_export(artifact, trusted_keys=_trusted_registry()).verified


def test_otp_refreshes_locked_state_before_checking(monkeypatch):
    monkeypatch.setenv("SESSION_SECRET", "test-secret-32-bytes-for-trust-center")
    share = SimpleNamespace(id=uuid4(), tenant_id=uuid4(), auditor_email="a@example.com", metadata_json={}, status="active", revoked_at=None, expires_at=trust_center.now_utc() + timedelta(days=1))
    stale = {"auditor_otp_hash": trust_center._auditor_otp_hash(share, "123456"), "auditor_otp_expires_at": (trust_center.now_utc() + timedelta(minutes=5)).isoformat()}
    share.metadata_json = stale
    def refresh(row, *, with_for_update):
        assert with_for_update is True
        row.metadata_json = {}  # Another transaction has consumed the code.
    db = SimpleNamespace(refresh=refresh, commit=lambda: pytest.fail("Consumed OTP must not issue access"))
    with pytest.raises(ValueError, match="missing or expired"):
        trust_center.verify_auditor_otp(db, share, "share", "123456")


def test_auditor_limits_block_before_database_access(monkeypatch):
    from fastapi import HTTPException
    from app.api.v1.endpoints import onboarding, trust_center as endpoint
    def limited(*_):
        raise HTTPException(429, "limited")
    monkeypatch.setattr(onboarding, "_enforce_onboarding_rate_limit", limited)
    request = SimpleNamespace(client=SimpleNamespace(host="192.0.2.1"))
    with pytest.raises(HTTPException) as error:
        endpoint.verify_public_trust_center_access("share", endpoint.TrustCenterAccessVerifyRequest(otp="123456"), request, object())
    assert error.value.status_code == 429


@pytest.mark.parametrize("index", [0, 1, 2])
@pytest.mark.parametrize("field,value", [
    *[(field, "missing") for field in sorted(audit_export.PROOF_FIELDS)],
    ("tenant_sequence", None), ("tenant_sequence", "2"), ("tenant_sequence", True),
    ("tenant_sequence", 0), ("tenant_sequence", -1), ("record_id", {}), ("tenant_id", None),
    ("prior_hash", []), ("prior_hash", "z" * 64), ("integrity_hash", 10**63),
    ("integrity_hash", "z" * 64), ("proof_only", "true"), ("proof_only", False),
    ("proof_only", None), ("extra", "payload"),
])
def test_malformed_signed_proofs_return_invalid_chain(monkeypatch, index, field, value):
    artifact, _, trusted = _artifact(monkeypatch, actions=("allow",) * 3, framework="SOC2")
    proof = {key: artifact["records"][index][key] for key in audit_export.PROOF_FIELDS}
    proof["proof_only"] = True
    if value == "missing":
        proof.pop(field)
    else:
        proof[field] = value
    artifact["records"][index] = proof
    body = audit_export._canonical_bytes({key: artifact[key] for key in ("manifest", "records")})
    artifact["digest"]["value"] = hashlib.sha256(body).hexdigest()
    artifact["signature"]["value"] = base64.b64encode(audit_export._private_key_from_env().sign(body)).decode()
    result = audit_export.verify_signed_audit_export(artifact, trusted_keys=trusted)
    assert result.signature_valid and result.digest_valid
    assert not result.verified and not result.chain_valid
    assert any("invalid opaque proof" in error for error in result.errors)


@pytest.mark.parametrize("export_format", [audit_export.EXPORT_FORMAT, audit_export.SCOPED_EXPORT_FORMAT])
def test_public_verifier_rejects_incomplete_proof_without_http_500(monkeypatch, export_format):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.api.v1.endpoints.trust_center import router
    monkeypatch.setenv("AUTHCLAW_ENV", "test")
    app = FastAPI()
    app.include_router(router, prefix="/v1/trust-center")
    response = TestClient(app).post("/v1/trust-center/public/verify", json={
        "artifact": {"format": export_format, "manifest": {}, "records": [{"proof_only": True}]},
    })
    assert response.status_code == 200
    assert response.json()["verified"] is False


@pytest.mark.parametrize("field", ["selection", "filters"])
@pytest.mark.parametrize("value", [None, [], ["SOC2"], "SOC2"])
def test_scoped_verifier_rejects_invalid_selection_objects(monkeypatch, field, value):
    artifact, _, trusted = _artifact(monkeypatch, framework="SOC2")
    if field == "selection":
        artifact["manifest"]["selection"] = value
    else:
        artifact["manifest"]["selection"]["filters"] = value
    body = audit_export._canonical_bytes({key: artifact[key] for key in ("manifest", "records")})
    artifact["digest"]["value"] = hashlib.sha256(body).hexdigest()
    artifact["signature"]["value"] = base64.b64encode(audit_export._private_key_from_env().sign(body)).decode()
    result = audit_export.verify_signed_audit_export(artifact, trusted_keys=trusted)
    assert result.signature_valid and result.digest_valid
    assert not result.verified
    assert any("must be a JSON object" in error for error in result.errors)

from datetime import datetime, timezone
from uuid import uuid4

from app.services import audit_export
from app.services.audit_store import compute_integrity_hash


def _record(*, tenant_id: str, prior_hash: str = "GENESIS", action: str = "allow"):
    row = {
        "record_id": str(uuid4()),
        "tenant_id": tenant_id,
        "timestamp": datetime(2026, 7, 1, 1, 2, 3, tzinfo=timezone.utc),
        "actor_id": "",
        "actor_type": "gateway",
        "action": action,
        "policy_id": "",
        "provider": "openai",
        "model": "gpt-4o-mini",
        "reason": "Allowed",
        "prompt_count": 1,
        "request_size": 42,
        "response_status": 200,
        "duration_ms": 12,
        "frameworks_affected": ["SOC2"],
        "execution_trace": '["proxy"]',
        "request_id": "req-1",
        "prior_hash": prior_hash,
        "integrity_hash": "",
    }
    row["integrity_hash"] = compute_integrity_hash(row, prior_hash)
    return row


def test_signed_audit_export_verifies(monkeypatch):
    tenant_id = str(uuid4())
    first = _record(tenant_id=tenant_id)
    second = _record(tenant_id=tenant_id, prior_hash=first["integrity_hash"])
    monkeypatch.setenv("AUDIT_EXPORT_DEV_SIGNING_SEED", "test-signing-seed")
    monkeypatch.setattr(audit_export, "get_postgres_records", lambda _db, _tenant: [first, second])

    artifact = audit_export.build_signed_audit_export(object(), tenant_id=tenant_id, requested_by="user-1")
    result = audit_export.verify_signed_audit_export(artifact)

    assert result.verified is True
    assert result.signature_valid is True
    assert result.digest_valid is True
    assert result.chain_valid is True
    assert result.record_count == 2
    assert artifact["signature"]["public_key"]


def test_signed_audit_export_detects_payload_tamper(monkeypatch):
    tenant_id = str(uuid4())
    record = _record(tenant_id=tenant_id)
    monkeypatch.setenv("AUDIT_EXPORT_DEV_SIGNING_SEED", "test-signing-seed")
    monkeypatch.setattr(audit_export, "get_postgres_records", lambda _db, _tenant: [record])

    artifact = audit_export.build_signed_audit_export(object(), tenant_id=tenant_id)
    artifact["payload"]["records"][0]["action"] = "block"
    result = audit_export.verify_signed_audit_export(artifact)

    assert result.verified is False
    assert result.signature_valid is False
    assert result.digest_valid is False
    assert result.chain_valid is False


def test_signed_audit_export_detects_chain_gap(monkeypatch):
    tenant_id = str(uuid4())
    first = _record(tenant_id=tenant_id)
    second = _record(tenant_id=tenant_id, prior_hash="not-the-previous-hash")
    monkeypatch.setenv("AUDIT_EXPORT_DEV_SIGNING_SEED", "test-signing-seed")
    monkeypatch.setattr(audit_export, "get_postgres_records", lambda _db, _tenant: [first, second])

    artifact = audit_export.build_signed_audit_export(object(), tenant_id=tenant_id)
    result = audit_export.verify_signed_audit_export(artifact)

    assert result.verified is False
    assert result.signature_valid is True
    assert result.digest_valid is True
    assert result.chain_valid is False
    assert any("prior_hash mismatch" in error for error in result.errors)

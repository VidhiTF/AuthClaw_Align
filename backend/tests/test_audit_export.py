import base64
import copy
import hashlib
import json
from datetime import datetime, timezone
from uuid import uuid4

from app.services import audit_export


def _record(*, tenant_id, sequence, prior_hash="GENESIS", action="allow"):
    record_id = str(uuid4())
    canonical_payload = json.dumps(
        {
            "record_id": record_id,
            "tenant_id": tenant_id,
            "tenant_sequence": sequence,
            "chain_version": 2,
            "action": action,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    integrity_hash = hashlib.sha256(
        (canonical_payload + prior_hash).encode()
    ).hexdigest()
    return {
        "record_id": record_id,
        "tenant_id": tenant_id,
        "tenant_sequence": sequence,
        "idempotency_key": f"event:{record_id}",
        "chain_version": 2,
        "canonical_payload": canonical_payload,
        "timestamp": datetime(2026, 7, 1, 1, 2, sequence, tzinfo=timezone.utc),
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
        "integrity_hash": integrity_hash,
    }


def _chain(tenant_id, actions=("allow", "allow")):
    records = []
    prior_hash = "GENESIS"
    for sequence, action in enumerate(actions, 1):
        record = _record(
            tenant_id=tenant_id,
            sequence=sequence,
            prior_hash=prior_hash,
            action=action,
        )
        records.append(record)
        prior_hash = record["integrity_hash"]
    return records


def _trusted_registry():
    metadata = audit_export.signing_key_metadata()
    return {
        metadata["key_id"]: {
            "public_key": metadata["public_key"],
            "status": "active",
        }
    }


def _artifact(monkeypatch, actions=("allow", "allow"), **filters):
    monkeypatch.setenv("AUTHCLAW_ENV", "test")
    tenant_id = str(uuid4())
    records = _chain(tenant_id, actions)
    monkeypatch.setenv("AUDIT_EXPORT_DEV_SIGNING_SEED", "trusted-export-key")
    monkeypatch.delenv("AUDIT_EXPORT_SIGNING_KEY_ID", raising=False)
    monkeypatch.setattr(
        audit_export,
        "get_postgres_records",
        lambda _db, _tenant: records,
    )
    artifact = audit_export.build_signed_audit_export(
        object(),
        tenant_id=tenant_id,
        **filters,
    )
    return artifact, records, _trusted_registry()


def test_export_v2_verifies_with_separately_pinned_key(monkeypatch):
    artifact, records, trusted = _artifact(monkeypatch)

    result = audit_export.verify_signed_audit_export(
        artifact,
        trusted_keys=trusted,
    )

    assert result.verified is True
    assert artifact["manifest"]["record_count"] == 2
    assert artifact["manifest"]["sequence_range"] == {"start": 1, "end": 2}
    assert artifact["manifest"]["starting_anchor"] == "GENESIS"
    assert artifact["manifest"]["final_chain_root"] == records[-1]["integrity_hash"]
    assert "public_key" not in artifact["signature"]


def test_wrong_trusted_key_rejects_valid_artifact(monkeypatch):
    artifact, _, _ = _artifact(monkeypatch)
    key_id = artifact["signature"]["key_id"]
    wrong_key = base64.b64encode(bytes(range(32))).decode()

    result = audit_export.verify_signed_audit_export(
        artifact,
        trusted_keys={key_id: wrong_key},
    )

    assert result.verified is False
    assert result.signature_valid is False


def test_attacker_resigned_artifact_is_not_trusted(monkeypatch):
    artifact, _, trusted = _artifact(monkeypatch)
    monkeypatch.setenv("AUDIT_EXPORT_DEV_SIGNING_SEED", "attacker-key")
    tenant_id = artifact["manifest"]["tenant_id"]
    attacker = audit_export.build_signed_audit_export(object(), tenant_id=tenant_id)

    result = audit_export.verify_signed_audit_export(
        attacker,
        trusted_keys=trusted,
    )

    assert result.verified is False
    assert any("unknown signing key ID" in error for error in result.errors)


def test_key_rotation_accepts_each_active_pinned_key(monkeypatch):
    old_artifact, _, old_registry = _artifact(monkeypatch)
    monkeypatch.setenv("AUDIT_EXPORT_DEV_SIGNING_SEED", "rotated-key")
    new_artifact = audit_export.build_signed_audit_export(
        object(),
        tenant_id=old_artifact["manifest"]["tenant_id"],
    )
    new_registry = _trusted_registry()
    registry = {**old_registry, **new_registry}

    assert audit_export.verify_signed_audit_export(
        old_artifact,
        trusted_keys=registry,
    ).verified
    assert audit_export.verify_signed_audit_export(
        new_artifact,
        trusted_keys=registry,
    ).verified


def test_unknown_and_revoked_key_ids_are_rejected(monkeypatch):
    artifact, _, trusted = _artifact(monkeypatch)
    key_id = artifact["signature"]["key_id"]

    unknown = audit_export.verify_signed_audit_export(
        artifact,
        trusted_keys={},
    )
    revoked_registry = copy.deepcopy(trusted)
    revoked_registry[key_id]["status"] = "revoked"
    revoked = audit_export.verify_signed_audit_export(
        artifact,
        trusted_keys=revoked_registry,
    )

    assert not unknown.verified
    assert not revoked.verified
    assert any("revoked" in error for error in revoked.errors)


def test_manifest_record_and_signature_tampering_are_detected(monkeypatch):
    artifact, _, trusted = _artifact(monkeypatch)
    variants = []
    manifest_tamper = copy.deepcopy(artifact)
    manifest_tamper["manifest"]["record_count"] = 999
    variants.append(manifest_tamper)
    record_tamper = copy.deepcopy(artifact)
    record_tamper["records"][0]["action"] = "block"
    variants.append(record_tamper)
    signature_tamper = copy.deepcopy(artifact)
    signature_tamper["signature"]["value"] = base64.b64encode(b"x" * 64).decode()
    variants.append(signature_tamper)

    for variant in variants:
        assert not audit_export.verify_signed_audit_export(
            variant,
            trusted_keys=trusted,
        ).verified


def test_filtered_export_retains_intermediate_proof_records(monkeypatch):
    artifact, records, trusted = _artifact(
        monkeypatch,
        actions=("allow", "block", "allow"),
        action="allow",
    )

    manifest = artifact["manifest"]
    assert [row["record_id"] for row in artifact["records"]] == [
        row["record_id"] for row in records
    ]
    assert manifest["selection"]["selected_record_ids"] == [
        records[0]["record_id"],
        records[2]["record_id"],
    ]
    assert manifest["selection"]["proof_records_retained"] == 1
    assert audit_export.verify_signed_audit_export(
        artifact,
        trusted_keys=trusted,
    ).verified


def test_deletion_reordering_duplication_and_cross_tenant_injection_fail(monkeypatch):
    artifact, _, trusted = _artifact(
        monkeypatch,
        actions=("allow", "block", "allow"),
    )
    mutations = []
    for index in (0, 1, 2):
        changed = copy.deepcopy(artifact)
        del changed["records"][index]
        mutations.append(changed)
    reordered = copy.deepcopy(artifact)
    reordered["records"][0], reordered["records"][1] = (
        reordered["records"][1],
        reordered["records"][0],
    )
    mutations.append(reordered)
    duplicated = copy.deepcopy(artifact)
    duplicated["records"].insert(1, copy.deepcopy(duplicated["records"][0]))
    mutations.append(duplicated)
    injected = copy.deepcopy(artifact)
    injected["records"][1]["tenant_id"] = str(uuid4())
    mutations.append(injected)

    for changed in mutations:
        result = audit_export.verify_signed_audit_export(
            changed,
            trusted_keys=trusted,
        )
        assert not result.verified

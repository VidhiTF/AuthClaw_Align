from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID

from app.core.evidence_integrity import compute_evidence_integrity_hash, verify_evidence_integrity


def _record():
    values = {
        "evidence_id": UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
        "tenant_id": UUID("11111111-1111-4111-8111-111111111111"),
        "workflow_id": "acl19-workflow",
        "framework": "SOC2",
        "source_type": "policy_evaluation",
        "source_reference": "SOC2:CC6.1",
        "evidence_type": "scan_result",
        "evidence_data": {"result": "pass", "owner": "Vidhi"},
        "severity": "info",
        "created_at": datetime(2026, 7, 29, 10, 30, tzinfo=timezone.utc),
    }
    integrity_hash = compute_evidence_integrity_hash(**values)
    return values, SimpleNamespace(
        id=values["evidence_id"],
        tenant_id=values["tenant_id"],
        workflow_id=values["workflow_id"],
        framework=values["framework"],
        source_type=values["source_type"],
        source_reference=values["source_reference"],
        evidence_type=values["evidence_type"],
        evidence_data=values["evidence_data"],
        severity=values["severity"],
        created_at=values["created_at"],
        integrity_hash=integrity_hash,
    )


def test_evidence_hash_is_deterministic_and_tenant_bound():
    values, _record_value = _record()

    first = compute_evidence_integrity_hash(**values)
    second = compute_evidence_integrity_hash(**values)
    other_tenant = compute_evidence_integrity_hash(
        **{**values, "tenant_id": UUID("22222222-2222-4222-8222-222222222222")}
    )

    assert first == second
    assert len(first) == 64
    assert first != other_tenant


def test_evidence_integrity_detects_payload_tampering():
    _values, record = _record()

    assert verify_evidence_integrity(record) is True
    record.evidence_data = {"result": "pass", "owner": "tampered"}
    assert verify_evidence_integrity(record) is False

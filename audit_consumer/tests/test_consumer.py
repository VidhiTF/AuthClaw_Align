import hashlib
import json
import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from consumer import (  # noqa: E402
    InvalidAuditEvent,
    RetryableMirrorError,
    SequenceGapError,
    _process_message,
    normalise_event,
)
import consumer  # noqa: E402


TENANT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
RECORD = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def test_metrics_bind_to_loopback_by_default(monkeypatch):
    monkeypatch.delenv("AUDIT_CONSUMER_METRICS_HOST", raising=False)
    assert consumer._metrics_bind_host() == "127.0.0.1"


@pytest.mark.parametrize("password", ["", "authclaw", "AUTHCLAW", "demo-CHANGE-ME"])
def test_shared_environment_rejects_default_clickhouse_password(monkeypatch, password):
    monkeypatch.setenv("AUTHCLAW_ENV", "staging")
    monkeypatch.setenv("CLICKHOUSE_PASSWORD", password)
    with pytest.raises(RuntimeError, match="CLICKHOUSE_PASSWORD"):
        consumer.validate_runtime_environment()


def test_local_environment_allows_explicit_development_default(monkeypatch):
    monkeypatch.setenv("AUTHCLAW_ENV", "development")
    monkeypatch.setenv("CLICKHOUSE_PASSWORD", "authclaw")
    consumer.validate_runtime_environment()


def test_unknown_environment_is_rejected(monkeypatch):
    monkeypatch.setenv("AUTHCLAW_ENV", "production-us")
    monkeypatch.setenv("CLICKHOUSE_PASSWORD", "strong-runtime-secret")
    with pytest.raises(RuntimeError, match="AUTHCLAW_ENV"):
        consumer.validate_runtime_environment()


def event(*, sequence=1, tenant_id=TENANT, record_id=RECORD, prior_hash="GENESIS"):
    canonical_payload = json.dumps(
        {
            "tenant_id": tenant_id,
            "record_id": record_id,
            "tenant_sequence": sequence,
            "chain_version": 2,
            "action": "allow",
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return {
        "id": record_id,
        "tenant_id": tenant_id,
        "tenant_sequence": sequence,
        "idempotency_key": f"request:{record_id}",
        "chain_version": 2,
        "canonical_payload": canonical_payload,
        "timestamp": "2026-07-20T10:00:00.000Z",
        "action": "allow",
        "prior_hash": prior_hash,
        "integrity_hash": hashlib.sha256(
            (canonical_payload + prior_hash).encode()
        ).hexdigest(),
    }


def configure(monkeypatch, *, tail=(0, "GENESIS"), exists=False, inserted=True):
    monkeypatch.setattr("consumer.get_tenant_tail", lambda _client, _tenant: tail)
    monkeypatch.setattr(
        "consumer.audit_event_exists",
        lambda _client, _record: exists,
    )
    insert = MagicMock(return_value=inserted)
    monkeypatch.setattr("consumer.insert_audit_event", insert)
    return insert


def test_normalise_preserves_postgres_proof_fields():
    row = normalise_event(event())
    assert row["tenant_sequence"] == 1
    assert row["chain_version"] == 2
    assert row["canonical_payload"]
    assert row["idempotency_key"].startswith("request:")


def test_valid_postgres_event_is_mirrored_without_rehashing(monkeypatch):
    insert = configure(monkeypatch)
    payload = event()

    _process_message(MagicMock(), payload)

    mirrored = insert.call_args.args[1]
    assert mirrored["integrity_hash"] == payload["integrity_hash"]
    assert mirrored["tenant_sequence"] == 1


def test_sequence_gap_is_retryable_and_not_a_dlq_error(monkeypatch):
    insert = configure(monkeypatch, tail=(1, "hash-1"))
    with pytest.raises(SequenceGapError, match="expects sequence 2"):
        _process_message(MagicMock(), event(sequence=3, prior_hash="hash-2"))
    insert.assert_not_called()


def test_clickhouse_outage_is_retryable(monkeypatch):
    monkeypatch.setattr(
        "consumer.audit_event_exists",
        lambda _client, _record: False,
    )
    monkeypatch.setattr(
        "consumer.get_tenant_tail",
        MagicMock(side_effect=OSError("ClickHouse unavailable")),
    )
    with pytest.raises(RetryableMirrorError, match="tail query failed"):
        _process_message(MagicMock(), event())


def test_cross_tenant_injection_is_rejected(monkeypatch):
    configure(monkeypatch)
    payload = event()
    payload["tenant_id"] = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    with pytest.raises(InvalidAuditEvent, match="identity"):
        _process_message(MagicMock(), payload)


def test_payload_or_hash_tamper_is_rejected(monkeypatch):
    configure(monkeypatch)
    payload = event()
    payload["canonical_payload"] = payload["canonical_payload"].replace(
        '"allow"',
        '"block"',
    )
    with pytest.raises(InvalidAuditEvent, match="integrity hash"):
        _process_message(MagicMock(), payload)


def test_wrong_chain_tail_is_mirror_drift(monkeypatch):
    configure(monkeypatch, tail=(1, "trusted-tail"))
    payload = event(sequence=2, prior_hash="attacker-tail")
    with pytest.raises(InvalidAuditEvent, match="chain tails differ"):
        _process_message(MagicMock(), payload)


def test_exact_duplicate_replay_is_skipped(monkeypatch):
    insert = configure(monkeypatch, exists=True)
    _process_message(MagicMock(), event())
    insert.assert_not_called()

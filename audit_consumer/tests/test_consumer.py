import hashlib
import json
import os
import sys
import types
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
    canonical = {
        "tenant_id": tenant_id,
        "record_id": record_id,
        "tenant_sequence": sequence,
        "chain_version": 2,
        "timestamp": "2026-07-20T10:00:00.000Z",
        "actor_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        "actor_type": "gateway",
        "action": "allow",
        "policy_id": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        "provider": "openai",
        "model": "gpt-test",
        "reason": "policy allowed",
        "prompt_count": 2,
        "request_size": 128,
        "response_status": 200,
        "duration_ms": 37,
        "frameworks_affected": ["SOC2", "HIPAA"],
        "execution_trace": '["policy","provider"]',
        "request_id": "req-verified",
    }
    canonical_payload = json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
    )
    return {
        **canonical,
        "id": record_id,
        "idempotency_key": f"request:{record_id}",
        "canonical_payload": canonical_payload,
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
    assert row["idempotency_key"] == RECORD


@pytest.mark.parametrize(
    "field,tampered",
    [
        ("record_id", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"),
        ("tenant_id", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"),
        ("tenant_sequence", 2),
        ("chain_version", 3),
        ("timestamp", "2026-07-20T10:00:01.000Z"),
        ("actor_id", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"),
        ("actor_type", "backend"),
        ("action", "block"),
        ("policy_id", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"),
        ("provider", "anthropic"),
        ("model", "other-model"),
        ("reason", "tampered"),
        ("prompt_count", 3),
        ("request_size", 129),
        ("response_status", 403),
        ("duration_ms", 38),
        ("frameworks_affected", ["PCI-DSS"]),
        ("execution_trace", '["tampered"]'),
        ("request_id", "req-tampered"),
    ],
)
def test_every_duplicate_canonical_field_mismatch_is_rejected(monkeypatch, field, tampered):
    insert = configure(monkeypatch)
    payload = event()
    payload[field] = tampered
    with pytest.raises(InvalidAuditEvent, match="envelope mismatch"):
        _process_message(MagicMock(), payload)
    insert.assert_not_called()


def test_unverified_transport_idempotency_key_is_not_mirrored():
    payload = event()
    payload["idempotency_key"] = "attacker-controlled"
    row = normalise_event(payload)
    assert row["idempotency_key"] == RECORD


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


@pytest.mark.parametrize("dlq_fails", [False, True])
def test_failed_message_is_acknowledged_only_after_durable_dlq_publish(monkeypatch, dlq_fails):
    from transport import AuditMessage

    first = AuditMessage(value=event(), offset=10, _position="partition-0")
    later = AuditMessage(value=event(sequence=2), offset=11, _position="partition-0")
    transport = MagicMock(redrive_failures=False)
    transport.poll.return_value = [[first, later]]
    if dlq_fails:
        transport.publish_dlq.side_effect = OSError("DLQ unavailable")
    monkeypatch.setattr(consumer, "_running", True)
    monkeypatch.setattr(consumer, "validate_runtime_environment", lambda: None)
    monkeypatch.setattr(consumer, "make_audit_consumer", lambda _observe: transport)
    monkeypatch.setattr(consumer, "_start_metrics_server", lambda: None)
    monkeypatch.setattr(consumer, "get_client", MagicMock())

    def reject(_client, _payload):
        consumer._running = False
        raise InvalidAuditEvent("invalid proof")

    process = MagicMock(side_effect=reject)
    monkeypatch.setattr(consumer, "_process_message", process)
    consumer.main()

    if dlq_fails:
        transport.ack.assert_not_called()
        transport.retry.assert_called_once_with(first)
        assert process.call_count == 1  # Do not commit a later partition offset.
    else:
        assert transport.ack.call_count == 2
        transport.retry.assert_not_called()


@pytest.mark.parametrize("proof_kind", ["valid", "missing", "forged", "cross-tenant", "outage", "replay"])
def test_authoritative_origin_is_checked_before_insertion_or_replay(monkeypatch, proof_kind):
    payload = event()
    insert = configure(monkeypatch, exists=proof_kind == "replay")
    monkeypatch.setenv("AUDIT_POSTGRES_URL", "postgresql://reader@postgres/authclaw")
    connection = MagicMock()
    connection.__enter__.return_value = connection
    proof = (payload["canonical_payload"], payload["prior_hash"], payload["integrity_hash"])
    if proof_kind in {"missing", "cross-tenant"}:
        proof = None
    elif proof_kind == "forged":
        proof = ("trusted evidence", "GENESIS", "trusted hash")
    connection.execute.return_value.fetchone.return_value = proof
    connect = MagicMock(return_value=connection)
    if proof_kind == "outage":
        connect.side_effect = OSError("unavailable")
    monkeypatch.setitem(sys.modules, "psycopg", types.SimpleNamespace(connect=connect))
    if proof_kind in {"valid", "replay"}:
        _process_message(MagicMock(), payload)
        assert insert.call_count == (proof_kind == "valid")
    else:
        error = RetryableMirrorError if proof_kind == "outage" else InvalidAuditEvent
        with pytest.raises(error):
            _process_message(MagicMock(), payload)
        insert.assert_not_called()
    if proof_kind != "outage":
        assert connection.execute.call_args.args[1] == (TENANT, RECORD)


def test_shared_environment_requires_https_and_authoritative_database(monkeypatch):
    monkeypatch.setenv("AUTHCLAW_ENV", "staging")
    monkeypatch.setenv("CLICKHOUSE_PASSWORD", "strong-runtime-secret")
    monkeypatch.setenv("CLICKHOUSE_SECURE", "false")
    with pytest.raises(RuntimeError, match="CLICKHOUSE_SECURE"):
        consumer.validate_runtime_environment()
    monkeypatch.setenv("CLICKHOUSE_SECURE", "true")
    monkeypatch.setenv("AUDIT_POSTGRES_URL", "postgresql://reader@postgres/db?sslmode=require")
    with pytest.raises(RuntimeError, match="verify-full"):
        consumer.validate_runtime_environment()
    monkeypatch.setenv("AUDIT_POSTGRES_URL", "postgresql://reader@postgres/db?sslmode=verify-full")
    consumer.validate_runtime_environment()

import pytest

from services import audit_transport


def test_agent_legacy_audit_ignores_canonical_transport_sqs(monkeypatch):
    monkeypatch.setenv("AUDIT_STREAM_TRANSPORT", "sqs_fifo")
    monkeypatch.delenv("AGENT_AUDIT_STREAM_TRANSPORT", raising=False)

    publisher = audit_transport.make_audit_publisher(timeout=1, required=False)

    assert isinstance(publisher, audit_transport.KafkaRestAuditPublisher)


def test_agent_legacy_event_shape_has_no_canonical_chain_fields():
    event = {
        "event_type": "policy_decision",
        "request_id": "req-agent-1",
        "tenant_id": 42,
        "agent_name": "Policy Agent",
        "details": {"decision": "allow"},
    }

    assert "audit_record_id" not in event
    assert "tenant_sequence" not in event
    assert "prior_hash" not in event


def test_agent_legacy_audit_rejects_sqs_until_canonical_records_exist(monkeypatch):
    monkeypatch.setenv("AGENT_AUDIT_STREAM_TRANSPORT", "sqs_fifo")

    with pytest.raises(RuntimeError, match="legacy audit events must remain on Kafka"):
        audit_transport.make_audit_publisher(timeout=1, required=False)


def test_agent_unsupported_transport_fails_closed(monkeypatch):
    monkeypatch.setenv("AGENT_AUDIT_STREAM_TRANSPORT", "kinesis")

    with pytest.raises(RuntimeError, match="unsupported AGENT_AUDIT_STREAM_TRANSPORT"):
        audit_transport.make_audit_publisher(timeout=1, required=False)

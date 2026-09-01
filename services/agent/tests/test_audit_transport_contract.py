import sys
import types

import pytest

from services import audit_transport

QUEUE_URL = "https://sqs.us-east-1.amazonaws.com/123456789012/authclaw-audit.fifo"
TENANT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
RECORD = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


class FakeSQS:
    def __init__(self):
        self.sent = []

    def send_message(self, **kwargs):
        self.sent.append(kwargs)


def install_boto3(monkeypatch, client):
    class Session:
        region_name = "us-east-1"

        def client(self, service, region_name=None):
            assert service == "sqs"
            assert region_name == "us-east-1"
            return client

    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(session=types.SimpleNamespace(Session=Session)))


def test_agent_sqs_preserves_canonical_uuid(monkeypatch):
    client = FakeSQS()
    install_boto3(monkeypatch, client)
    monkeypatch.setenv("SQS_AUDIT_QUEUE_URL", QUEUE_URL)

    audit_transport.SQSFIFOAuditPublisher().publish("audit.events", {"id": RECORD, "tenant_id": TENANT})

    assert client.sent[0]["MessageGroupId"] == TENANT
    assert client.sent[0]["MessageDeduplicationId"] == RECORD


def test_agent_sqs_rejects_invalid_canonical_uuid(monkeypatch):
    install_boto3(monkeypatch, FakeSQS())
    monkeypatch.setenv("SQS_AUDIT_QUEUE_URL", QUEUE_URL)

    with pytest.raises(RuntimeError, match="canonical UUID"):
        audit_transport.SQSFIFOAuditPublisher().publish("audit.events", {"id": "not-a-uuid", "tenant_id": TENANT})


def test_agent_unsupported_transport_fails_closed(monkeypatch):
    monkeypatch.setenv("AUDIT_STREAM_TRANSPORT", "kinesis")

    with pytest.raises(RuntimeError, match="unsupported AUDIT_STREAM_TRANSPORT"):
        audit_transport.make_audit_publisher(timeout=1, required=False)

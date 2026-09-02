import importlib
import sys
import types

import pytest

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


def load_transport(monkeypatch, transport):
    monkeypatch.setenv("AUDIT_STREAM_TRANSPORT", transport)
    monkeypatch.setenv("SQS_AUDIT_QUEUE_URL", QUEUE_URL)
    import app.services.audit_transport as audit_transport

    return importlib.reload(audit_transport)


def test_backend_sqs_preserves_canonical_id_and_tenant_group(monkeypatch):
    client = FakeSQS()
    install_boto3(monkeypatch, client)
    audit_transport = load_transport(monkeypatch, "sqs_fifo")

    audit_transport.make_audit_publisher().publish(TENANT, {"id": RECORD, "tenant_id": TENANT})

    assert client.sent[0]["MessageGroupId"] == TENANT
    assert client.sent[0]["MessageDeduplicationId"] == RECORD


def test_backend_sqs_rejects_missing_canonical_id(monkeypatch):
    install_boto3(monkeypatch, FakeSQS())
    audit_transport = load_transport(monkeypatch, "sqs_fifo")

    with pytest.raises(RuntimeError, match="audit_record_id"):
        audit_transport.make_audit_publisher().publish(TENANT, {"tenant_id": TENANT})


def test_backend_unsupported_transport_fails_closed(monkeypatch):
    with pytest.raises(RuntimeError, match="unsupported AUDIT_STREAM_TRANSPORT"):
        load_transport(monkeypatch, "kinesis")

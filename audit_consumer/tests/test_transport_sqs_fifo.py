import json
import os
import sys
import types
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from transport import SQSFIFOAuditConsumer, make_audit_consumer  # noqa: E402


TENANT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
RECORD = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
QUEUE_URL = "https://sqs.us-east-1.amazonaws.com/123456789012/authclaw-audit.fifo"


class FakeSQS:
    def __init__(self, messages=None):
        self.messages = messages or []
        self.deleted = []
        self.visibility = []

    def receive_message(self, **kwargs):
        self.receive_kwargs = kwargs
        return {"Messages": self.messages}

    def delete_message(self, **kwargs):
        self.deleted.append(kwargs)

    def change_message_visibility(self, **kwargs):
        self.visibility.append(kwargs)


class FakeSession:
    region_name = "us-east-1"

    def __init__(self, client):
        self._client = client

    def client(self, service, region_name=None):
        assert service == "sqs"
        assert region_name == "us-east-1"
        return self._client


def install_boto3(monkeypatch, client, *, region="us-east-1"):
    class Session(FakeSession):
        region_name = region

        def __init__(self):
            super().__init__(client)

    monkeypatch.setitem(
        sys.modules,
        "boto3",
        types.SimpleNamespace(session=types.SimpleNamespace(Session=Session)),
    )


def sqs_message(*, record_id=RECORD, tenant_id=TENANT, group_id=TENANT, dedup_id=RECORD):
    return {
        "ReceiptHandle": "receipt-1",
        "Body": json.dumps({"id": record_id, "tenant_id": tenant_id}),
        "Attributes": {
            "MessageGroupId": group_id,
            "MessageDeduplicationId": dedup_id,
            "ApproximateReceiveCount": "2",
        },
    }


def configure(monkeypatch, client, **env):
    install_boto3(monkeypatch, client, region=env.pop("AWS_DEFAULT_REGION", "us-east-1"))
    monkeypatch.setenv("AUDIT_STREAM_TRANSPORT", "sqs_fifo")
    monkeypatch.setenv("SQS_AUDIT_QUEUE_URL", env.pop("SQS_AUDIT_QUEUE_URL", QUEUE_URL))
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return make_audit_consumer(MagicMock())


def test_sqs_fifo_selection_receives_bounded_long_poll_batch(monkeypatch):
    client = FakeSQS([sqs_message()])
    consumer = configure(
        monkeypatch,
        client,
        SQS_LONG_POLL_SECONDS="5",
        SQS_MAX_MESSAGES="3",
        SQS_VISIBILITY_TIMEOUT_SECONDS="30",
    )

    batches = consumer.poll(timeout_ms=1000)

    assert isinstance(consumer, SQSFIFOAuditConsumer)
    assert len(batches) == 1
    assert batches[0][0].value["id"] == RECORD
    assert batches[0][0].receive_count == 2
    assert client.receive_kwargs["WaitTimeSeconds"] == 5
    assert client.receive_kwargs["MaxNumberOfMessages"] == 3
    assert client.receive_kwargs["VisibilityTimeout"] == 30
    assert "MessageGroupId" in client.receive_kwargs["MessageSystemAttributeNames"]
    assert "MessageDeduplicationId" in client.receive_kwargs["MessageSystemAttributeNames"]
    assert "ApproximateReceiveCount" in client.receive_kwargs["MessageSystemAttributeNames"]


def test_sqs_fifo_ack_deletes_only_after_processing(monkeypatch):
    client = FakeSQS([sqs_message()])
    consumer = configure(monkeypatch, client)
    message = consumer.poll(timeout_ms=1000)[0][0]

    consumer.ack(message)

    assert client.deleted == [{"QueueUrl": QUEUE_URL, "ReceiptHandle": "receipt-1"}]


def test_sqs_fifo_retry_leaves_message_for_visibility_redrive(monkeypatch):
    client = FakeSQS([sqs_message()])
    consumer = configure(monkeypatch, client)
    message = consumer.poll(timeout_ms=1000)[0][0]

    consumer.retry(message)

    assert client.deleted == []
    with pytest.raises(RuntimeError, match="visibility and redrive"):
        consumer.publish_dlq(message.value, "invalid")


def test_sqs_fifo_rejects_missing_or_mismatched_identity(monkeypatch):
    client = FakeSQS(
        [
            sqs_message(record_id=""),
            sqs_message(dedup_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
            sqs_message(group_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
        ]
    )
    consumer = configure(monkeypatch, client)

    messages = [message for batch in consumer.poll(timeout_ms=1000) for message in batch]

    assert all(message.validation_error is not None for message in messages)
    assert "canonical audit-record UUID" in str(messages[0].validation_error)
    assert "DeduplicationId does not match" in str(messages[1].validation_error)
    assert "MessageGroupId does not match" in str(messages[2].validation_error)


def test_sqs_fifo_rejects_invalid_url_region_and_bounds(monkeypatch):
    with pytest.raises(RuntimeError, match="HTTPS FIFO queue URL"):
        configure(monkeypatch, FakeSQS(), SQS_AUDIT_QUEUE_URL="http://sqs.us-east-1.amazonaws.com/123/q.fifo")

    with pytest.raises(RuntimeError, match="region does not match"):
        configure(monkeypatch, FakeSQS(), AWS_DEFAULT_REGION="us-west-2")

    with pytest.raises(RuntimeError, match="SQS_MAX_MESSAGES must be between 1 and 10"):
        configure(monkeypatch, FakeSQS(), SQS_MAX_MESSAGES="11")

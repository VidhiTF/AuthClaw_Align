import json
import os
import sys
import types
import base64
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from transport import AuditMessage, KafkaAuditConsumer, SQSFIFOAuditConsumer, make_audit_consumer  # noqa: E402


@pytest.mark.parametrize("raw", [b"\xff", b"{", b"[]", None])
def test_kafka_malformed_record_does_not_block_valid_successor(monkeypatch, raw):
    position = types.SimpleNamespace(topic="audit.events", partition=2)
    adapter = KafkaAuditConsumer.__new__(KafkaAuditConsumer)
    adapter._consumer = MagicMock()
    adapter._observe_lag = MagicMock()
    adapter._consumer.poll.return_value = types.SimpleNamespace(items=lambda: [(position, [
        types.SimpleNamespace(value=raw, offset=4),
        types.SimpleNamespace(value=b'{"tenant_id":"valid"}', offset=5),
    ])])
    first, later = adapter.poll(1000)[0]
    assert first.validation_error is not None
    assert base64.b64decode(first.value["raw_value_base64"]) == (raw or b"")
    assert (first.value["topic"], first.value["partition"], first.value["offset"]) == ("audit.events", 2, 4)
    assert later.validation_error is None
    assert later.value == {"tenant_id": "valid"}


def test_kafka_shared_transport_requires_credentials_and_verified_tls(monkeypatch):
    from transport import kafka_security_options

    monkeypatch.setenv("AUTHCLAW_ENV", "staging")
    monkeypatch.setenv("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT")
    with pytest.raises(RuntimeError, match="SASL_SSL"):
        kafka_security_options()
    monkeypatch.setenv("KAFKA_SECURITY_PROTOCOL", "SASL_SSL")
    monkeypatch.delenv("KAFKA_SASL_PASSWORD", raising=False)
    with pytest.raises(RuntimeError, match="credentials"):
        kafka_security_options()
    monkeypatch.setenv("KAFKA_SASL_USERNAME", "audit-reader")
    monkeypatch.setenv("KAFKA_SASL_PASSWORD", "test-secret")
    options = kafka_security_options()
    assert options["ssl_check_hostname"] is True
    assert options["security_protocol"] == "SASL_SSL"


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

    def client(self, service, region_name=None, endpoint_url=None):
        del endpoint_url
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


def test_kafka_multi_partition_failure_does_not_commit_unprocessed_offset(monkeypatch):
    offset = MagicMock(side_effect=lambda value, metadata: (value, metadata))
    monkeypatch.setitem(sys.modules, "kafka.structs", types.SimpleNamespace(OffsetAndMetadata=offset))
    client = MagicMock()
    consumer = KafkaAuditConsumer.__new__(KafkaAuditConsumer)
    consumer._consumer = client
    processed_partition = ("audit.events", 0)
    failed_partition = ("audit.events", 1)

    consumer.ack(AuditMessage({}, 4, processed_partition))
    consumer.retry(AuditMessage({}, 9, failed_partition))

    client.commit.assert_called_once_with({processed_partition: (5, "")})
    client.seek.assert_called_once_with(failed_partition, 9)


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

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from consumer import normalise_event, _process_message, publish_to_dlq, stable_record_id
from hash_chain import GENESIS_HASH, compute_integrity_hash


class FakeRedis:
    def __init__(self):
        self.values = {}

    def get(self, key):
        return self.values.get(key)

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True

    def delete(self, key):
        self.values.pop(key, None)


@pytest.fixture(autouse=True)
def isolated_tail_hash_cache(monkeypatch):
    monkeypatch.setattr("consumer.redis_client", FakeRedis())
    monkeypatch.setattr("consumer.audit_event_exists", lambda _ch_client, _record_id: False)


def gateway_payload(
    record_id="test-id-1",
    tenant_id="tenant-abc",
    action="allow",
    provider="gemini",
    model="gemini-2.0-flash-lite",
    request_id="req-abc123",
):
    return {
        "id": record_id,
        "timestamp": "2024-06-01T12:00:00Z",
        "tenant_id": tenant_id,
        "policy_id": "pol-001",
        "action": action,
        "reason": "Allowed",
        "provider": provider,
        "model": model,
        "prompt_count": 2,
        "request_size": 512,
        "response_status": 200,
        "duration_ms": 85,
        "frameworks_affected": ["HIPAA"],
        "execution_trace": ["redact:pii_detected"],
        "request_id": request_id,
    }


class TestNormaliseEvent:
    def test_basic_fields_mapped(self):
        payload = gateway_payload()
        row = normalise_event(payload)
        assert row["record_id"] == "test-id-1"
        assert row["tenant_id"] == "tenant-abc"
        assert row["action"] == "allow"
        assert row["provider"] == "gemini"
        assert row["model"] == "gemini-2.0-flash-lite"
        assert row["prompt_count"] == 2
        assert row["request_size"] == 512
        assert row["response_status"] == 200
        assert row["duration_ms"] == 85

    def test_request_id_propagated(self):
        payload = gateway_payload(request_id="req-xyz789")
        row = normalise_event(payload)
        assert row["request_id"] == "req-xyz789"

    def test_request_id_defaults_to_empty_string(self):
        payload = gateway_payload()
        del payload["request_id"]
        row = normalise_event(payload)
        assert row["request_id"] == ""

    def test_gateway_identity_defaults_match_postgres_chain(self):
        payload = gateway_payload()
        row = normalise_event(payload)
        assert row["actor_id"] == ""
        assert row["actor_type"] == "gateway"

    def test_timestamp_parsed_as_datetime(self):
        payload = gateway_payload()
        row = normalise_event(payload)
        assert isinstance(row["timestamp"], datetime)

    def test_missing_id_generates_uuid(self):
        payload = gateway_payload()
        del payload["id"]
        row = normalise_event(payload)
        assert row["record_id"]  # non-empty UUID generated

    def test_missing_id_generates_stable_uuid_for_same_payload(self):
        payload = gateway_payload()
        del payload["id"]
        assert stable_record_id(payload) == stable_record_id(dict(payload))

    def test_frameworks_affected_preserved(self):
        payload = gateway_payload()
        row = normalise_event(payload)
        assert row["frameworks_affected"] == ["HIPAA"]

    def test_execution_trace_is_json_string(self):
        payload = gateway_payload()
        row = normalise_event(payload)
        parsed = json.loads(row["execution_trace"])
        assert parsed == ["redact:pii_detected"]

    def test_empty_frameworks_defaults_to_list(self):
        payload = gateway_payload()
        payload["frameworks_affected"] = None
        row = normalise_event(payload)
        assert row["frameworks_affected"] == []

    def test_chain_fields_initially_empty(self):
        row = normalise_event(gateway_payload())
        assert row["prior_hash"] == ""
        assert row["integrity_hash"] == ""


class TestProcessMessage:
    @patch("consumer.get_prior_hash", return_value=GENESIS_HASH)
    @patch("consumer.insert_audit_event")
    def test_inserts_record_with_hash_chain(self, mock_insert, mock_prior):
        ch_client = MagicMock()
        payload = gateway_payload(tenant_id="tenant-xyz")

        _process_message(ch_client, payload)

        assert mock_insert.called
        inserted_row = mock_insert.call_args[0][1]
        assert inserted_row["prior_hash"] == GENESIS_HASH
        assert inserted_row["integrity_hash"]
        assert inserted_row["tenant_id"] == "tenant-xyz"

    @patch("consumer.get_prior_hash", return_value=GENESIS_HASH)
    @patch("consumer.insert_audit_event")
    def test_integrity_hash_computed_correctly(self, mock_insert, mock_prior):
        ch_client = MagicMock()
        payload = gateway_payload(tenant_id="tenant-hash")

        _process_message(ch_client, payload)

        inserted_row = mock_insert.call_args[0][1]
        expected = compute_integrity_hash(inserted_row, GENESIS_HASH)
        assert inserted_row["integrity_hash"] == expected

    @patch("consumer.get_prior_hash", return_value=GENESIS_HASH)
    @patch("consumer.insert_audit_event")
    def test_skips_empty_tenant_id(self, mock_insert, mock_prior):
        ch_client = MagicMock()
        payload = gateway_payload(tenant_id="")

        _process_message(ch_client, payload)

        mock_insert.assert_not_called()

    @patch("consumer.get_prior_hash", return_value="previous-hash-abc")
    @patch("consumer.insert_audit_event")
    def test_uses_prior_hash_from_clickhouse(self, mock_insert, mock_prior):
        ch_client = MagicMock()
        payload = gateway_payload(tenant_id="tenant-chained")

        _process_message(ch_client, payload)

        inserted_row = mock_insert.call_args[0][1]
        assert inserted_row["prior_hash"] == "previous-hash-abc"

    @patch("consumer.get_prior_hash", return_value=GENESIS_HASH)
    @patch("consumer.insert_audit_event")
    def test_block_events_processed(self, mock_insert, mock_prior):
        ch_client = MagicMock()
        payload = gateway_payload(tenant_id="tenant-block", action="block")

        _process_message(ch_client, payload)

        inserted_row = mock_insert.call_args[0][1]
        assert inserted_row["action"] == "block"

    @patch("consumer.get_prior_hash", return_value=GENESIS_HASH)
    @patch("consumer.insert_audit_event")
    def test_request_id_persisted_in_row(self, mock_insert, mock_prior):
        ch_client = MagicMock()
        payload = gateway_payload(tenant_id="tenant-rid", request_id="req-persist-me")

        _process_message(ch_client, payload)

        inserted_row = mock_insert.call_args[0][1]
        assert inserted_row["request_id"] == "req-persist-me"

    @patch("consumer.get_prior_hash", return_value=GENESIS_HASH)
    @patch("consumer.insert_audit_event")
    def test_empty_request_id_stored_as_empty_string(self, mock_insert, mock_prior):
        ch_client = MagicMock()
        payload = gateway_payload(tenant_id="tenant-norid", request_id="")

        _process_message(ch_client, payload)

        inserted_row = mock_insert.call_args[0][1]
        assert inserted_row["request_id"] == ""

    @patch("consumer.get_prior_hash", return_value=GENESIS_HASH)
    @patch("consumer.insert_audit_event")
    def test_duplicate_record_id_skips_insert(self, mock_insert, mock_prior, monkeypatch):
        ch_client = MagicMock()
        payload = gateway_payload(tenant_id="tenant-dup", record_id="11111111-1111-4111-8111-111111111111")
        monkeypatch.setattr("consumer.audit_event_exists", lambda _client, _record_id: True)

        _process_message(ch_client, payload)

        mock_prior.assert_not_called()
        mock_insert.assert_not_called()

    @patch("consumer.get_prior_hash", return_value=GENESIS_HASH)
    @patch("consumer.insert_audit_event", return_value=True)
    def test_replayed_message_after_restart_does_not_insert_twice(self, mock_insert, mock_prior):
        ch_client = MagicMock()
        payload = gateway_payload(tenant_id="tenant-replay", record_id="11111111-1111-4111-8111-222222222222")

        _process_message(ch_client, payload)
        _process_message(ch_client, payload)

        assert mock_insert.call_count == 1


class TestPublishToDLQ:
    def _make_dlq_producer(self):
        """Return a mock KafkaProducer."""
        mock_producer = MagicMock()
        mock_future = MagicMock()
        mock_future.get.return_value = None
        mock_producer.send.return_value = mock_future
        return mock_producer

    def test_publishes_envelope_to_dlq_topic(self):
        producer = self._make_dlq_producer()
        payload = gateway_payload(tenant_id="tenant-dlq", request_id="req-dlq-1")
        error = "clickhouse timeout"

        publish_to_dlq(producer, payload, error)

        assert producer.send.called
        call_kwargs = producer.send.call_args
        topic = call_kwargs[0][0]
        assert topic == "audit.deadletter"

        sent_value = call_kwargs[1]["value"]
        assert sent_value["error_reason"] == error
        assert sent_value["tenant_id"] == "tenant-dlq"
        assert sent_value["request_id"] == "req-dlq-1"
        assert "failed_at" in sent_value
        assert "original_payload" in sent_value

    def test_original_payload_preserved_in_envelope(self):
        producer = self._make_dlq_producer()
        payload = gateway_payload(tenant_id="t1", record_id="evt-orig")

        publish_to_dlq(producer, payload, "parse error")

        sent_value = producer.send.call_args[1]["value"]
        assert sent_value["original_payload"]["id"] == "evt-orig"
        assert sent_value["original_payload"]["tenant_id"] == "t1"

    def test_tenant_id_used_as_kafka_key(self):
        producer = self._make_dlq_producer()
        payload = gateway_payload(tenant_id="tenant-key-test")

        publish_to_dlq(producer, payload, "error")

        key = producer.send.call_args[1]["key"]
        assert key == "tenant-key-test"

    def test_empty_tenant_id_in_payload(self):
        producer = self._make_dlq_producer()
        payload = {"id": "no-tenant", "action": "allow"}  # no tenant_id

        publish_to_dlq(producer, payload, "missing tenant")

        sent_value = producer.send.call_args[1]["value"]
        assert sent_value["tenant_id"] == ""

    def test_failed_at_is_iso_utc_string(self):
        producer = self._make_dlq_producer()
        payload = gateway_payload(tenant_id="t-ts")

        publish_to_dlq(producer, payload, "timeout")

        sent_value = producer.send.call_args[1]["value"]
        failed_at = sent_value["failed_at"]
        # Must be parseable as ISO datetime
        dt = datetime.fromisoformat(failed_at.replace("Z", "+00:00"))
        assert dt.tzinfo is not None

    def test_dlq_producer_failure_does_not_raise(self):
        """DLQ publish failure must be swallowed — original processing error takes priority."""
        producer = MagicMock()
        producer.send.side_effect = Exception("Kafka connection refused")
        payload = gateway_payload(tenant_id="tenant-dlq-fail")

        # Must not raise.
        publish_to_dlq(producer, payload, "original error")


class TestDLQTriggeredOnProcessingFailure:
    """Verify that main()'s exception handler routes failures to publish_to_dlq.

    We test the exact code path in main():
        try:
            _process_message(ch_client, message.value)
        except Exception as exc:
            publish_to_dlq(dlq_producer, message.value, str(exc))
    """

    @patch("consumer.get_prior_hash", side_effect=Exception("ClickHouse unavailable"))
    @patch("consumer.insert_audit_event")
    def test_dlq_invoked_on_exception_from_process_message(self, mock_insert, mock_prior):
        """Directly simulate the main() try/except block."""
        ch_client = MagicMock()
        payload = gateway_payload(tenant_id="tenant-fail", request_id="req-fail")

        # Build a real DLQ producer mock with send().get() chain
        mock_producer = MagicMock()
        mock_future = MagicMock()
        mock_future.get.return_value = None
        mock_producer.send.return_value = mock_future

        # Simulate the try/except in main():
        try:
            _process_message(ch_client, payload)
        except Exception as exc:
            # This is what main() does on failure:
            publish_to_dlq(mock_producer, payload, str(exc))

        # DLQ producer must have been called
        assert mock_producer.send.called, "DLQ producer.send() should have been called"

        sent_value = mock_producer.send.call_args[1]["value"]
        assert sent_value["error_reason"] == "ClickHouse unavailable"
        assert sent_value["request_id"] == "req-fail"
        assert sent_value["tenant_id"] == "tenant-fail"
        assert "original_payload" in sent_value
        assert sent_value["original_payload"]["id"] == "test-id-1"

    @patch("consumer.get_prior_hash", return_value=GENESIS_HASH)
    @patch("consumer.insert_audit_event", side_effect=Exception("Insert failed"))
    def test_dlq_invoked_on_clickhouse_insert_failure(self, mock_insert, mock_prior):
        """DLQ must also be triggered when ClickHouse insert fails."""
        ch_client = MagicMock()
        payload = gateway_payload(tenant_id="tenant-insert-fail", request_id="req-ins-fail")

        mock_producer = MagicMock()
        mock_future = MagicMock()
        mock_future.get.return_value = None
        mock_producer.send.return_value = mock_future

        try:
            _process_message(ch_client, payload)
        except Exception as exc:
            publish_to_dlq(mock_producer, payload, str(exc))

        assert mock_producer.send.called
        sent_value = mock_producer.send.call_args[1]["value"]
        assert sent_value["error_reason"] == "Insert failed"
        assert sent_value["request_id"] == "req-ins-fail"

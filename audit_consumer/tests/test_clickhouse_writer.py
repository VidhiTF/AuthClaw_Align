import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from clickhouse_writer import audit_event_exists, insert_audit_event


class QueryResult:
    def __init__(self, rows):
        self.result_rows = rows


class FakeClickHouse:
    def __init__(self, exists=False):
        self.exists = exists
        self.insert_calls = []

    def query(self, *_args, **_kwargs):
        return QueryResult([(1 if self.exists else 0,)])

    def insert(self, **kwargs):
        self.insert_calls.append(kwargs)


def _row():
    return {
        "record_id": "11111111-1111-4111-8111-111111111111",
        "tenant_id": "22222222-2222-4222-8222-222222222222",
        "timestamp": "2026-06-30T00:00:00.000Z",
        "actor_id": "",
        "actor_type": "gateway",
        "action": "allow",
        "policy_id": "",
        "provider": "openai",
        "model": "gpt-4o-mini",
        "reason": "Allowed",
        "prompt_count": 1,
        "request_size": 42,
        "response_status": 200,
        "duration_ms": 12,
        "frameworks_affected": [],
        "execution_trace": "[]",
        "request_id": "req-1",
        "prior_hash": "GENESIS",
        "integrity_hash": "abc123",
    }


def test_audit_event_exists_true_when_count_positive():
    assert audit_event_exists(FakeClickHouse(exists=True), _row()["record_id"]) is True


def test_insert_audit_event_skips_duplicate_record_id():
    client = FakeClickHouse(exists=True)

    inserted = insert_audit_event(client, _row())

    assert inserted is False
    assert client.insert_calls == []


def test_insert_audit_event_inserts_new_record():
    client = FakeClickHouse(exists=False)

    inserted = insert_audit_event(client, _row())

    assert inserted is True
    assert len(client.insert_calls) == 1
    assert client.insert_calls[0]["table"] == "authclaw.audit_events"

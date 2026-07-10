from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

from app.services import audit_store


def _record(record_id=None, *, tenant_id=None, prior_hash="GENESIS", integrity_hash=None):
    row = {
        "record_id": str(record_id or uuid4()),
        "tenant_id": str(tenant_id or uuid4()),
        "timestamp": datetime(2026, 6, 30, 1, 2, 3, tzinfo=timezone.utc),
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
        "frameworks_affected": ["SOC2"],
        "execution_trace": '["proxy"]',
        "request_id": "req-1",
        "prior_hash": prior_hash,
        "integrity_hash": "",
    }
    row["integrity_hash"] = integrity_hash or audit_store.compute_integrity_hash(row, prior_hash)
    return row


def test_postgres_audit_row_preserves_extended_metadata():
    tenant_id = uuid4()
    log = SimpleNamespace(
        record_id=uuid4(),
        tenant_id=tenant_id,
        created_at=datetime(2026, 6, 30, tzinfo=timezone.utc),
        actor_id=uuid4(),
        actor_type="orchestrator",
        action="workflow:remediation_action_succeeded",
        policy_id=None,
        provider="orchestrator",
        model="",
        reason="Remediation action succeeded",
        prompt_count=0,
        request_size=0,
        response_status=200,
        duration_ms=5,
        frameworks_affected=["HIPAA"],
        execution_trace='["workflow_id=w1","action_id=a1"]',
        request_id="workflow-1",
        prior_hash="GENESIS",
        integrity_hash="abc123",
    )

    row = audit_store.postgres_audit_row(log)

    assert row["tenant_id"] == str(tenant_id)
    assert row["actor_type"] == "orchestrator"
    assert row["execution_trace"] == '["workflow_id=w1","action_id=a1"]'
    assert row["frameworks_affected"] == ["HIPAA"]


def test_consistency_report_detects_missing_and_hash_mismatch(monkeypatch):
    tenant_id = str(uuid4())
    shared = _record(tenant_id=tenant_id)
    missing = _record(tenant_id=tenant_id, prior_hash=shared["integrity_hash"])
    mismatched = {
        **_record(tenant_id=tenant_id, prior_hash=missing["integrity_hash"]),
        "integrity_hash": "bad-hash",
    }
    clickhouse_shared = dict(shared)
    clickhouse_mismatched = {**mismatched, "integrity_hash": "different-bad-hash"}

    monkeypatch.setattr(audit_store, "get_postgres_records", lambda _db, _tenant: [shared, missing, mismatched])
    monkeypatch.setattr(audit_store, "fetch_clickhouse_records", lambda _ch, _tenant: [clickhouse_shared, clickhouse_mismatched])

    report = audit_store.build_consistency_report(object(), object(), tenant_id)

    assert not report.consistent
    assert report.postgres_count == 3
    assert report.clickhouse_count == 2
    assert report.missing_in_clickhouse == [missing["record_id"]]
    assert report.hash_mismatches[0]["record_id"] == mismatched["record_id"]


def test_replay_inserts_only_missing_rows_and_preserves_chain_hashes(monkeypatch):
    tenant_id = str(uuid4())
    existing = _record(tenant_id=tenant_id)
    missing = _record(tenant_id=tenant_id, prior_hash=existing["integrity_hash"])

    monkeypatch.setattr(audit_store, "get_postgres_records", lambda _db, _tenant: [existing, missing])
    monkeypatch.setattr(audit_store, "fetch_clickhouse_records", lambda _ch, _tenant: [existing])

    class FakeClickHouse:
        def __init__(self):
            self.inserted = []

        def insert(self, *, table, data, column_names):
            self.inserted.append((table, data, column_names))

    ch = FakeClickHouse()
    result = audit_store.replay_postgres_to_clickhouse(object(), ch, tenant_id)

    assert result["inserted"] == 1
    assert result["skipped"] == 1
    assert result["record_ids"] == [missing["record_id"]]
    table, data, column_names = ch.inserted[0]
    assert table == "authclaw.audit_events"
    assert column_names == audit_store.CLICKHOUSE_COLUMNS
    inserted_row = dict(zip(column_names, data[0]))
    assert inserted_row["prior_hash"] == missing["prior_hash"]
    assert inserted_row["integrity_hash"] == missing["integrity_hash"]


def test_replay_dry_run_does_not_insert(monkeypatch):
    tenant_id = str(uuid4())
    missing = _record(tenant_id=tenant_id)
    monkeypatch.setattr(audit_store, "get_postgres_records", lambda _db, _tenant: [missing])
    monkeypatch.setattr(audit_store, "fetch_clickhouse_records", lambda _ch, _tenant: [])

    class FakeClickHouse:
        def insert(self, **_kwargs):
            raise AssertionError("dry-run replay must not insert")

    result = audit_store.replay_postgres_to_clickhouse(object(), FakeClickHouse(), tenant_id, dry_run=True)

    assert result["dry_run"] is True
    assert result["inserted"] == 0
    assert result["would_insert"] == 1

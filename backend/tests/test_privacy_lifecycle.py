"""Tests for ACL-15 tenant-aware privacy lifecycle operations."""

import json
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from app.db.models import RedactionToken
from app.services import privacy_lifecycle


def _mock_db(*, deleted_count: int = 1, delete_error: Exception | None = None):
    db = MagicMock(spec=Session)

    redaction_query = MagicMock()
    redaction_query.filter.return_value = redaction_query
    if delete_error:
        redaction_query.delete.side_effect = delete_error
    else:
        redaction_query.delete.return_value = deleted_count

    def query_for(model):
        if model is RedactionToken:
            return redaction_query
        raise AssertionError(f"Unexpected query model: {model}")

    db.query.side_effect = query_for
    return db


def _stub_canonical_append(monkeypatch):
    captured = []

    def append(_db, event):
        captured.append(event)
        return {
            "record_id": uuid4(),
            "tenant_sequence": 1,
            "canonical_payload": "{}",
            "prior_hash": "GENESIS",
            "integrity_hash": "a" * 64,
        }

    monkeypatch.setattr(privacy_lifecycle, "append_audit_event", append)
    return captured


def test_purge_deletes_expired_records_and_creates_safe_audit(monkeypatch):
    tenant_id = uuid4()
    actor_id = uuid4()
    db = _mock_db(deleted_count=3)
    events = _stub_canonical_append(monkeypatch)

    result = privacy_lifecycle.purge_expired_redaction_mappings(
        db,
        tenant_id=tenant_id,
        request_id="acl15-request-001",
        actor_id=actor_id,
    )

    assert result.tenant_id == str(tenant_id)
    assert result.deleted_count == 3
    assert result.request_id == "acl15-request-001"
    assert result.status == "completed"

    db.commit.assert_called_once()
    db.rollback.assert_not_called()
    event = events[0]
    assert event["tenant_id"] == str(tenant_id)
    assert event["actor_id"] == str(actor_id)
    assert event["actor_type"] == "privacy_lifecycle"
    assert event["action"] == "privacy:purge_expired"
    assert event["frameworks_affected"] == ["GDPR"]

    trace = event["execution_trace"]
    assert "data_class=redaction_token_mapping" in trace
    assert "deleted_count=3" in trace


def test_purge_is_idempotent_when_no_expired_records_exist(monkeypatch):
    tenant_id = uuid4()
    db = _mock_db(deleted_count=0)
    events = _stub_canonical_append(monkeypatch)

    result = privacy_lifecycle.purge_expired_redaction_mappings(
        db,
        tenant_id=tenant_id,
        request_id="acl15-request-002",
    )

    assert result.deleted_count == 0
    assert result.status == "completed"
    db.commit.assert_called_once()
    db.rollback.assert_not_called()

    assert "Purged 0 expired redaction mappings" == events[0]["reason"]


def test_purge_rolls_back_when_deletion_fails():
    tenant_id = uuid4()
    db = _mock_db(delete_error=RuntimeError("database unavailable"))

    with pytest.raises(RuntimeError, match="database unavailable"):
        privacy_lifecycle.purge_expired_redaction_mappings(
            db,
            tenant_id=tenant_id,
            request_id="acl15-request-003",
        )

    db.commit.assert_not_called()
    db.rollback.assert_called_once()
    db.add.assert_not_called()


def test_request_id_is_limited_to_audit_column_length(monkeypatch):
    tenant_id = uuid4()
    db = _mock_db(deleted_count=1)
    events = _stub_canonical_append(monkeypatch)

    result = privacy_lifecycle.purge_expired_redaction_mappings(
        db,
        tenant_id=tenant_id,
        request_id="r" * 300,
    )

    assert len(result.request_id) == 255
    assert len(events[0]["request_id"]) == 255


def test_audit_evidence_contains_no_personal_value(monkeypatch):
    tenant_id = uuid4()
    db = _mock_db(deleted_count=2)
    events = _stub_canonical_append(monkeypatch)
    synthetic_personal_value = "vidhi.acl15@example.test"

    privacy_lifecycle.purge_expired_redaction_mappings(
        db,
        tenant_id=tenant_id,
        request_id="acl15-request-004",
    )

    audit_log = events[0]
    serialized_evidence = " ".join(
        [
            audit_log["reason"],
            json.dumps(audit_log["execution_trace"]),
            audit_log["action"],
            audit_log["request_id"],
        ]
    )

    assert synthetic_personal_value not in serialized_evidence

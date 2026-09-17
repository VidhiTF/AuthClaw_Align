import base64
from types import SimpleNamespace
from uuid import uuid4
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints import evidence


@pytest.fixture(autouse=True)
def valid_evidence_integrity(monkeypatch):
    monkeypatch.setattr(evidence, "verify_evidence_integrity", lambda _: True)


def _request(tenant_id):
    return SimpleNamespace(
        state=SimpleNamespace(
            tenant_id=tenant_id, user_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        ),
        headers={"x-request-id": "request-1"},
    )


def _record(tenant_id, key=None):
    return SimpleNamespace(
        id=uuid4(),
        tenant_id=tenant_id,
        framework="SOC2",
        evidence_type="scan_result",
        evidence_data={
            "storage": {
                "bucket": "evidence-bucket",
                "object_key": key or f"tenant-{tenant_id}/report.json",
                "sha256": "a" * 64,
                "retention_class": "seven_years",
                "access_policy": {"allow_download": True},
                "content_type": "application/json",
            }
        },
    )


def test_download_is_authorized_by_tenant_evidence_record_not_filename(monkeypatch):
    tenant_id = str(uuid4())
    record = _record(tenant_id)
    calls = []

    class Client:
        def head_object(self, **kwargs):
            calls.append(("head", kwargs))
            return {
                "ChecksumSHA256": base64.b64encode(bytes.fromhex("a" * 64)).decode()
            }

        def get_object(self, **kwargs):
            calls.append(("get", kwargs))
            return {
                "ChecksumSHA256": base64.b64encode(bytes.fromhex("a" * 64)).decode(),
                "Body": SimpleNamespace(
                    iter_chunks=lambda **_: iter([b"ok"]), close=lambda: None
                ),
            }

    monkeypatch.setattr(
        evidence.evidence_service,
        "get_evidence",
        lambda *_args, **kwargs: (
            record
            if kwargs["tenant_id"] == tenant_id
            and kwargs["evidence_id"] == str(record.id)
            else None
        ),
    )
    monkeypatch.setattr(evidence, "_s3_client", Client)
    monkeypatch.setattr(evidence, "_audit_access", lambda *_args: None)

    response = evidence.download_evidence(
        str(record.id), _request(tenant_id), db=object()
    )

    assert (
        response.headers["content-disposition"]
        == "attachment; filename*=UTF-8''report.json"
    )
    assert [call[1]["Key"] for call in calls] == [f"tenant-{tenant_id}/report.json"]
    with pytest.raises(HTTPException) as rejected:
        evidence.download_evidence("report.json", _request(tenant_id), db=object())
    assert rejected.value.status_code == 404
    with pytest.raises(HTTPException) as rejected:
        evidence.download_evidence(str(record.id), _request(str(uuid4())), db=object())
    assert rejected.value.status_code == 404


@pytest.mark.parametrize(
    "key", ["../report.json", "tenant-a/../report.json", "tenant-a\\report.json"]
)
def test_download_rejects_traversal_before_storage_access(monkeypatch, key):
    tenant_id = "a"
    record = _record(tenant_id, key)
    monkeypatch.setattr(
        evidence.evidence_service, "get_evidence", lambda *_args, **_kwargs: record
    )
    monkeypatch.setattr(
        evidence,
        "_s3_client",
        lambda: (_ for _ in ()).throw(AssertionError("storage must not be called")),
    )

    with pytest.raises(HTTPException) as rejected:
        evidence.download_evidence(str(record.id), _request(tenant_id), db=object())
    assert rejected.value.status_code == 404


def test_download_refuses_checksum_or_audit_failure(monkeypatch):
    tenant_id = str(uuid4())
    record = _record(tenant_id)
    monkeypatch.setattr(
        evidence.evidence_service, "get_evidence", lambda *_args, **_kwargs: record
    )

    class Client:
        def get_object(self, **_kwargs):
            return {
                "ChecksumSHA256": base64.b64encode(b"x" * 32).decode(),
                "Body": SimpleNamespace(close=lambda: None),
            }

    monkeypatch.setattr(evidence, "_s3_client", Client)
    with pytest.raises(HTTPException) as rejected:
        evidence.download_evidence(str(record.id), _request(tenant_id), db=object())
    assert rejected.value.status_code == 409

    monkeypatch.setattr(
        evidence,
        "_s3_client",
        lambda: SimpleNamespace(
            head_object=lambda **_: {
                "ChecksumSHA256": base64.b64encode(bytes.fromhex("a" * 64)).decode()
            },
            get_object=lambda **_: {
                "ChecksumSHA256": base64.b64encode(bytes.fromhex("a" * 64)).decode(),
                "Body": SimpleNamespace(close=lambda: None),
            },
        ),
    )
    monkeypatch.setattr(
        evidence,
        "_audit_access",
        lambda *_args: (_ for _ in ()).throw(HTTPException(status_code=503)),
    )
    with pytest.raises(HTTPException) as rejected:
        evidence.download_evidence(str(record.id), _request(tenant_id), db=object())
    assert rejected.value.status_code == 503


def test_download_rejects_tampered_evidence_before_storage_access(monkeypatch):
    tenant_id = str(uuid4())
    record = _record(tenant_id)
    monkeypatch.setattr(
        evidence.evidence_service, "get_evidence", lambda *_args, **_kwargs: record
    )
    monkeypatch.setattr(evidence, "verify_evidence_integrity", lambda _: False)
    monkeypatch.setattr(
        evidence,
        "_s3_client",
        lambda: (_ for _ in ()).throw(AssertionError("storage must not be called")),
    )

    with pytest.raises(HTTPException) as rejected:
        evidence.download_evidence(str(record.id), _request(tenant_id), db=object())
    assert rejected.value.status_code == 409


def test_access_audit_persists_actor_and_purpose(monkeypatch):
    tenant_id = str(uuid4())
    record = _record(tenant_id)
    captured = {}
    authenticated_db = object()

    monkeypatch.setattr(
        "app.services.event_backbone.publish_audit_event",
        lambda _producer, _tenant_id, event, **kwargs: captured.update(event)
        or captured.update(kwargs)
        or None,
    )

    evidence._audit_access(record, _request(tenant_id), "download", authenticated_db)

    assert captured["actor_id"] == "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    assert captured["actor_type"] == "user"
    assert captured["action"] == "evidence:download"
    assert "purpose=download" in captured["execution_trace"]
    assert captured["db"] is authenticated_db


def test_evidence_list_audits_each_returned_record(monkeypatch):
    tenant_id = str(uuid4())
    record = _record(tenant_id)
    operations = []
    monkeypatch.setattr(
        evidence.evidence_service,
        "list_evidence",
        lambda *_args, **_kwargs: ([record], 1),
    )
    monkeypatch.setattr(
        evidence,
        "_audit_access",
        lambda item, _request, operation, _db: operations.append((item.id, operation)),
    )
    monkeypatch.setattr(evidence, "_serialize_record", lambda _record: {"id": "one"})
    monkeypatch.setattr(
        evidence, "EvidenceListResponse", lambda **kwargs: SimpleNamespace(**kwargs)
    )

    response = evidence.list_evidence(_request(tenant_id), db=object())

    assert response.total == 1
    assert operations == [(record.id, "view")]


def test_content_disposition_encodes_control_characters(monkeypatch):
    tenant_id = str(uuid4())
    record = _record(tenant_id, f"tenant-{tenant_id}/report\r\nX-Injected: yes")
    monkeypatch.setattr(
        evidence.evidence_service, "get_evidence", lambda *_args, **_kwargs: record
    )
    monkeypatch.setattr(
        evidence,
        "_s3_client",
        lambda: SimpleNamespace(
            head_object=lambda **_: {
                "ChecksumSHA256": base64.b64encode(bytes.fromhex("a" * 64)).decode()
            },
            get_object=lambda **_: {
                "ChecksumSHA256": base64.b64encode(bytes.fromhex("a" * 64)).decode(),
                "Body": SimpleNamespace(
                    iter_chunks=lambda **_: iter(()), close=lambda: None
                ),
            },
        ),
    )
    monkeypatch.setattr(evidence, "_audit_access", lambda *_args: None)

    response = evidence.download_evidence(
        str(record.id), _request(tenant_id), db=object()
    )

    assert "\r" not in response.headers["content-disposition"]
    assert "\n" not in response.headers["content-disposition"]


def test_expired_evidence_file_deletion_is_audited_before_storage_delete(monkeypatch):
    tenant_id = str(uuid4())
    record = _record(tenant_id)
    record.evidence_data["storage"].update(
        access_policy={"allow_download": True, "allow_delete": True},
        deletion_allowed_at=(
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat(),
    )
    calls = []
    monkeypatch.setattr(
        evidence.evidence_service, "get_evidence", lambda *_args, **_kwargs: record
    )
    monkeypatch.setattr(
        evidence,
        "_s3_client",
        lambda: SimpleNamespace(
            head_object=lambda **kwargs: calls.append(("head", kwargs))
            or {
                "ChecksumSHA256": base64.b64encode(bytes.fromhex("a" * 64)).decode(),
                "ETag": '"immutable"',
            },
            delete_object=lambda **kwargs: calls.append(("delete", kwargs)),
        ),
    )
    monkeypatch.setattr(
        evidence, "_audit_access", lambda *_args, **_kwargs: calls.append(("audit", {}))
    )

    response = evidence.delete_evidence_file(
        str(record.id), _request(tenant_id), db=object()
    )

    assert response.status_code == 204
    assert [operation for operation, _ in calls] == ["head", "audit", "delete"]
    assert calls[-1][1]["IfMatch"] == '"immutable"'


def test_failed_access_closes_stream_and_repeated_request_ids_are_audited(monkeypatch):
    tenant = str(uuid4())
    record = _record(tenant)
    events, closed = [], []
    monkeypatch.setattr(
        evidence.evidence_service, "get_evidence", lambda *a, **k: record
    )
    monkeypatch.setattr(
        "app.services.event_backbone.publish_audit_event",
        lambda p, t, e, **k: events.append(e) or None,
    )
    evidence._audit_access(record, _request(tenant), "download", object())
    evidence._audit_access(record, _request(tenant), "download", object())
    assert events[0]["id"] != events[1]["id"]
    monkeypatch.setattr(
        evidence,
        "_s3_client",
        lambda: SimpleNamespace(
            get_object=lambda **k: {
                "ChecksumSHA256": base64.b64encode(bytes.fromhex("a" * 64)).decode(),
                "Body": SimpleNamespace(close=lambda: closed.append(True)),
            }
        ),
    )
    monkeypatch.setattr(
        "app.services.event_backbone.publish_audit_event",
        lambda *a, **k: RuntimeError("audit unavailable"),
    )
    with pytest.raises(HTTPException) as error:
        evidence.download_evidence(str(record.id), _request(tenant), object())
    assert error.value.status_code == 503
    assert closed == [True]


def test_evidence_file_deletion_respects_retention_policy(monkeypatch):
    tenant_id = str(uuid4())
    record = _record(tenant_id)
    monkeypatch.setattr(
        evidence.evidence_service, "get_evidence", lambda *_args, **_kwargs: record
    )
    monkeypatch.setattr(
        evidence,
        "_s3_client",
        lambda: (_ for _ in ()).throw(AssertionError("storage must not be called")),
    )

    with pytest.raises(HTTPException) as rejected:
        evidence.delete_evidence_file(str(record.id), _request(tenant_id), db=object())
    assert rejected.value.status_code == 403

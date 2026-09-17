from types import SimpleNamespace
from uuid import uuid4

from app.api.v1.endpoints import audit


def test_signed_export_audits_actor_and_purpose(monkeypatch):
    tenant_id = str(uuid4())
    actor_id = str(uuid4())
    captured = {}
    monkeypatch.setattr(
        audit,
        "build_signed_audit_export",
        lambda *_args, **_kwargs: {"manifest": {"export_id": "export-1"}},
    )
    monkeypatch.setattr(
        audit.event_backbone,
        "publish_audit_event",
        lambda _producer, _tenant_id, event, **_kwargs: captured.update(event) or None,
    )
    request = SimpleNamespace(
        state=SimpleNamespace(tenant_id=tenant_id, user_id=actor_id),
        headers={"x-request-id": "request-1"},
    )

    result = audit.create_signed_audit_export(
        request, audit.SignedAuditExportRequest(), db=object()
    )

    assert result["manifest"]["export_id"] == "export-1"
    assert captured["actor_id"] == actor_id
    assert captured["action"] == "audit:export"
    assert "purpose=export" in captured["execution_trace"]

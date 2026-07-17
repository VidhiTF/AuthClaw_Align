from types import SimpleNamespace

from app.api.v1.endpoints import audit


def test_integrity_check_does_not_change_audit_store(monkeypatch):
    request = SimpleNamespace(state=SimpleNamespace(tenant_id="tenant-1"))
    expected = object()
    monkeypatch.setenv("CLICKHOUSE_HOST", "clickhouse")
    monkeypatch.setattr(audit, "_get_clickhouse_client", lambda: object())
    monkeypatch.setattr(audit, "_query_clickhouse", lambda *_args: expected)
    monkeypatch.setattr(
        audit,
        "_query_postgres",
        lambda *_args: (_ for _ in ()).throw(AssertionError("unexpected postgres read")),
    )

    result = audit.get_audit_logs(
        request,
        db=object(),
        limit=10,
        offset=0,
        action=None,
        integrity_check=True,
    )

    assert result is expected

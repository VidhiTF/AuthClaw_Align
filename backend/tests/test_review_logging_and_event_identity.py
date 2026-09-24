"""Reported SQL parameter exposure and repeated finding-event regressions."""
import ast
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4

from app.db import session
from app.api.v1.endpoints import policies, redaction
from app.services import event_backbone, findings_service


def test_runtime_sql_engines_hide_bound_secrets():
    assert session.engine.hide_parameters is True
    if session.PlatformSessionLocal is not None:
        assert session.PlatformSessionLocal.kw['bind'].hide_parameters is True


def test_repeated_finding_actions_have_distinct_event_identity(monkeypatch):
    events = []
    monkeypatch.setattr(findings_service, '_init_kafka_producer', lambda: None)
    monkeypatch.setattr(event_backbone, 'publish_audit_event', lambda producer, tenant, event: events.append(event))
    for _ in range(2):
        findings_service._emit_finding_audit('finding-1', 'tenant-1', 'SOC2', 'FINDING_UPDATED')
    assert len(events) == 2
    assert events[0]['id'] != events[1]['id']


def test_explicit_occurrence_keeps_retry_identity_stable():
    fields = dict(event_type='finding', tenant_id='tenant-1', subject_id='finding-1',
                  identity_action='UPDATED:SOC2', action='finding:UPDATED', reason='test',
                  provider='findings_service', request_id='occurrence-1')
    assert event_backbone.audit_event(**fields)['id'] == event_backbone.audit_event(**fields)['id']
    assert event_backbone.audit_event(**fields)['id'] != event_backbone.audit_event(**{**fields, 'request_id': 'occurrence-2'})['id']


def test_policy_invalidation_failure_logs_only_error_type(monkeypatch, caplog):
    def fail(_):
        raise RuntimeError("redis-host-secret")

    monkeypatch.setattr("redis.from_url", fail)
    with caplog.at_level("WARNING"):
        assert policies._publish_policy_invalidation(uuid4()) is None
    assert "policy_invalidation" in caplog.text
    assert "RuntimeError" in caplog.text
    assert "redis-host-secret" not in caplog.text


def test_redaction_decrypt_failure_preserves_response_without_sensitive_log(monkeypatch, caplog):
    tenant_id = uuid4()
    token = SimpleNamespace(
        id=uuid4(), token_value="[REDACTED]", token_hash="hash", original_value="ciphertext-secret",
        strategy="mask", entity_type=None, expires_at=None, last_used_at=None,
        use_count=0, purged_at=None, created_at=datetime.now(timezone.utc),
    )
    db = MagicMock()
    db.query.return_value.filter.return_value.filter.return_value.filter.return_value.order_by.return_value.all.return_value = [token]

    def fail(_):
        raise RuntimeError("plaintext-secret")

    monkeypatch.setattr(redaction, "decrypt_secret", fail)
    with caplog.at_level("WARNING"):
        result = redaction.get_tokenization_map(
            tenant_id, SimpleNamespace(state=SimpleNamespace(tenant_id=tenant_id)), db
        )
    assert result[0].original_value == "[Decryption Failed]"
    assert "redaction_decrypt" in caplog.text
    assert "RuntimeError" in caplog.text
    assert "ciphertext-secret" not in caplog.text
    assert "plaintext-secret" not in caplog.text


def test_backend_runtime_has_no_bare_prints_or_direct_stream_writes():
    backend = Path(__file__).resolve().parents[1]
    sources = [backend / "main.py", *(backend / "app").rglob("*.py")]
    for source in sources:
        for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call):
                continue
            target = node.func
            assert not (isinstance(target, ast.Name) and target.id in {"print", "pprint"}), source
            assert not (isinstance(target, ast.Attribute) and target.attr in {"print", "pprint"}), source
            assert not (
                isinstance(target, ast.Attribute) and target.attr == "write"
                and isinstance(target.value, ast.Attribute)
                and target.value.attr in {"stdout", "stderr"}
            ), source

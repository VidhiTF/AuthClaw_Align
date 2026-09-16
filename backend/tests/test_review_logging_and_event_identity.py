"""Reported SQL parameter exposure and repeated finding-event regressions."""
from app.db import session
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

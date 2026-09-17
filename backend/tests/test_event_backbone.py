from app.services import event_backbone


def test_stable_event_id_is_deterministic_for_same_identity():
    first = event_backbone.stable_event_id(
        event_type="workflow",
        tenant_id="tenant-1",
        subject_id="workflow-1",
        action="TRANSITION:action:status:req-1",
        trace=["workflow_id=workflow-1", "transition=TRANSITION"],
    )
    second = event_backbone.stable_event_id(
        event_type="workflow",
        tenant_id="tenant-1",
        subject_id="workflow-1",
        action="TRANSITION:action:status:req-1",
        trace=["workflow_id=workflow-1", "transition=TRANSITION"],
    )

    assert first == second


def test_backend_event_topic_names_match_backbone_contract():
    assert event_backbone.GATEWAY_TRAFFIC_TOPIC == "gateway.traffic"
    assert event_backbone.AUDIT_EVENTS_TOPIC == "audit.events"
    assert event_backbone.AUDIT_DLQ_TOPIC == "audit.deadletter"


def test_publish_persists_before_kafka(monkeypatch):
    order = []

    monkeypatch.setattr(
        event_backbone,
        "persist_audit_event",
        lambda _event, **kwargs: order.append("postgres"),
    )
    monkeypatch.setattr(
        event_backbone,
        "publish_pending_audit_events",
        lambda _producer, _tenant: order.append("outbox"),
    )

    assert event_backbone.publish_audit_event(object(), "tenant-1", {}) is None
    assert order == ["postgres", "outbox"]


def test_publish_stops_when_postgres_fails(monkeypatch):
    failure = RuntimeError("postgres unavailable")
    monkeypatch.setattr(
        event_backbone, "persist_audit_event", lambda _event, **kwargs: failure
    )

    assert event_backbone.publish_audit_event(object(), "tenant-1", {}) is failure

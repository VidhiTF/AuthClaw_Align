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

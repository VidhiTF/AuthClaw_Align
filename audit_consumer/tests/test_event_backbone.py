import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from event_backbone import AUDIT_DLQ_TOPIC, AUDIT_EVENTS_TOPIC, GATEWAY_TRAFFIC_TOPIC, TOPICS


def test_required_topics_are_defined_with_tenant_keying():
    assert set(TOPICS) == {GATEWAY_TRAFFIC_TOPIC, AUDIT_EVENTS_TOPIC, AUDIT_DLQ_TOPIC}
    for spec in TOPICS.values():
        assert spec.partitions > 0
        assert spec.retention_ms > 0
        assert spec.cleanup_policy == "delete"
        assert spec.key_field == "tenant_id"
        assert "Replay" in spec.replay_policy or "Reprocess" in spec.replay_policy


def test_deadletter_retention_is_longer_than_source_topics():
    assert TOPICS[AUDIT_DLQ_TOPIC].retention_ms > TOPICS[AUDIT_EVENTS_TOPIC].retention_ms
    assert TOPICS[AUDIT_EVENTS_TOPIC].retention_ms > TOPICS[GATEWAY_TRAFFIC_TOPIC].retention_ms

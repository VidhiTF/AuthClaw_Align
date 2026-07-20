import pytest

from app.orchestrator import runner
from app.services import event_backbone, evidence_service, findings_service


@pytest.fixture(autouse=True)
def isolate_audit_kafka(monkeypatch):
    monkeypatch.setattr(event_backbone, "make_kafka_producer", lambda: None)
    monkeypatch.setattr(runner, "_kafka_producer", None)
    monkeypatch.setattr(evidence_service, "_kafka_producer", None)
    monkeypatch.setattr(findings_service, "_kafka_producer", None)

import pytest

from app.services import compliance_scoring
from app.services.compliance_scoring import FrameworkMetrics
from app.api.v1.endpoints.compliance_scores import ControlScoreResponse


def _metrics(**overrides):
    values = {
        "framework": "SOC2",
        "evidence_count": 6,
        "audit_event_count": 30,
        "framework_audit_event_count": 6,
        "audit_hash_count": 30,
        "redaction_count": 12,
        "active_policy_count": 1,
        "active_gateway_count": 1,
        "active_api_key_count": 1,
        "pending_approvals": 0,
        "open_findings": 0,
        "critical_findings": 0,
        "high_findings": 0,
        "resolved_findings": 2,
        "pii_evidence_count": 2,
        "approval_evidence_count": 1,
        "remediation_audit_count": 2,
        "policy_evidence_count": 1,
    }
    values.update(overrides)
    return FrameworkMetrics(**values)


def test_score_control_marks_strong_signal_compliant():
    control = next(item for item in compliance_scoring.CONTROL_CATALOG["SOC2"] if item["id"] == "CC7.2")

    scored = compliance_scoring.score_control(control, _metrics())

    assert scored["status"] == "compliant"
    assert scored["score"] == 100.0
    assert any("audit events" in item for item in scored["evidence"])


def test_score_control_penalizes_open_critical_findings():
    control = next(item for item in compliance_scoring.CONTROL_CATALOG["SOC2"] if item["id"] == "CC7.3")

    scored = compliance_scoring.score_control(
        control,
        _metrics(open_findings=4, critical_findings=2, high_findings=1, remediation_audit_count=0, resolved_findings=0),
    )

    assert scored["status"] in {"partial", "non_compliant"}
    assert scored["score"] < 75
    assert any("Open findings" in item or "open findings" in item for item in scored["gaps"])


def test_score_framework_uses_catalog_weights(monkeypatch):
    monkeypatch.setattr(compliance_scoring, "collect_metrics", lambda _db, _tenant, framework: _metrics(framework=framework))
    monkeypatch.setattr(
        compliance_scoring,
        "_control_traceability",
        lambda *_args: {
            "evidence_total": 1,
            "finding_total": 0,
            "audit_event_total": 1,
            "evidence": [],
            "findings": [],
            "audit_events": [],
            "links": {
                "evidence_url": "/evidence?framework=SOC2",
                "findings_url": "/findings?framework=SOC2",
                "audit_url": "/audit",
            },
        },
    )

    result = compliance_scoring.score_framework(object(), "00000000-0000-0000-0000-000000000001", "SOC2")

    assert result["framework"] == "SOC2"
    assert result["score"] >= 90
    assert result["readiness_level"] == "monitor"
    assert any(control["implementation_status"] == "partial" for control in result["controls"])
    assert len(result["controls"]) == len(compliance_scoring.CONTROL_CATALOG["SOC2"])
    assert result["controls"][0]["traceability"]["links"]["evidence_url"] == "/evidence?framework=SOC2"
    assert result["controls"][0]["traceability"]["links"]["findings_url"] == "/findings?framework=SOC2"


def test_soc2_catalog_matches_frozen_p0_matrix_and_exposes_ownership():
    controls = compliance_scoring.CONTROL_CATALOG["SOC2"]

    assert [control["id"] for control in controls] == [
        "CC6.1", "CC6.6", "CC7.1", "CC7.2", "CC7.3", "CC8.1", "A1.2", "C1.1"
    ]
    assert sum(control["weight"] for control in controls) == 1.0
    assert all(control["product_owners"] for control in controls)
    assert all(control["operational_owners"] for control in controls)
    assert all(control["evidence_sources"] for control in controls)
    assert all(control["collection_frequency"] for control in controls)


def test_open_evidence_gap_cannot_be_reported_compliant():
    control = next(item for item in compliance_scoring.CONTROL_CATALOG["SOC2"] if item["id"] == "CC6.1")

    scored = compliance_scoring.score_control(control, _metrics(active_api_key_count=0))

    assert scored["score"] <= 84.9
    assert scored["status"] == "partial"
    assert scored["exceptions"]
    assert any("API key" in item["message"] for item in scored["exceptions"])


def test_missing_control_specific_evidence_blocks_audit_ready(monkeypatch):
    monkeypatch.setattr(compliance_scoring, "collect_metrics", lambda _db, _tenant, framework: _metrics(framework=framework))
    monkeypatch.setattr(
        compliance_scoring,
        "_control_traceability",
        lambda *_args: {
            "evidence_total": 0,
            "finding_total": 0,
            "audit_event_total": 0,
            "evidence": [],
            "findings": [],
            "audit_events": [],
            "links": {"evidence_url": "/evidence", "findings_url": "/findings", "audit_url": "/audit"},
        },
    )

    result = compliance_scoring.score_framework(object(), "00000000-0000-0000-0000-000000000001", "SOC2")

    assert result["readiness_level"] != "audit_ready"
    assert all(control["status"] != "compliant" for control in result["controls"])
    assert all("No control-specific operating evidence" in control["gaps"] for control in result["controls"])


def test_score_all_frameworks_can_skip_expensive_traceability(monkeypatch):
    monkeypatch.setattr(compliance_scoring, "collect_metrics", lambda _db, _tenant, framework: _metrics(framework=framework))
    monkeypatch.setattr(
        compliance_scoring,
        "_control_traceability",
        lambda *_args: (_ for _ in ()).throw(AssertionError("traceability should be skipped")),
    )

    result = compliance_scoring.score_all_frameworks(
        object(),
        "00000000-0000-0000-0000-000000000001",
        persist=False,
        include_traceability=False,
    )

    assert len(result["frameworks"]) == 3
    assert all("traceability" not in control for framework in result["frameworks"] for control in framework["controls"])
    assert ControlScoreResponse.model_validate(result["frameworks"][0]["controls"][0]).traceability is None
    assert {result["generated_at"], result["trust_summary"]["generated_at"], *[item["generated_at"] for item in result["frameworks"]]} == {result["generated_at"]}


def test_data_source_failures_are_not_reported_as_zero_or_empty():
    class FailedQuery:
        def count(self):
            raise RuntimeError("data source unavailable")

    class FailedDB:
        def query(self, *_args):
            raise RuntimeError("data source unavailable")

    with pytest.raises(RuntimeError, match="data source unavailable"):
        compliance_scoring._safe_count(FailedQuery())
    with pytest.raises(RuntimeError, match="data source unavailable"):
        compliance_scoring._control_traceability(
            FailedDB(), "00000000-0000-0000-0000-000000000001", "SOC2", compliance_scoring.CONTROL_CATALOG["SOC2"][0]
        )


def test_readiness_levels_are_stable():
    assert compliance_scoring.readiness_level(95) == "audit_ready"
    assert compliance_scoring.readiness_level(80) == "monitor"
    assert compliance_scoring.readiness_level(65) == "needs_attention"
    assert compliance_scoring.readiness_level(20) == "insufficient_evidence"


def test_score_provenance_and_missing_evidence(monkeypatch):
    from app.api.v1.endpoints.compliance_scores import ComplianceScoreResponse
    for timestamp in (None, "2026-09-17T10:00:00+00:00"):
        monkeypatch.setattr(compliance_scoring, "collect_metrics", lambda _db, _tenant, framework:
                            _metrics(framework=framework, evidence_timestamp=timestamp))
        result = ComplianceScoreResponse.model_validate(compliance_scoring.score_all_frameworks(
            object(), "00000000-0000-0000-0000-000000000001", persist=False, include_traceability=False))
        assert result.calculation_version == "control-signals-v1"
        assert result.evidence_timestamp == timestamp
        assert "source errors abort" in result.missing_control_treatment
        assert all(item.evidence_timestamp == timestamp for item in result.frameworks)


def test_historical_snapshot_does_not_invent_calculation_provenance():
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    db = MagicMock()
    row = SimpleNamespace(framework="SOC2", snapshot_date="2026-09-01", overall_score=75,
                          readiness_level="monitor", evidence_count=2, audit_event_count=3,
                          open_findings=1, critical_findings=0, generated_at=None, control_scores={})
    db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [row]
    result = compliance_scoring.score_history(db, "00000000-0000-0000-0000-000000000001")[0]
    assert result["calculation_version"] is None
    assert result["evidence_timestamp"] is None
    assert result["missing_control_treatment"] is None


def test_trust_summary_maps_existing_control_statuses_once():
    frameworks = [
        {
            "framework": "SOC2",
            "controls": [
                {"id": "one", "name": "One", "score": 90.0, "status": "compliant"},
                {"id": "two", "name": "Two", "score": 70.0, "status": "partial"},
                {"id": "three", "name": "Three", "score": 40.0, "status": "non_compliant"},
            ],
        }
    ]

    summary = compliance_scoring._build_trust_summary(frameworks)

    assert summary["counts"] == {"verified": 1, "in_progress": 1, "planned": 1}
    assert summary["verified"][0]["id"] == "one"
    assert summary["in_progress"][0]["id"] == "two"
    assert summary["planned"][0]["id"] == "three"
    control_ids = [item["id"] for bucket in ("verified", "in_progress", "planned") for item in summary[bucket]]
    assert sorted(control_ids) == ["one", "three", "two"]
    assert len(control_ids) == len(set(control_ids))


def test_trust_summary_does_not_modify_existing_control_fields():
    control = {"id": "one", "name": "One", "score": 90.0, "status": "compliant", "evidence": ["signal"]}
    frameworks = [{"framework": "SOC2", "controls": [control]}]

    compliance_scoring._build_trust_summary(frameworks)

    assert control == {
        "id": "one",
        "name": "One",
        "score": 90.0,
        "status": "compliant",
        "evidence": ["signal"],
    }

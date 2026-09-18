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


def _qualified():
    return {"state": "qualified", "reason_codes": [], "required_count": 2,
            "qualified_count": 2, "as_of": "2026-09-18T00:00:00+00:00",
            "valid_until": "2026-09-19T00:00:00+00:00", "gaps": [], "evidence_ids": ["assessment"]}


@pytest.fixture(autouse=True)
def assessment_boundary(monkeypatch):
    # The qualification service has real writer/read integration tests; these
    # cases exercise the scoring contract after that boundary's decision.
    monkeypatch.setattr(compliance_scoring.control_assessments, "assess_framework",
                        lambda db, tenant, framework, as_of: {})


def test_score_control_marks_qualified_strong_signal_compliant():
    control = next(item for item in compliance_scoring.CONTROL_CATALOG["SOC2"] if item["id"] == "CC7.2")

    scored = compliance_scoring.score_control(control, _metrics(), _qualified())

    assert scored["status"] == "compliant"
    assert scored["score"] == 100.0
    assert any("audit events" in item for item in scored["evidence"])


def test_reviewed_evidence_with_missing_activity_explains_partial_state():
    control = next(item for item in compliance_scoring.CONTROL_CATALOG["SOC2"] if item["id"] == "CC7.2")
    scored = compliance_scoring.score_control(control, _metrics(audit_event_count=0), _qualified())
    assert scored["status"] != "compliant"
    assert scored["evidence_assessment"]["state"] == "blocked"
    assert "activity_gap" in scored["evidence_assessment"]["reason_codes"]
    assert "No audit events" in scored["gaps"]


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
    monkeypatch.setattr(compliance_scoring.control_assessments, "assess_framework",
        lambda db, tenant, framework, as_of: {item["id"]: _qualified() for item in compliance_scoring.CONTROL_CATALOG[framework]})
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
    assert all(control["product_roles"] for control in controls)
    assert all(control["operational_roles"] for control in controls)
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
    assert all("missing_assessment" in control["evidence_assessment"]["reason_codes"] for control in result["controls"])


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


def test_t10_activity_counts_never_qualify_control():
    control = next(item for item in compliance_scoring.CONTROL_CATALOG["SOC2"] if item["id"] == "CC7.2")
    result = compliance_scoring.score_control(control, _metrics())
    assert result["status"] != "compliant"
    assert result["score"] < 85
    assert result["evidence_assessment"]["state"] == "blocked"
    assert "missing_assessment" in result["evidence_assessment"]["reason_codes"]


def test_t10_aggregate_preserves_child_readiness_restriction():
    frameworks = [{"framework": "SOC2", "score": 94.0, "readiness_level": "monitor"}]
    assert compliance_scoring.aggregate_readiness(frameworks) == (94.0, "monitor")
    assert compliance_scoring.aggregate_readiness([]) == (0.0, "insufficient_evidence")


def test_t10_qualification_is_independent_of_traceability(monkeypatch):
    monkeypatch.setattr(compliance_scoring, "collect_metrics", lambda db, tid, framework: _metrics(framework=framework))
    monkeypatch.setattr(compliance_scoring, "_control_traceability", lambda *args: {
        "evidence_total": 0, "finding_total": 1000, "audit_event_total": 1000})
    with_detail = compliance_scoring.score_framework(object(), "00000000-0000-0000-0000-000000000001", "SOC2")
    no_detail = compliance_scoring.score_framework(object(), "00000000-0000-0000-0000-000000000001", "SOC2", include_traceability=False)
    assert all(c["status"] != "compliant" for c in with_detail["controls"])
    assert [(c["score"], c["status"], c["gaps"]) for c in with_detail["controls"]] == [
        (c["score"], c["status"], c["gaps"]) for c in no_detail["controls"]]
    assert with_detail["calculation_version"] == no_detail["calculation_version"]


def test_t10_findings_block_even_controls_without_finding_signal():
    control = compliance_scoring.CONTROL_CATALOG["SOC2"][0]
    result = compliance_scoring.score_control(control, _metrics(open_findings=1), _qualified())
    assert result["status"] != "compliant"
    assert "open_finding" in result["evidence_assessment"]["reason_codes"]
    assert "ACCEPTED_RISK" not in compliance_scoring.RESOLVED_STATUSES

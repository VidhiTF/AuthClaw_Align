from app.services import compliance_scoring
from app.services.compliance_scoring import FrameworkMetrics


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
    control = compliance_scoring.CONTROL_CATALOG["SOC2"][1]

    scored = compliance_scoring.score_control(control, _metrics())

    assert scored["status"] == "compliant"
    assert scored["score"] == 100.0
    assert any("audit events" in item for item in scored["evidence"])


def test_score_control_penalizes_open_critical_findings():
    control = compliance_scoring.CONTROL_CATALOG["SOC2"][3]

    scored = compliance_scoring.score_control(
        control,
        _metrics(open_findings=4, critical_findings=2, high_findings=1, remediation_audit_count=0, resolved_findings=0),
    )

    assert scored["status"] in {"partial", "non_compliant"}
    assert scored["score"] < 75
    assert any("Open findings" in item or "open findings" in item for item in scored["gaps"])


def test_score_framework_uses_catalog_weights(monkeypatch):
    monkeypatch.setattr(compliance_scoring, "collect_metrics", lambda _db, _tenant, framework: _metrics(framework=framework))

    result = compliance_scoring.score_framework(object(), "00000000-0000-0000-0000-000000000001", "SOC2")

    assert result["framework"] == "SOC2"
    assert result["score"] >= 90
    assert result["readiness_level"] == "audit_ready"
    assert len(result["controls"]) == len(compliance_scoring.CONTROL_CATALOG["SOC2"])
    assert result["controls"][0]["traceability"]["links"]["evidence_url"] == "/evidence?framework=SOC2"
    assert result["controls"][0]["traceability"]["links"]["findings_url"] == "/findings?framework=SOC2"


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

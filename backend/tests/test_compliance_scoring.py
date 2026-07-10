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


def test_readiness_levels_are_stable():
    assert compliance_scoring.readiness_level(95) == "audit_ready"
    assert compliance_scoring.readiness_level(80) == "monitor"
    assert compliance_scoring.readiness_level(65) == "needs_attention"
    assert compliance_scoring.readiness_level(20) == "insufficient_evidence"

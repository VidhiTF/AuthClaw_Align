"""Calculation identities follow executable policy, independently of display names."""
from pathlib import Path

import pytest

from app.core.compliance_policy import calculation_version


@pytest.fixture
def sources():
    services = Path(__file__).resolve().parents[1] / "app" / "services"
    return {"scoring_source": (services / "compliance_scoring.py").read_text(encoding="utf-8"),
            "assessment_source": (services / "control_assessments.py").read_text(encoding="utf-8")}


@pytest.mark.parametrize("old,new", [("if score >= 85:", "if score >= 86:"),
    ('"weight": 0.125', '"weight": 0.126'), ('84.9', '84.8'),
    ('RESOLVED_STATUSES = ("RESOLVED", "FALSE_POSITIVE")', 'RESOLVED_STATUSES = ("RESOLVED",)')])
def test_score_policy_changes_have_distinct_identity(sources, old, new):
    before = calculation_version(**sources)
    assert old in sources["scoring_source"]
    sources["scoring_source"] = sources["scoring_source"].replace(old, new)
    assert calculation_version(**sources) != before


@pytest.mark.parametrize("old,new", [('"monitoring_operation": 1', '"monitoring_operation": 2'),
    ('if uid == approval.requester_id:', 'if False:'),
    ('expiry <= as_of', 'expiry < as_of')])
def test_qualification_rules_have_distinct_identity(sources, old, new):
    before = calculation_version(**sources)
    assert old in sources["assessment_source"]
    sources["assessment_source"] = sources["assessment_source"].replace(old, new)
    assert calculation_version(**sources) != before


def test_formatting_and_catalog_owner_names_do_not_change_calculation(sources):
    before = calculation_version(**sources)
    sources["scoring_source"] = "# release comment\n\n" + sources["scoring_source"].replace(
        '"product_roles": ["platform_security"]', '"product_roles": ["new_role"]')
    sources["assessment_source"] += "\n# comments do not change rules\n"
    assert calculation_version(**sources) == before


def test_incomplete_policy_fails_closed(sources):
    sources["scoring_source"] = sources["scoring_source"].replace("def control_status(", "def missing_status(")
    with pytest.raises(RuntimeError, match="Incomplete"):
        calculation_version(**sources)


def test_integrity_version_changes_calculation(sources):
    before = calculation_version(**sources)
    integrity = Path(__file__).resolve().parents[1] / "app" / "core" / "evidence_integrity.py"
    sources["integrity_source"] = integrity.read_text(encoding="utf-8").replace("INTEGRITY_VERSION = 1", "INTEGRITY_VERSION = 2")
    assert calculation_version(**sources) != before


def test_deployed_version_matches_policy(sources):
    from app.services.control_assessments import CALCULATION_VERSION
    assert CALCULATION_VERSION == calculation_version(**sources)

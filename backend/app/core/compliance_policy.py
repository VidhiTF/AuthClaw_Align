"""Fingerprint the deployed scoring rules without importing either service.

Source ships with the application. Missing policy definitions fail startup rather
than silently assigning a previous calculation's identity to unknown rules.
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path


_SCORING_DEFINITIONS = {
    "FRAMEWORKS", "RESOLVED_STATUSES", "FrameworkMetrics", "CONTROL_CATALOG",
    "_tenant_uuid", "_safe_count", "_framework_audit_count", "collect_metrics",
    "_signal_score", "readiness_level", "control_status", "score_control",
    "_calculate_framework", "aggregate_readiness",
}


def calculation_version(*, scoring_source: str | None = None, assessment_source: str | None = None,
                        integrity_source: str | None = None) -> str:
    services = Path(__file__).resolve().parents[1] / "services"
    scoring = ast.parse(scoring_source if scoring_source is not None else
                        (services / "compliance_scoring.py").read_text(encoding="utf-8-sig"))
    assessments = ast.parse(assessment_source if assessment_source is not None else
                            (services / "control_assessments.py").read_text(encoding="utf-8-sig"))
    integrity = ast.parse(integrity_source if integrity_source is not None else
                          Path(__file__).with_name("evidence_integrity.py").read_text(encoding="utf-8-sig"))
    policy, found = [], set()
    for node in scoring.body:
        name = _definition_name(node)
        if name not in _SCORING_DEFINITIONS:
            continue
        found.add(name)
        if name == "CONTROL_CATALOG":
            catalog = ast.literal_eval(node.value)
            # Personnel, descriptions and display traceability do not change rules.
            policy.append({framework: [{key: control[key] for key in
                ("id", "weight", "signals", "implementation_status") if key in control}
                for control in controls] for framework, controls in catalog.items()})
        else:
            policy.append(ast.dump(node, include_attributes=False))
    if found != _SCORING_DEFINITIONS:
        raise RuntimeError("Incomplete compliance scoring policy")
    assessment_names = set()
    for node in assessments.body:
        name = _definition_name(node)
        if name and name not in {"CALCULATION_VERSION", "resolve_owners"}:
            assessment_names.add(name)
            policy.append(ast.dump(node, include_attributes=False))
    if not {"CONTROL_REQUIREMENTS", "PRODUCER", "AssessmentProposal", "assess_framework",
            "_trusted_proposal", "propose_assessment", "review_assessment"} <= assessment_names:
        raise RuntimeError("Incomplete compliance qualification policy")
    integrity_names = set()
    for node in integrity.body:
        name = _definition_name(node)
        if name:
            integrity_names.add(name)
            policy.append(ast.dump(node, include_attributes=False))
    if not {"INTEGRITY_ALGORITHM", "INTEGRITY_VERSION", "verify_evidence_integrity",
            "compute_evidence_integrity_hash", "canonical_evidence_payload"} <= integrity_names:
        raise RuntimeError("Incomplete evidence integrity policy")
    digest = hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return "evidence-v3-" + digest[:20]


def _definition_name(node: ast.AST) -> str | None:
    if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
        return node.name
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return node.target.id
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        return node.targets[0].id
    return None

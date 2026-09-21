"""T10 diagnostic boundary tests; no database bootstrap or live connections."""

import ast
import csv
import importlib.util
import io
import json
import os
import sys
import time
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy import text


ROOT = Path(__file__).parents[1]


@pytest.fixture
def scoring(monkeypatch):
    database = ModuleType("database")
    database.engine = MagicMock()
    database.engine.begin = database.engine.connect
    monkeypatch.setitem(sys.modules, "database", database)
    spec = importlib.util.spec_from_file_location("t10_agent_scoring", ROOT / "services/compliance_evidence_engine.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.CONTROL_CATALOG = module.CONTROL_CATALOG[:1]
    return module


def calculate(scoring, items=(), previous=()):
    conn = scoring.engine.connect.return_value.__enter__.return_value
    conn.execute.return_value.fetchall.side_effect = [
        [SimpleNamespace(control_id="SOC2-CC6.1", _mapping=item) for item in items], list(previous)
    ]
    scorer = scoring.ComplianceEvidenceEngine()
    scorer.map_evidence = MagicMock()
    scorer.catalog = lambda: [scoring.CONTROL_CATALOG[0]]
    return scorer.calculate_scores(42), conn


@pytest.mark.parametrize("items", [[], [dict(source_type="audit", impact=1000000)], [dict(source_type="finding", impact=-50)]])
def test_activity_never_becomes_affirmative_compliance(scoring, items):
    payload, conn = calculate(scoring, items)
    assert payload["soc2"] is None if not items else 0 <= payload["soc2"] <= 84
    assert payload["status"] == "unassessed"
    assert payload["authoritative"] is False
    assert payload["score_kind"] == "diagnostic"
    assert payload["calculation_version"] == "agent-diagnostic-v2"
    control = payload["soc2_controls"]["items"][0]
    assert control["status"] == ("unassessed" if items else "unknown")
    assert control["evidence_status"] == "unsupported"
    assert control["evidence_gaps"]
    assert payload["soc2_controls"]["passed"] == 0
    persisted = [call.args[1] for call in conn.execute.call_args_list if "INSERT INTO compliance_control_scores" in str(call.args[0])]
    assert persisted[0]["status"] == control["status"]
    assert persisted[0]["score"] == control["score"]
    assert json.loads(persisted[0]["metadata"])["calculation_version"] == payload["calculation_version"]


def test_empty_evidence_has_null_diagnostic_score(scoring):
    payload, conn = calculate(scoring)
    assert payload["soc2"] is None
    assert payload["soc2_controls"]["unknown"] == 1
    persisted = [call.args[1] for call in conn.execute.call_args_list if "INSERT INTO compliance_control_scores" in str(call.args[0])]
    assert persisted[0]["score"] is None
    assert persisted[0]["status"] == "unknown"


@pytest.mark.parametrize("version, expected_previous", [(None, None), ("agent-diagnostic-v2", 84)])
def test_score_change_compares_only_same_calculation_version(scoring, version, expected_previous):
    previous = SimpleNamespace(framework="SOC2", control_id="SOC2-CC6.1", score=84, metadata=json.dumps({"calculation_version": version}))
    _, conn = calculate(scoring, previous=[previous])
    changes = [call.args[1] for call in conn.execute.call_args_list if "INSERT INTO compliance_score_changes" in str(call.args[0])]
    assert changes[0]["previous_score"] == expected_previous


def test_score_history_is_explicitly_legacy_and_unassessed(scoring):
    conn = scoring.engine.connect.return_value.__enter__.return_value
    conn.execute.return_value.fetchall.return_value = [SimpleNamespace(_mapping={"current_score": 100, "metadata": "{}"})]
    history = scoring.ComplianceEvidenceEngine().score_changes(42)
    assert history[0]["current_score"] == 100  # Historical data is preserved.
    assert history[0]["calculation_version"] == "legacy-unknown"
    assert history[0]["status"] == "unassessed"
    assert history[0]["authoritative"] is False


def test_exported_activity_has_explicit_unsupported_qualification(scoring):
    conn = scoring.engine.connect.return_value.__enter__.return_value
    conn.execute.return_value.fetchall.return_value = [SimpleNamespace(_mapping={
        "framework": "SOC2", "control_id": "SOC2-CC6.1", "source_type": "audit", "source_id": "1",
        "evidence_hash": "legacy-hash", "reason": "activity", "impact": 5, "created_at": "2026-09-18",
    })]
    scorer = scoring.ComplianceEvidenceEngine()
    scorer.calculate_scores = MagicMock()
    rows = list(csv.DictReader(io.StringIO(scorer.evidence_csv(42).decode())))
    assert rows[0]["evidence_status"] == "unsupported"
    assert rows[0]["calculation_version"] == "agent-diagnostic-v2"
    assert rows[0]["score_kind"] == "diagnostic"
    assert conn.execute.call_args.args[1]["tenant_id"] == 42


def test_read_failure_propagates_without_persisting(scoring):
    conn = scoring.engine.connect.return_value.__enter__.return_value
    conn.execute.side_effect = RuntimeError("database unavailable")
    scorer = scoring.ComplianceEvidenceEngine()
    scorer.map_evidence = MagicMock()
    scorer.catalog = lambda: [scoring.CONTROL_CATALOG[0]]
    with pytest.raises(RuntimeError, match="database unavailable"):
        scorer.calculate_scores(42)
    assert not any("INSERT INTO compliance_control_scores" in str(call.args[0]) for call in conn.execute.call_args_list)


def load_functions(*names, relative_path="main.py", **bindings):
    tree = ast.parse((ROOT / relative_path).read_text(encoding="utf-8"))
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    for node in nodes:
        node.decorator_list = []
    namespace = dict(Any=Any, Dict=Dict, List=List, Optional=Optional, datetime=datetime, timezone=timezone,
                     Header=lambda *_: None, JSONResponse=JSONResponse, get_current_tenant_id=lambda: "42")
    namespace.update(bindings)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), relative_path, "exec"), namespace)
    return namespace


def test_compact_explorer_preserves_diagnostic_decision(scoring):
    payload, _ = calculate(scoring)
    compact = load_functions("_compact_framework_scores")["_compact_framework_scores"](payload)
    assert compact["status"] == "unassessed"
    assert compact["calculation_version"] == payload["calculation_version"]
    control = compact["soc2_controls"]["items"][0]
    assert control["evidence_status"] == "unsupported"
    assert control["evidence_gaps"]
    assert compact["soc2_controls"]["unknown"] == 1
    assert control["score"] is None


def test_metrics_error_does_not_synthesize_success(scoring):
    scoring.engine.connect.side_effect = RuntimeError("database unavailable")
    namespace = load_functions("get_metrics", logger=MagicMock(), get_all_approvals=lambda: {}, metrics_snapshot=lambda: {})
    response = namespace["get_metrics"]()
    assert response.status_code == 503
    payload = json.loads(response.body)
    assert payload["compliance_score"] is None
    assert payload["status"] == "unavailable"
    assert "database unavailable" not in response.body.decode()


def test_healthy_activity_metrics_cannot_synthesize_compliance(scoring, monkeypatch):
    conn = scoring.engine.connect.return_value.__enter__.return_value
    conn.execute.return_value.scalar.return_value = 0
    conn.execute.return_value.fetchone.return_value = [0]
    conn.execute.return_value.fetchall.return_value = []
    pipeline = MagicMock()
    pipeline.EventPipeline.return_value.delivery_metrics.return_value = {"checkpoints": []}
    monkeypatch.setitem(sys.modules, "services.event_pipeline", pipeline)
    monkeypatch.setitem(sys.modules, "verify_audit", SimpleNamespace(verify_audit_chain=lambda **_: {"valid": True}))
    observability = MagicMock()
    observability.ObservabilityService.return_value._queue_lag.return_value = {
        "status": "unknown", "max_lag_seconds": None, "pending_events": None, "dead_letter_count": None,
    }
    observability.aggregate_health.return_value = "unknown"
    monkeypatch.setitem(sys.modules, "services.observability_service", observability)
    namespace = load_functions("get_metrics", logger=MagicMock(), get_all_approvals=lambda: {}, metrics_snapshot=lambda: {})
    payload = namespace["get_metrics"]()
    assert payload["compliance_score"] is None
    assert payload["compliance_status"] == "unknown"
    assert payload["compliance_authoritative"] is False


def test_signed_auditor_package_keeps_diagnostic_scope(scoring, monkeypatch):
    payload, _ = calculate(scoring)
    fake = MagicMock()
    fake.ComplianceEvidenceEngine.return_value.calculate_scores.return_value = payload
    monkeypatch.setitem(sys.modules, "services.compliance_evidence_engine", fake)
    monkeypatch.setitem(sys.modules, "verify_audit", SimpleNamespace(verify_audit_chain=lambda **_: {"valid": True}))
    namespace = load_functions("_build_auditor_package_payload")
    package = namespace["_build_auditor_package_payload"](42, "SOC2")
    assert package["framework_scores"]["status"] == "unassessed"
    assert package["framework_scores"]["authoritative"] is False


def test_public_signed_trust_state_preserves_unassessed_scores(scoring, monkeypatch):
    payload, _ = calculate(scoring)
    fake = MagicMock()
    fake.ComplianceEvidenceEngine.return_value.calculate_scores.return_value = payload
    monkeypatch.setitem(sys.modules, "services.compliance_evidence_engine", fake)
    monkeypatch.setitem(sys.modules, "services.event_pipeline", MagicMock())
    monkeypatch.setitem(sys.modules, "services.secret_manager", MagicMock())
    monkeypatch.setitem(sys.modules, "verify_audit", SimpleNamespace(
        verify_audit_chain=lambda **_: {"valid": True},
        create_signed_export_package=lambda data, **_: {"payload": data, "manifest": {}, "payload_b64": "signed"},
        verify_signed_export_package=lambda **_: {"valid": True},
    ))
    namespace = load_functions("build_public_trust_state", relative_path="services/trust_center_runtime.py",
        os=os, time=time, _CACHE_LOCK=nullcontext(), _CACHE={},
        get_current_tenant_id=lambda: "42", validate_tenant_id=lambda _: None,
        _active_tenant_row=lambda _: SimpleNamespace(id=42, name="Fixture", domain="example.test"),
        _metrics_summary=lambda _: {}, _provider_status=lambda _: {}, _certificate_status=lambda: {})
    result = namespace["build_public_trust_state"](force_refresh=True)
    scores = result["payload"]["framework_scores"]
    assert scores["status"] == "unassessed"
    assert scores["authoritative"] is False
    assert scores["calculation_version"] == "agent-diagnostic-v2"


def test_explorer_score_failure_returns_unavailable(scoring, monkeypatch):
    fake = MagicMock(CONTROL_CATALOG=scoring.CONTROL_CATALOG)
    fake.ComplianceEvidenceEngine.return_value.calculate_scores.side_effect = RuntimeError("database unavailable")
    monkeypatch.setitem(sys.modules, "services.compliance_evidence_engine", fake)
    namespace = load_functions("get_compliance_framework_explorer", HTTPException=HTTPException, resolve_tenant=lambda *_: 42)
    with pytest.raises(HTTPException) as caught:
        namespace["get_compliance_framework_explorer"]()
    assert caught.value.status_code == 503


def test_legacy_snapshot_does_not_write_or_alert(scoring):
    namespace = load_functions("record_compliance_snapshot", relative_path="document_processing/drift.py", logger=MagicMock(), engine=scoring.engine, get_current_framework_scores=lambda: {"SOC2": 100}, text=lambda value: value)
    namespace["record_compliance_snapshot"]()
    scoring.engine.connect.assert_not_called()


def test_report_has_no_assessed_score_without_qualified_evidence(scoring, monkeypatch):
    monkeypatch.setitem(sys.modules, "document_processing.drift", SimpleNamespace(get_current_framework_scores=lambda: {}))
    conn = scoring.engine.connect.return_value.__enter__.return_value
    conn.execute.return_value.scalar.return_value = 0
    namespace = load_functions("get_live_stats", relative_path="document_processing/reports.py",
                               engine=scoring.engine, text=text, validate_tenant_id=lambda tenant: None,
                               HTTPException=HTTPException)
    payload = namespace["get_live_stats"](42)
    assert payload["compliance_score"] is None
    assert payload["compliance_status"] == "unassessed"
    assert payload["compliance_authoritative"] is False
    report = load_functions("generate_executive_summary_report", relative_path="document_processing/reports.py",
        io=io, csv=csv, json=json, get_live_stats=lambda tenant: payload)["generate_executive_summary_report"]("csv", 42)
    assert b"Unassessed" in report
    assert b"agent-diagnostic-v2" in report
    assert b"100%" not in report
    assert all(call.args[1]["tenant_id"] == 42 for call in conn.execute.call_args_list)
    scoring.engine.connect.side_effect = RuntimeError("database unavailable")
    with pytest.raises(HTTPException) as unavailable:
        namespace["get_live_stats"](42)
    assert unavailable.value.status_code == 503


def test_legacy_framework_adapter_has_no_tenant_or_failure_fallback(scoring):
    namespace = load_functions("get_current_framework_scores", relative_path="document_processing/drift.py", logger=MagicMock(), engine=scoring.engine)
    assert namespace["get_current_framework_scores"]() == {}
    scoring.engine.connect.assert_not_called()

"""Execute actual telemetry functions without starting the agent or a live database."""

import ast
import csv
import io
import json
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
import sys
import unittest
from unittest.mock import MagicMock, patch

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


def load_functions(path, names, **namespace):
    tree = ast.parse(path.read_text())
    exec(
        compile(
            ast.Module(
                body=[node for node in tree.body if getattr(node, "name", "") in names],
                type_ignores=[],
            ),
            str(path),
            "exec",
        ),
        namespace,
    )
    return namespace


class TruthfulTelemetryTests(unittest.TestCase):
    def test_measured_zero_and_unknown_latency_are_distinct_and_audit_outage_fails(self):
        engine, pipeline, verifier = MagicMock(), MagicMock(), MagicMock()
        result = engine.connect.return_value.__enter__.return_value.execute.return_value
        result.scalar.return_value = 0
        result.fetchone.return_value = [None]
        result.fetchall.return_value = []
        scope = load_functions(
            Path(__file__).resolve().parents[1] / "main.py",
            {"get_metrics"},
            app=FastAPI(),
            JSONResponse=JSONResponse,
            logger=MagicMock(),
            get_all_approvals=lambda: {},
            metrics_snapshot=lambda: {},
        )
        analytics = load_functions(
            Path(__file__).resolve().parents[1] / "services/observability_service.py",
            {"ObservabilityService"},
            Dict=dict,
            Any=object,
            List=list,
            HTTPException=HTTPException,
        )
        pipeline.EventPipeline.return_value.delivery_metrics.return_value = {"checkpoints": []}
        verifier.verify_audit_chain.return_value = {"valid": False, "records_checked": 1}
        with patch.dict(
            sys.modules,
            {
                "database": MagicMock(engine=engine),
                "services.event_pipeline": pipeline,
                "verify_audit": verifier,
                "services.observability_service": MagicMock(**analytics),
            },
        ):
            for latency in (None, 0):
                engine.connect.return_value.__enter__.return_value.execute.side_effect = (
                    lambda sql: (
                        MagicMock(scalar=lambda: latency) if "AVG(latency)" in str(sql) else result
                    )
                )
                payload = scope["get_metrics"]()
                self.assertEqual(payload["avg_latency"], latency)
                self.assertEqual(payload["status"], "degraded")
                self.assertIs(payload["audit_chain_status"]["valid"], False)
                self.assertIsNone(payload["queue_lag_seconds"])
            verifier.verify_audit_chain.side_effect = RuntimeError("audit unavailable")
            self.assertEqual(scope["get_metrics"]().status_code, 503)

    def test_database_outage_does_not_invent_metrics(self):
        engine = MagicMock()
        engine.connect.side_effect = RuntimeError("synthetic outage: secret must not leak")
        scope = load_functions(
            Path(__file__).resolve().parents[1] / "main.py",
            {"get_metrics"},
            app=FastAPI(),
            JSONResponse=JSONResponse,
            logger=MagicMock(),
            get_all_approvals=lambda: {},
            metrics_snapshot=lambda: {},
        )
        with patch.dict(sys.modules, {"database": MagicMock(engine=engine)}):
            response = scope["get_metrics"]()
        self.assertEqual(response.status_code, 503)
        payload = json.loads(response.body)
        self.assertEqual(payload["status"], "unavailable")
        self.assertIsNone(payload["avg_latency"])
        self.assertIsNone(payload["compliance_score"])
        self.assertIsNone(payload["audit_chain_status"]["valid"])
        self.assertNotIn("secret", response.body.decode())
        if os.getenv("ENT019_TELEMETRY_EXPORT"):
            Path(os.environ["ENT019_TELEMETRY_EXPORT"]).write_text(
                json.dumps(payload, indent=2) + "\n"
            )

    def test_analytics_query_failure_does_not_return_empty_success(self):
        engine = MagicMock()
        scope = load_functions(
            Path(__file__).resolve().parents[1] / "services/observability_service.py",
            {"ObservabilityService"},
            Dict=dict,
            Any=object,
            List=list,
            engine=engine,
            HTTPException=HTTPException,
            text=lambda sql: sql,
            clickhouse_pipeline_enabled=lambda: False,
        )
        for target in (engine.connect, engine.connect.return_value.__enter__.return_value.execute):
            with patch.object(target, "side_effect", RuntimeError("synthetic database outage")):
                with self.assertRaises(HTTPException) as caught:
                    scope["ObservabilityService"]().governance_analytics(7)
                self.assertEqual(caught.exception.status_code, 503)

    def test_clickhouse_empty_partial_and_failed_responses_are_not_success(self):
        scope = load_functions(
            Path(__file__).resolve().parents[1] / "services/observability_service.py",
            {"ObservabilityService", "_int", "_float"},
            Dict=dict,
            Any=object,
            List=list,
            os=os,
            HTTPException=HTTPException,
            clickhouse_pipeline_enabled=lambda: True,
        )
        service = scope["ObservabilityService"]()
        service._clickhouse_query_json = MagicMock()
        for rows in ([], [{}], [{"total_requests": 0}], [{"ok": 1}]):
            service._clickhouse_query_json.return_value = rows
            with self.assertRaises(HTTPException) as caught:
                service._clickhouse_gateway_summary("7")
            self.assertEqual(caught.exception.status_code, 503)
        row = dict.fromkeys(
            (
                "total_requests",
                "allowed_requests",
                "blocked_requests",
                "pending_requests",
                "tokens_in",
                "tokens_out",
            ),
            0,
        )
        row["avg_duration_ms"] = None
        service._clickhouse_query_json.return_value = [row]
        self.assertIsNone(service._clickhouse_gateway_summary("7")["avg_duration_ms"])
        self.assertEqual(service._clickhouse_gateway_summary("7")["total_requests"], 0)
        service._clickhouse_query_json.side_effect = RuntimeError("source outage")
        with self.assertRaises(HTTPException):
            service._clickhouse_gateway_summary("7")
        self.assertEqual(service._clickhouse_status()["status"], "unavailable")

    def test_legacy_compliance_without_evidence_has_no_score(self):
        engine = MagicMock()
        engine.connect.return_value.__enter__.return_value.execute.return_value.fetchall.return_value = (
            []
        )
        scope = load_functions(
            Path(__file__).resolve().parents[1] / "services/compliance_evidence_engine.py",
            {"ComplianceEvidenceEngine"},
            Dict=dict,
            Any=object,
            List=list,
            Optional=Optional,
            engine=engine,
            text=lambda sql: sql,
            datetime=datetime,
            timezone=timezone,
        )
        service = scope["ComplianceEvidenceEngine"]()
        service.map_evidence = MagicMock()
        service.catalog = lambda: [
            {"control_id": "one", "framework": "SOC2", "title": "Synthetic control"}
        ]
        service._control_weight = lambda _: 1
        service._persist_control_score = MagicMock()
        payload = service.calculate_scores(7)
        self.assertIsNone(payload["soc2"])
        self.assertEqual(payload["soc2_controls"]["unknown"], 1)
        self.assertEqual(payload["soc2_controls"]["passed"], 0)
        self.assertIsNone(payload["evidence_timestamp"])
        self.assertEqual(payload["calculation_version"], "evidence-impact-v2")
        engine.connect.side_effect = RuntimeError("source outage")
        with self.assertRaises(RuntimeError):
            service.calculate_scores(7)

    def test_absent_queue_checkpoints_are_unknown_and_alertable(self):
        scope = load_functions(
            Path(__file__).resolve().parents[1] / "services/observability_service.py",
            {"ObservabilityService", "_int"},
            Dict=dict,
            Any=object,
            List=list,
            HTTPException=HTTPException,
            os=os,
        )
        service = scope["ObservabilityService"]()
        unknown = service._queue_lag({"checkpoints": []})
        self.assertEqual(unknown["status"], "unknown")
        self.assertTrue(unknown["alertable"])
        self.assertIsNone(unknown["max_lag_seconds"])
        observed = service._queue_lag(
            {"checkpoints": [{"lag_seconds": 0, "dead_letter_count": 0, "pending_events": 0}]}
        )
        self.assertEqual(observed["status"], "healthy")
        self.assertFalse(observed["alertable"])

    def test_legacy_report_and_drift_consumers_do_not_invent_scores(self):
        engine = MagicMock()
        conn = engine.connect.return_value.__enter__.return_value
        conn.execute.return_value.fetchall.return_value = [(7,)]
        scores = {
            "soc2": None,
            "gdpr": None,
            "hipaa": None,
            "calculation_version": "evidence-impact-v2",
            "evidence_timestamp": None,
            "missing_control_treatment": "Missing controls remain unknown",
        }
        calculator = MagicMock()
        calculator.ComplianceEvidenceEngine.return_value.calculate_scores.return_value = scores
        scope = load_functions(
            Path(__file__).resolve().parents[1] / "document_processing/drift.py",
            {"get_current_framework_scores", "record_compliance_snapshot"},
            engine=engine,
            text=lambda sql: sql,
            HTTPException=HTTPException,
            datetime=datetime,
            timezone=timezone,
            json=json,
            logger=MagicMock(),
        )
        report = load_functions(
            Path(__file__).resolve().parents[1] / "document_processing/reports.py",
            {"get_live_stats", "generate_executive_summary_report"},
            engine=engine,
            text=lambda sql: sql,
            HTTPException=HTTPException,
            datetime=datetime,
            timezone=timezone,
            json=json,
            csv=csv,
            io=io,
            colors=colors,
            letter=letter,
            getSampleStyleSheet=getSampleStyleSheet,
            ParagraphStyle=ParagraphStyle,
            SimpleDocTemplate=SimpleDocTemplate,
            Paragraph=Paragraph,
            Spacer=Spacer,
            Table=Table,
            TableStyle=TableStyle,
        )
        with patch.dict(
            sys.modules,
            {
                "services.compliance_evidence_engine": calculator,
                "document_processing.drift": MagicMock(**scope),
            },
        ):
            scope["record_compliance_snapshot"]()
            self.assertFalse(any("INSERT" in str(call) for call in conn.execute.call_args_list))
            with self.assertRaises(HTTPException):
                report["get_live_stats"]()
            scores.update(soc2=0, gdpr=60, hipaa=90)
            conn.execute.return_value.scalar.return_value = 0
            payload = json.loads(report["generate_executive_summary_report"]("json"))
            self.assertEqual(payload["compliance_score"], 50)
            self.assertEqual(payload["calculation_version"], "evidence-impact-v2")
            self.assertTrue(report["generate_executive_summary_report"]("pdf").startswith(b"%PDF"))
            self.assertIn(b"evidence-impact-v2", report["generate_executive_summary_report"]("csv"))
            conn.execute.return_value.fetchone.return_value = (None,)
            scope["record_compliance_snapshot"]()
            self.assertTrue(conn.commit.called)
            conn.execute.return_value.fetchall.return_value = []
            with self.assertRaises(HTTPException):
                scope["get_current_framework_scores"]()
            engine.connect.side_effect = RuntimeError("secret database outage")
            for loader in (scope["get_current_framework_scores"], report["get_live_stats"]):
                with self.assertRaises(HTTPException) as caught:
                    loader()
                self.assertEqual(caught.exception.status_code, 503)
                self.assertNotIn("secret", caught.exception.detail)

    def test_audit_summary_and_report_preserve_unknown(self):
        verifier, engine = MagicMock(), MagicMock()
        verifier.verify_audit_chain.return_value = {"valid": None, "records_checked": 0}
        engine.connect.return_value.__enter__.return_value.execute.return_value.fetchall.return_value = (
            []
        )
        summary = load_functions(
            Path(__file__).resolve().parents[1] / "main.py",
            {"verify_audit_summary"},
            app=FastAPI(),
            Optional=Optional,
            Header=Header,
            resolve_tenant_from_authorization=lambda _: 7,
        )
        report = load_functions(
            Path(__file__).resolve().parents[1] / "document_processing/reports.py",
            {"generate_auditor_evidence_report", "generate_technical_findings_report"},
            engine=engine,
            text=lambda sql: sql,
            HTTPException=HTTPException,
            json=json,
            datetime=datetime,
            timezone=timezone,
            io=io,
            colors=colors,
            letter=letter,
            getSampleStyleSheet=getSampleStyleSheet,
            ParagraphStyle=ParagraphStyle,
            SimpleDocTemplate=SimpleDocTemplate,
            Paragraph=Paragraph,
            Spacer=Spacer,
            Table=Table,
            TableStyle=TableStyle,
        )
        with patch.dict(sys.modules, {"verify_audit": verifier}):
            self.assertIsNone(summary["verify_audit_summary"]()["valid"])
            self.assertEqual(summary["verify_audit_summary"]()["status"], "unknown")
            self.assertTrue(report["generate_auditor_evidence_report"]("pdf").startswith(b"%PDF"))
            for valid, expected in ((None, "UNKNOWN"), (False, "CORRUPTED"), (True, "VALID")):
                verifier.verify_audit_chain.return_value["valid"] = valid
                self.assertEqual(
                    json.loads(report["generate_auditor_evidence_report"]("json"))[
                        "chain_verification"
                    ],
                    expected,
                )
            verifier.verify_audit_chain.side_effect = RuntimeError("outage")
            with self.assertRaises(HTTPException):
                report["generate_auditor_evidence_report"]("json")
            engine.connect.side_effect = RuntimeError("source outage")
            with self.assertRaises(HTTPException) as caught:
                report["generate_technical_findings_report"]("json")
            self.assertEqual(caught.exception.status_code, 503)

    def test_signed_trust_package_is_not_proof_of_runtime_health(self):
        builder = MagicMock()
        scope = load_functions(
            Path(__file__).resolve().parents[1] / "services/trust_center_runtime.py",
            {"trust_runtime_health"},
            Dict=dict,
            Any=object,
            build_public_trust_state=builder,
        )
        for valid, expected in ((False, "degraded"), (None, "unknown"), (True, "unknown")):
            builder.return_value = {
                "verification": {"valid": True},
                "payload": {"runtime": {"audit_status": {"valid": valid}}},
            }
            self.assertEqual(scope["trust_runtime_health"]()["status"], expected)
        builder.side_effect = RuntimeError("secret database details")
        payload = scope["trust_runtime_health"]()
        self.assertEqual(payload["status"], "unavailable")
        self.assertNotIn("secret", json.dumps(payload))
        endpoint = load_functions(
            Path(__file__).resolve().parents[1] / "main.py",
            {"get_public_trust_health"},
            app=FastAPI(),
            JSONResponse=JSONResponse,
            jsonable_encoder=lambda value: value,
        )
        with patch.dict(sys.modules, {"services.trust_center_runtime": MagicMock(**scope)}):
            self.assertEqual(endpoint["get_public_trust_health"]().status_code, 503)

    def test_framework_explorer_preserves_unknown_and_zero_and_fails_on_outage(self):
        calculator = MagicMock()
        service = calculator.ComplianceEvidenceEngine.return_value
        service.catalog.return_value = [{"control_id": "one"}]
        service.evidence_export_rows.return_value = []
        service.score_changes.return_value = []
        scope = load_functions(
            Path(__file__).resolve().parents[1] / "main.py",
            {"get_compliance_framework_explorer", "_compact_framework_scores"},
            app=FastAPI(),
            Optional=Optional,
            Header=Header,
            HTTPException=HTTPException,
            resolve_tenant=lambda *_: 7,
            datetime=datetime,
            timezone=timezone,
            Dict=dict,
            List=list,
            Any=object,
        )
        with patch.dict(sys.modules, {"services.compliance_evidence_engine": calculator}):
            for score, risk in ((None, "UNKNOWN"), (0, "MEDIUM"), (90, "LOW")):
                service.calculate_scores.return_value = {
                    "soc2_controls": {
                        "unknown": int(score is None),
                        "items": [{"control_id": "one", "score": score}],
                    }
                }
                payload = scope["get_compliance_framework_explorer"]()
                self.assertEqual(payload["controls"][0]["risk"], risk)
                self.assertEqual(
                    payload["framework_scores"]["soc2_controls"]["unknown"], int(score is None)
                )
            for loader in (
                service.catalog,
                service.calculate_scores,
                service.evidence_export_rows,
                service.score_changes,
            ):
                with patch.object(loader, "side_effect", RuntimeError("outage")):
                    with self.assertRaises(HTTPException) as caught:
                        scope["get_compliance_framework_explorer"]()
                    self.assertEqual(caught.exception.status_code, 503)

    def test_no_audit_chain_is_unknown_not_valid(self):
        engine = MagicMock()
        scope = load_functions(
            Path(__file__).resolve().parents[1] / "verify_audit.py",
            {"verify_audit_chain"},
            engine=engine,
            text=lambda sql: sql,
        )
        for rows in ([], [(None,) * 9]):
            engine.connect.return_value.__enter__.return_value.execute.return_value.fetchall.return_value = (
                rows
            )
            result = scope["verify_audit_chain"](tenant_id=7)
            self.assertIsNone(result["valid"])
            self.assertEqual(result["status"], "unknown")

    def test_health_distinguishes_unavailable_degraded_and_unknown(self):
        engine = MagicMock()
        scope = load_functions(
            Path(__file__).resolve().parents[1] / "main.py",
            {"get_health_details", "get_readiness"},
            app=FastAPI(),
            JSONResponse=JSONResponse,
            os=os,
            check_available=lambda: None,
            validate_database_security=lambda: None,
            _rbac_enforcement_enabled=lambda: True,
        )
        with patch.dict(
            sys.modules, {"database": MagicMock(engine=engine), "providers": MagicMock()}
        ), patch.dict(os.environ, {"AUTHCLAW_ENV": "development"}):
            payload = json.loads(scope["get_health_details"]().body)
            self.assertEqual(payload["status"], "degraded")
            self.assertEqual(payload["provider_status"], "unknown")
            self.assertIsNone(payload["audit_chain_active"])
            if os.getenv("ENT019_TELEMETRY_EXPORT"):
                Path(os.environ["ENT019_TELEMETRY_EXPORT"]).with_name(
                    "ENT-019-degraded-health.json"
                ).write_text(json.dumps(payload, indent=2) + "\n")
            ready = json.loads(scope["get_readiness"]().body)
            self.assertEqual(ready["health_status"], "healthy")
            self.assertEqual(ready["checks"]["production_validation"], "not_applicable")
            engine.connect.side_effect = RuntimeError("outage")
            response = scope["get_health_details"]()
            self.assertEqual(response.status_code, 503)
            self.assertEqual(json.loads(response.body)["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()

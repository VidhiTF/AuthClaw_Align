"""Execute actual telemetry functions without starting the agent or a live database."""

import ast
import csv
import io
import json
import os
import re
import smtplib
import socketserver
import threading
from contextlib import contextmanager, nullcontext
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional
import sys
import unittest
from unittest.mock import MagicMock, patch
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email import message_from_bytes
from email.message import EmailMessage
from types import SimpleNamespace

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.tenant_context import tenant_context, validate_tenant_id


def load_functions(path, names, **namespace):
    namespace.setdefault("validate_tenant_id", validate_tenant_id)
    namespace.setdefault("contextmanager", contextmanager)
    namespace.setdefault("nullcontext", nullcontext)
    tree = ast.parse(path.read_text(encoding="utf-8"))
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
    def setUp(self):
        self.enterContext(tenant_context(7, request_id="telemetry-test", required=True))

    def test_audit_verification_events_are_tristate(self):
        verifier, audit = MagicMock(), MagicMock()
        scope = load_functions(Path(__file__).resolve().parents[1] / "main.py", {"verify_audit"},
            app=FastAPI(), Optional=Optional, Header=Header, uuid=MagicMock(),
            resolve_tenant_from_authorization=lambda _: 7)
        with patch.dict(sys.modules, {"verify_audit": verifier, "startup.audit": audit}):
            for valid, suffix in ((True, "passed"), (False, "failed"), (None, "unknown")):
                verifier.verify_audit_chain.return_value = {"valid": valid, "records_checked": 0}
                self.assertIs(scope["verify_audit"]()["valid"], valid)
                self.assertEqual(audit.log_audit_event.call_args.kwargs["event"], "audit_verification_" + suffix)

    def test_health_precedence_preserves_all_five_states(self):
        aggregate = load_functions(
            Path(__file__).resolve().parents[1] / "services/observability_service.py", {"aggregate_health"}
        )["aggregate_health"]
        cases = (((), "unknown"), (("not_applicable",), "not_applicable"),
                 (("healthy", "not_applicable"), "healthy"), (("unknown", "healthy"), "unknown"),
                 (("degraded", "unknown"), "degraded"), (("unavailable", "degraded"), "unavailable"),
                 ((None, "healthy"), "unknown"), (("unexpected",), "unknown"))
        for states, expected in cases:
            with self.subTest(states=states):
                self.assertEqual(aggregate(*states), expected)
                self.assertEqual(aggregate(*reversed(states)), expected)

    def test_alert_transport_does_not_swallow_delivery_failures(self):
        smtp, database = MagicMock(), MagicMock()
        database.connect.return_value.__enter__.return_value.execute.return_value.scalars.return_value.all.return_value = ["admin@tenant.test"]
        smtp.SMTP.return_value.__enter__.return_value.send_message.return_value = {}
        scope = load_functions(
            Path(__file__).resolve().parents[1] / "document_processing/alerts.py",
            {"trigger_security_alert"}, os=os, engine=database, text=text,
            smtplib=smtp, EmailMessage=EmailMessage,
        )
        event = {"tenant_id": 7, "document_id": 1}
        with patch.dict(os.environ, {"SMTP_HOST": "smtp.test.invalid", "SKIP_EMAIL_DELIVERY_FOR_TESTING": "false"}):
            smtp.SMTP.side_effect = OSError("SMTP unavailable")
            with self.assertRaises(OSError):
                scope["trigger_security_alert"](event)
            smtp.SMTP.side_effect = None
            scope["trigger_security_alert"](event)
            smtp.SMTP.return_value.__enter__.return_value.send_message.assert_called_once()
            with patch.dict(os.environ, {"SMTP_HOST": ""}):
                with self.assertRaises(RuntimeError):
                    scope["trigger_security_alert"](event)
            with patch.dict(os.environ, {"SKIP_EMAIL_DELIVERY_FOR_TESTING": "true"}):
                with self.assertRaises(RuntimeError):
                    scope["trigger_security_alert"](event)
            with self.assertRaises(HTTPException):
                scope["trigger_security_alert"]({"tenant_id": 8, "document_id": 1})
            smtp.SMTP.return_value.__enter__.return_value.send_message.return_value = {"admin@tenant.test": (550, "refused")}
            with self.assertRaises(RuntimeError):
                scope["trigger_security_alert"](event)

    def test_alert_reaches_local_smtp_receiver(self):
        messages = []

        class Receiver(socketserver.StreamRequestHandler):
            def handle(self):
                self.connection.settimeout(3)
                self.wfile.write(b"220 localhost\r\n")
                while line := self.rfile.readline():
                    if line.upper().startswith(b"DATA"):
                        self.wfile.write(b"354 Send message\r\n")
                        chunks = []
                        while (chunk := self.rfile.readline()) not in (b".\r\n", b""):
                            chunks.append(chunk)
                        messages.append(b"".join(chunks))
                    elif line.upper().startswith(b"QUIT"):
                        self.wfile.write(b"221 Bye\r\n")
                        break
                    self.wfile.write(b"250 OK\r\n")

        database = MagicMock()
        database.connect.return_value.__enter__.return_value.execute.return_value.scalars.return_value.all.return_value = ["admin@tenant.test"]
        scope = load_functions(
            Path(__file__).resolve().parents[1] / "document_processing/alerts.py",
            {"trigger_security_alert"}, os=os, engine=database, text=text,
            smtplib=smtplib, EmailMessage=EmailMessage,
        )
        with socketserver.TCPServer(("127.0.0.1", 0), Receiver) as server:
            worker = threading.Thread(target=server.handle_request, daemon=True)
            worker.start()
            try:
                with patch.dict(os.environ, {"SMTP_HOST": "127.0.0.1", "SMTP_PORT": str(server.server_address[1]), "SMTP_USE_TLS": "false", "SMTP_USERNAME": "", "SMTP_PASSWORD": "", "SKIP_EMAIL_DELIVERY_FOR_TESTING": "false"}):
                    scope["trigger_security_alert"]({"tenant_id": 7, "document_id": 1, "matched_text": "never-email-this-secret"})
            finally:
                worker.join(timeout=4)
        self.assertEqual(len(messages), 1)
        message = message_from_bytes(messages[0])
        self.assertNotIn("Leak", str(message["Subject"]))
        self.assertEqual(message["To"], "admin@tenant.test")
        self.assertNotIn(b"never-email-this-secret", messages[0])

    def test_compliance_timestamp_is_source_time_not_remapping_time(self):
        engine = MagicMock()
        scope = load_functions(
            Path(__file__).resolve().parents[1] / "services/compliance_evidence_engine.py",
            {"ComplianceEvidenceEngine"}, Dict=dict, Any=object, List=list, Optional=Optional,
            engine=engine, text=text, datetime=datetime, timezone=timezone, json=json,
        )
        service = scope["ComplianceEvidenceEngine"]()
        service.map_evidence = MagicMock()
        service.catalog = lambda: [{"control_id": "one", "framework": "SOC2", "title": "Control"}]
        scope["CONTROL_CATALOG"] = service.catalog()
        engine.begin = engine.connect
        service._control_weight = lambda _: 1
        service._persist_control_score = MagicMock()
        execute = engine.connect.return_value.__enter__.return_value.execute
        for metadata, expected in (({}, None), ({"evidence_timestamp": "2020-01-02"}, "2020-01-02T00:00:00+00:00"), ({"evidence_timestamp": "2020-01-02T05:30:00+05:30"}, "2020-01-02T00:00:00+00:00"), ({"evidence_timestamp": "invalid"}, None)):
            mapping = {"framework": "SOC2", "control_id": "one", "impact": 8, "source_type": "evidence", "created_at": datetime.now(timezone.utc), "metadata": json.dumps(metadata)}
            row = SimpleNamespace(control_id="one", _mapping=mapping)
            execute.return_value.fetchall.side_effect = [[row], []]
            payload = service.calculate_scores(7)
            self.assertEqual(payload["evidence_timestamp"], expected)
            self.assertEqual(payload["soc2"], 84)
            self.assertFalse(payload["authoritative"])

        row = SimpleNamespace(id=1, name="Evidence", category="SOC2", file_path="evidence.pdf", framework="SOC2", control_id="one", evidence_timestamp="2020-01-02", risk_level="HIGH", finding_type="PII", matched_pattern="PII", recommendation="redact", impact="policy", location_evidence="page 1", approval_id="approval", status="approved", metadata="{}", mfa_verified=True, approval_status="approved", policy_name="policy", policy_type="PII", provider="test", severity="HIGH", evidence="{}")
        scope["SEVERITY_PENALTY"] = {"HIGH": 10}
        row.reason = "Approval reason"
        execute.return_value.fetchall.side_effect = [[row]] * 5
        events = service._collect_source_events(7)
        self.assertEqual([event["evidence_timestamp"] for event in events], ["2020-01-02", None, "2020-01-02", "2020-01-02", "2020-01-02"])

    def test_control_change_history_preserves_unknown_and_recovery_to_zero(self):
        engine = MagicMock()
        engine.begin = engine.connect
        scope = load_functions(
            Path(__file__).resolve().parents[1] / "services/compliance_evidence_engine.py",
            {"ComplianceEvidenceEngine"}, Dict=dict, Any=object, List=list, Optional=Optional,
            engine=engine, text=text, datetime=datetime, timezone=timezone, json=json,
        )
        service = scope["ComplianceEvidenceEngine"]()
        execute = engine.connect.return_value.__enter__.return_value.execute
        control = {"framework": "SOC2", "control_id": "one", "title": "Control"}
        for previous, status, count, expected in ((100, "unknown", 0, None), (None, "failing", 1, 0)):
            execute.reset_mock()
            service._persist_control_score(7, control, expected, status, count, 0, "Reason", "catalog_baseline" if not count else "evidence", {("SOC2", "one"): previous})
            change = execute.call_args.args[1]
            self.assertEqual(change["current_score"], expected)
            self.assertEqual(json.loads(change["metadata"])["status"], status)
        execute.return_value.fetchall.return_value = [SimpleNamespace(_mapping={"current_score": 100, "source_event": "catalog_baseline"})]
        self.assertIsNone(service.score_changes(7)[0]["current_score"])

    def test_nullable_control_persistence_and_recovery_to_measured_zero(self):
        # Real SQL and transactions. Optional PostgreSQL rehearsal uses only TEMP tables.
        engine = create_engine(os.getenv("ENT019_TEST_DATABASE_URL", "sqlite://"))
        self.addCleanup(engine.dispose)
        migration = (Path(__file__).resolve().parents[1] / "database/migrations.py").read_text()
        with engine.begin() as conn:
            if engine.dialect.name == "sqlite":
                conn.connection.driver_connection.create_function("NOW", 0, lambda: datetime.now(timezone.utc).isoformat())
            for table, alteration_count in (("compliance_score_history", 1), ("compliance_drift_alerts", 3), ("compliance_control_scores", 1), ("compliance_score_changes", 1)):
                ddl = re.search(rf"CREATE TABLE IF NOT EXISTS {table} \(.*?\);", migration, re.S).group()
                ddl = ddl.replace("CREATE TABLE IF NOT EXISTS", "CREATE TEMP TABLE")
                ddl = ddl.replace("REFERENCES tenants(id) ON DELETE CASCADE", "")
                alterations = re.findall(rf"ALTER TABLE {table} ALTER COLUMN \w+ DROP NOT NULL;", migration)
                self.assertEqual(len(alterations), alteration_count)
                if engine.dialect.name == "sqlite":
                    ddl = ddl.replace("SERIAL", "INTEGER")
                    for alter in alterations:
                        ddl = ddl.replace(f"{alter.split()[5]} INTEGER NOT NULL", f"{alter.split()[5]} INTEGER")
                conn.execute(text(ddl))
                if engine.dialect.name == "postgresql":
                    for _ in range(2):  # Existing installations and idempotent restart.
                        for alter in alterations:
                            conn.execute(text(alter))
        scoring = load_functions(
            Path(__file__).resolve().parents[1] / "services/compliance_evidence_engine.py",
            {"ComplianceEvidenceEngine"}, Dict=dict, Any=object, List=list, Optional=Optional,
            engine=engine, text=text, datetime=datetime, timezone=timezone, json=json,
        )["ComplianceEvidenceEngine"]()
        control = {"framework": "SOC2", "control_id": "one", "title": "Control"}
        previous = {}
        for score, status, count in ((80, "watch", 1), (None, "unknown", 0), (None, "unknown", 0), (0, "failing", 1)):
            scoring._persist_control_score(7, control, score, status, count, 0, "Reason", "evidence" if count else "catalog_baseline", previous)
            previous = {("SOC2", "one"): score if count else None}
        with engine.connect() as conn:
            self.assertEqual(conn.execute(text("SELECT score FROM compliance_control_scores")).scalar(), 0)
        changes = scoring.score_changes(7)
        self.assertEqual([row["current_score"] for row in changes], [0, None, 80])
        self.assertEqual([row["previous_score"] for row in changes], [None, 80, None])

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
            get_current_tenant_id=lambda: "7",
        )
        analytics = load_functions(
            Path(__file__).resolve().parents[1] / "services/observability_service.py",
            {"ObservabilityService", "aggregate_health"},
            Dict=dict,
            Any=object,
            List=list,
            HTTPException=HTTPException,
            os=os,
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
                    lambda sql, *params: (
                        MagicMock(scalar=lambda: latency) if "AVG(latency)" in str(sql) else result
                    )
                )
                payload = scope["get_metrics"]()
                self.assertEqual(payload["avg_latency"], latency)
                self.assertEqual(payload["status"], "degraded")
                self.assertEqual(payload["compliance_status"], "unknown")
                self.assertIs(payload["audit_chain_status"]["valid"], False)
                self.assertIsNone(payload["queue_lag_seconds"])
            verifier.verify_audit_chain.return_value = {"valid": None, "status": "unknown", "records_checked": 0}
            client = TestClient(scope["app"])
            self.assertEqual(client.get("/metrics").json()["status"], "unknown")
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
        service._clickhouse_query_json.return_value = [{"ok": 1}]
        self.assertEqual(service._clickhouse_status()["status"], "unknown")
        self.assertTrue(service._clickhouse_status()["alertable"])
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
        scope["CONTROL_CATALOG"] = service.catalog()
        engine.begin = engine.connect
        service._control_weight = lambda _: 1
        service._persist_control_score = MagicMock()
        payload = service.calculate_scores(7)
        self.assertIsNone(payload["soc2"])
        self.assertEqual(payload["soc2_controls"]["unknown"], 1)
        self.assertEqual(payload["soc2_controls"]["passed"], 0)
        self.assertIsNone(payload["evidence_timestamp"])
        self.assertEqual(payload["calculation_version"], "agent-diagnostic-v2")
        self.assertIsNone(service._persist_control_score.call_args.args[2])
        self.assertIn("unknown", service._persist_control_score.call_args.args[6])
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
            datetime=datetime,
            timezone=timezone,
        )
        service = scope["ObservabilityService"]()
        unknown = service._queue_lag({"checkpoints": []})
        self.assertEqual(unknown["status"], "unknown")
        self.assertTrue(unknown["alertable"])
        self.assertIsNone(unknown["max_lag_seconds"])
        checkpoint = {"stream": "audit", "lag_seconds": 0, "dead_letter_count": 0, "pending_events": 0, "updated_at": datetime.now(timezone.utc)}
        observed = service._queue_lag({"streams": {}, "checkpoints": [checkpoint]})
        self.assertEqual(observed["status"], "healthy")
        self.assertFalse(observed["alertable"])
        for updated_at in (None, "invalid", datetime.now(timezone.utc) - timedelta(days=1), datetime.now(timezone.utc) + timedelta(days=1)):
            result = service._queue_lag({"streams": {}, "checkpoints": [{**checkpoint, "updated_at": updated_at}]})
            self.assertEqual(result["status"], "unknown")
            self.assertTrue(result["alertable"])
            self.assertIsNone(result["max_lag_seconds"])
        for field in ("lag_seconds", "dead_letter_count", "pending_events"):
            for invalid in (None, -1, "broken", float("nan"), 0.5, False):
                self.assertEqual(service._queue_lag({"streams": {}, "checkpoints": [{**checkpoint, field: invalid}]})["status"], "unknown")
        self.assertEqual(service._queue_lag({"streams": {"audit": {"dead_letter": 1}}, "checkpoints": [{**checkpoint, "dead_letter_count": 1, "pending_events": 1}]})["status"], "degraded")
        self.assertEqual(service._queue_lag({"checkpoints": [checkpoint]})["status"], "unknown")
        for streams, status in (({"analytics": {"queued": 1}}, "unknown"), ({"audit": {"dead_letter": 1}}, "degraded")):
            result = service._queue_lag({"streams": streams, "checkpoints": [checkpoint]})
            self.assertEqual(result["status"], status)
            self.assertTrue(result["alertable"])

    def test_legacy_reports_are_unassessed_and_retired_drift_cannot_write(self):
        engine = MagicMock()
        scope = load_functions(
            Path(__file__).resolve().parents[1] / "document_processing/drift.py",
            {"get_current_framework_scores", "record_compliance_snapshot"}, engine=engine,
        )
        self.assertEqual(scope["get_current_framework_scores"](7), {})
        self.assertIsNone(scope["record_compliance_snapshot"](7))
        engine.connect.assert_not_called()
        report = load_functions(
            Path(__file__).resolve().parents[1] / "document_processing/reports.py",
            {"get_live_stats", "generate_executive_summary_report"},
            engine=engine,
            text=lambda sql: sql,
            HTTPException=HTTPException,
            os=os,
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
        conn = engine.connect.return_value.__enter__.return_value
        conn.execute.return_value.scalar.return_value = 0
        payload = json.loads(report["generate_executive_summary_report"]("json", 7))
        self.assertIsNone(payload["compliance_score"])
        self.assertFalse(payload["compliance_authoritative"])
        self.assertEqual(payload["compliance_status"], "unassessed")
        self.assertEqual(payload["calculation_version"], "agent-diagnostic-v2")
        self.assertTrue(report["generate_executive_summary_report"]("pdf", 7).startswith(b"%PDF"))
        self.assertIn(b"Unassessed", report["generate_executive_summary_report"]("csv", 7))
        self.assertTrue(all(call.args[1] == {"tenant_id": 7} for call in conn.execute.call_args_list))
        with self.assertRaises(HTTPException):
            report["get_live_stats"](8)
        engine.connect.side_effect = RuntimeError("secret database outage")
        with self.assertRaises(HTTPException) as caught:
            report["get_live_stats"](7)
        self.assertEqual(caught.exception.status_code, 503)
        self.assertNotIn("secret", caught.exception.detail)

    def test_audit_summary_and_report_preserve_unknown(self):
        verifier, engine = MagicMock(), MagicMock()
        verifier.verify_audit_chain.return_value = {"valid": None, "records_checked": 0}
        engine.connect.return_value.__enter__.return_value.execute.return_value.fetchall.return_value = (
            [(1, datetime.now(timezone.utc), "Request", None, None, "hash", None)]
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
            csv=csv,
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
            self.assertTrue(report["generate_auditor_evidence_report"]("pdf", 7).startswith(b"%PDF"))
            audit = json.loads(report["generate_auditor_evidence_report"]("json", 7))["audit_logs"][0]
            self.assertEqual((audit["risk"], audit["status"]), ("UNKNOWN", "UNKNOWN"))
            self.assertIn(b"UNKNOWN,UNKNOWN", report["generate_auditor_evidence_report"]("csv", 7))
            for valid, expected in ((None, "UNKNOWN"), (False, "CORRUPTED"), (True, "VALID")):
                verifier.verify_audit_chain.return_value["valid"] = valid
                self.assertEqual(
                    json.loads(report["generate_auditor_evidence_report"]("json", 7))[
                        "chain_verification"
                    ],
                    expected,
                )
            verifier.verify_audit_chain.side_effect = RuntimeError("outage")
            with self.assertRaises(HTTPException):
                report["generate_auditor_evidence_report"]("json", 7)
            engine.connect.side_effect = RuntimeError("source outage")
            with self.assertRaises(HTTPException) as caught:
                report["generate_technical_findings_report"]("json", 7)
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
        observability = MagicMock()
        observability.aggregate_health = load_functions(
            Path(__file__).resolve().parents[1] / "services/observability_service.py", {"aggregate_health"}
        )["aggregate_health"]
        observability.ObservabilityService.return_value._queue_lag.return_value = {"status": "healthy"}
        for valid, expected in ((False, "degraded"), (None, "unknown"), (True, "healthy")):
            builder.return_value = {
                "status": "published",
                "verification": {"valid": True},
                "payload": {"framework_scores": {"soc2": 90, "gdpr": 80, "hipaa": 70}, "runtime": {"audit_status": {"valid": valid}}},
            }
            with patch.dict(sys.modules, {"services.observability_service": observability}):
                payload = scope["trust_runtime_health"]()
                self.assertEqual(payload["status"], expected)
                if expected == "degraded" and os.getenv("ENT019_TELEMETRY_EXPORT"):
                    Path(os.environ["ENT019_TELEMETRY_EXPORT"]).with_name(
                        "ENT-019-degraded-health.json"
                    ).write_text(json.dumps(payload, indent=2) + "\n")
                builder.assert_called_with(force_refresh=True)
        with patch.dict(sys.modules, {"services.observability_service": observability}):
            for score, queue, signature, expected in (
                (None, "healthy", True, "unknown"),
                (0, "healthy", True, "healthy"),
                (90, "unknown", True, "unknown"),
                (90, "degraded", True, "degraded"),
                (90, "unavailable", True, "unavailable"),
                (90, "healthy", False, "degraded"),
            ):
                builder.return_value["payload"]["framework_scores"]["soc2"] = score
                builder.return_value["verification"]["valid"] = signature
                observability.ObservabilityService.return_value._queue_lag.return_value = {"status": queue}
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
            for score, risk in ((None, "UNASSESSED"), (0, "UNASSESSED"), (90, "UNASSESSED")):
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

    def test_health_distinguishes_readiness_from_unmeasured_features(self):
        engine = MagicMock()
        scope = load_functions(
            Path(__file__).resolve().parents[1] / "main.py",
            {"get_health", "get_health_details", "get_readiness"},
            app=FastAPI(),
            JSONResponse=JSONResponse,
            os=os,
            json=json,
            check_available=lambda: None,
            validate_database_security=lambda: None,
            _rbac_enforcement_enabled=lambda: True,
        )
        client = TestClient(scope["app"])
        with patch.dict(
            sys.modules, {"database": MagicMock(engine=engine), "providers": MagicMock()}
        ), patch.dict(os.environ, {"AUTHCLAW_ENV": "development"}):
            payload = json.loads(scope["get_health_details"]().body)
            self.assertEqual(payload["status"], "healthy")
            self.assertEqual(payload["scope"], "agent_readiness")
            self.assertEqual(payload["provider_status"], "unknown")
            self.assertIsNone(payload["audit_chain_active"])
            ready = json.loads(scope["get_readiness"]().body)
            self.assertEqual(ready["health_status"], "healthy")
            self.assertEqual(ready["checks"]["production_validation"], "not_applicable")
            for route in ("/health", "/api/v1/agent/health"):
                self.assertEqual(client.get(route).json(), {"status": "alive", "scope": "process_liveness"})
            for route in ("/health/ready", "/api/v1/agent/health/ready", "/health/details"):
                self.assertEqual(client.get(route).status_code, 200)
            scope["validate_database_security"] = MagicMock(side_effect=RuntimeError("outage"))
            response = scope["get_health_details"]()
            self.assertEqual(response.status_code, 503)
            self.assertEqual(json.loads(response.body)["status"], "unavailable")
            for route in ("/health/ready", "/api/v1/agent/health/ready", "/health/details"):
                self.assertEqual(client.get(route).status_code, 503)
            scope["validate_database_security"].side_effect = None
            scope["check_available"] = MagicMock(side_effect=RuntimeError("redis down"))
            self.assertEqual(client.get("/health/details").status_code, 503)
            self.assertEqual(client.get("/health/details").json()["database_status"], "healthy")
            scope["check_available"].side_effect = None
            self.assertEqual(client.get("/health/details").json()["status"], "healthy")
            validation = MagicMock()
            with patch.dict(os.environ, {"AUTHCLAW_ENV": "production"}), patch.dict(sys.modules, {"startup.validation": validation}):
                for errors, expected in (([], "healthy"), (["invalid configuration"], "unavailable")):
                    validation.validate_production_environment.return_value = errors
                    self.assertEqual(client.get("/health/details").json()["status"], expected)
                validation.validate_production_environment.side_effect = RuntimeError("secret validation error")
                response = client.get("/health/details")
                self.assertEqual(response.status_code, 503)
                self.assertNotIn("secret", response.text)


if __name__ == "__main__":
    unittest.main()

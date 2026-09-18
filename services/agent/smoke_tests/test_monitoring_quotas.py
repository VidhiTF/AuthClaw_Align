"""Execute actual monitoring functions with filesystem/database I/O seams."""
import ast
from datetime import datetime, timezone
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import Mock, mock_open, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.quota_service import QuotaExceeded, QuotaUnavailable
from services.tenant_context import get_current_request_id, get_current_tenant_id, tenant_context


class MonitoringQuotaTests(unittest.TestCase):
    def setUp(self):
        source = Path(__file__).resolve().parents[1] / "document_processing/monitoring.py"
        nodes = [node for node in ast.parse(source.read_text()).body
                 if isinstance(node, ast.FunctionDef) and node.name in
                 {"_scan_request_context", "sync_sources", "trigger_manual_sync", "start_background_monitoring", "_monitor_loop"}]
        self.conn = Mock()
        self.conn.execute.return_value.fetchone.return_value = (1, 2, "completed")
        self.conn.execute.return_value.fetchall.return_value = []
        self.engine = Mock()
        self.engine.connect.return_value.__enter__ = Mock(return_value=self.conn)
        self.engine.connect.return_value.__exit__ = Mock(return_value=False)
        self.ns = {"get_current_request_id": get_current_request_id,
                   "get_current_tenant_id": get_current_tenant_id,
                   "QuotaExceeded": QuotaExceeded, "QuotaUnavailable": QuotaUnavailable,
                   "record_unavailable": Mock(), "engine": self.engine, "text": lambda value: value,
                   "get_watched_directory": Mock(), "WATCH_DIR": "fixture",
                   "os": Mock(), "open": mock_open(read_data=b"data"),
                   "run_document_scan_pipeline": Mock(), "logger": Mock(),
                   "is_real_connectors_enabled": lambda: False,
                   "list_cloud_source_files": Mock(return_value=[]),
                   "datetime": datetime, "timezone": timezone, "last_sync_time": "N/A",
                   "tenant_context": tenant_context, "threading": threading,
                   "_monitor_thread": None,
                   "_stop_event": Mock(), "time": Mock(),
                   "MONITOR_REQUESTER_ID": "service:document-monitor"}
        self.monitor_state = {"enabled": False, "status": "disabled",
                              "tenant_configured": False, "failures_total": 0,
                              "last_error_type": None, "last_success_timestamp": None}
        self.ns["monitor_status"] = lambda: dict(self.monitor_state)
        self.ns["update_monitor_status"] = lambda **changes: self.monitor_state.update(changes)
        self.ns["os"].listdir.return_value = ["document.txt"]
        self.ns["os"].path.isfile.return_value = True
        self.ns["os"].path.getsize.return_value = 4
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec"), self.ns)

    def test_background_start_requires_explicit_tenant(self):
        self.ns["os"].getenv.return_value = ""
        with self.assertRaises(ValueError):
            self.ns["start_background_monitoring"]()
        self.ns["get_watched_directory"].assert_not_called()
        self.engine.connect.assert_not_called()
        self.ns["run_document_scan_pipeline"].assert_not_called()

    def test_background_retries_with_explicit_tenant_context_and_status(self):
        observed = []

        def sync():
            observed.append(get_current_tenant_id())
            if len(observed) == 1:
                raise QuotaUnavailable("temporary")

        self.ns["sync_sources"] = sync
        self.ns["_stop_event"].is_set.return_value = False
        self.ns["_stop_event"].wait.side_effect = [False, True]
        self.ns["_monitor_loop"]("7")
        self.assertEqual(observed, ["7", "7"])
        self.assertEqual(self.monitor_state["failures_total"], 1)
        self.assertIsNone(self.monitor_state["last_error_type"])
        self.assertGreater(self.monitor_state["last_success_timestamp"], 0)
        self.assertEqual(self.monitor_state["status"], "stopped")

    def test_manual_quota_failure_is_not_success(self):
        for failure in (QuotaExceeded("expensive_model"), QuotaUnavailable("Redis unavailable")):
            self.ns["run_document_scan_pipeline"].side_effect = failure
            with tenant_context(7), self.assertRaises(type(failure)):
                self.ns["trigger_manual_sync"]("oidc|manual-requester")
            self.assertEqual(self.ns["last_sync_time"], "N/A")
            self.ns["list_cloud_source_files"].assert_not_called()

    def test_manual_passes_verified_tenant_and_scopes_queries(self):
        with tenant_context(7):
            self.assertEqual(self.ns["trigger_manual_sync"]("oidc|manual-requester")["status"], "success")
        self.assertEqual(self.ns["run_document_scan_pipeline"].call_args.kwargs["tenant_id"], "7")
        self.assertEqual(
            self.ns["run_document_scan_pipeline"].call_args.kwargs["requested_by"],
            "oidc|manual-requester",
        )
        self.assertTrue(self.ns["run_document_scan_pipeline"].call_args.kwargs["request_id"])
        for call in self.conn.execute.call_args_list:
            self.assertIn("tenant_id = :tenant_id", call.args[0])
            self.assertEqual(call.args[1]["tenant_id"], "7")

    def test_cloud_quota_failure_propagates(self):
        self.ns["os"].listdir.return_value = []
        self.ns["list_cloud_source_files"].side_effect = QuotaUnavailable("quota unavailable")
        with tenant_context(7), self.assertRaises(QuotaUnavailable):
            self.ns["trigger_manual_sync"]("oidc|manual-requester")

    def test_manual_sync_rejects_missing_requester_identity(self):
        with tenant_context(7), self.assertRaises(ValueError):
            self.ns["trigger_manual_sync"]("")
        self.ns["run_document_scan_pipeline"].assert_not_called()

    def test_autonomous_scan_uses_monitor_service_identity(self):
        context = self.ns["_scan_request_context"](71)
        self.assertEqual(context["requested_by"], "service:document-monitor")
        self.assertTrue(context["request_id"])
        self.assertEqual(self.ns["last_sync_time"], "N/A")


class MonitoringConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = Path(__file__).resolve().parents[1] / "startup/validation.py"
        node = next(node for node in ast.parse(source.read_text()).body
                    if isinstance(node, ast.FunctionDef) and node.name == "background_monitor_config_errors")
        cls.ns = {"os": __import__("os")}
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), "exec"), cls.ns)

    def test_monitor_is_disabled_by_default(self):
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(self.ns["background_monitor_config_errors"](), [])

    def test_enabled_monitor_requires_explicit_positive_tenant(self):
        for tenant in ("", "0", "-1", "tenant-header"):
            with self.subTest(tenant=tenant), patch.dict(
                    "os.environ", {"AUTHCLAW_DISABLE_BACKGROUND_MONITOR": "false",
                                   "AUTHCLAW_BACKGROUND_MONITOR_TENANT_ID": tenant}, clear=True):
                self.assertTrue(self.ns["background_monitor_config_errors"]())
        with patch.dict("os.environ", {"AUTHCLAW_DISABLE_BACKGROUND_MONITOR": "false",
                                      "AUTHCLAW_BACKGROUND_MONITOR_TENANT_ID": "7"}, clear=True):
            self.assertEqual(self.ns["background_monitor_config_errors"](), [])

    def test_monitor_flag_rejects_malformed_boolean(self):
        with patch.dict("os.environ", {"AUTHCLAW_DISABLE_BACKGROUND_MONITOR": "sometimes"}, clear=True):
            self.assertTrue(self.ns["background_monitor_config_errors"]())


if __name__ == "__main__":
    unittest.main()

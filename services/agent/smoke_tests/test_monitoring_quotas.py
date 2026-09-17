"""Execute actual monitoring functions with filesystem/database I/O seams."""
import ast
from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, mock_open

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.quota_service import QuotaExceeded, QuotaUnavailable
from services.tenant_context import get_current_tenant_id, tenant_context


class MonitoringQuotaTests(unittest.TestCase):
    def setUp(self):
        source = Path(__file__).resolve().parents[1] / "document_processing/monitoring.py"
        nodes = [node for node in ast.parse(source.read_text()).body
                 if isinstance(node, ast.FunctionDef) and node.name in
                 {"sync_sources", "trigger_manual_sync", "_monitor_loop"}]
        self.conn = Mock()
        self.conn.execute.return_value.fetchone.return_value = (1, 2, "completed")
        self.conn.execute.return_value.fetchall.return_value = []
        self.engine = Mock()
        self.engine.connect.return_value.__enter__ = Mock(return_value=self.conn)
        self.engine.connect.return_value.__exit__ = Mock(return_value=False)
        self.ns = {"get_current_tenant_id": get_current_tenant_id,
                   "QuotaExceeded": QuotaExceeded, "QuotaUnavailable": QuotaUnavailable,
                   "record_unavailable": Mock(), "engine": self.engine, "text": lambda value: value,
                   "get_watched_directory": Mock(), "WATCH_DIR": "fixture",
                   "os": Mock(), "open": mock_open(read_data=b"data"),
                   "run_document_scan_pipeline": Mock(), "logger": Mock(),
                   "is_real_connectors_enabled": lambda: False,
                   "list_cloud_source_files": Mock(return_value=[]),
                   "datetime": datetime, "timezone": timezone, "last_sync_time": "N/A"}
        self.ns["os"].listdir.return_value = ["document.txt"]
        self.ns["os"].path.isfile.return_value = True
        self.ns["os"].path.getsize.return_value = 4
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec"), self.ns)

    def test_unbound_background_stops_before_io(self):
        with tenant_context(None):
            self.ns["_monitor_loop"]()
        self.ns["get_watched_directory"].assert_not_called()
        self.engine.connect.assert_not_called()
        self.ns["run_document_scan_pipeline"].assert_not_called()

    def test_manual_quota_failure_is_not_success(self):
        for failure in (QuotaExceeded("expensive_model"), QuotaUnavailable("Redis unavailable")):
            self.ns["run_document_scan_pipeline"].side_effect = failure
            with tenant_context(7), self.assertRaises(type(failure)):
                self.ns["trigger_manual_sync"]()
            self.assertEqual(self.ns["last_sync_time"], "N/A")
            self.ns["list_cloud_source_files"].assert_not_called()

    def test_manual_passes_verified_tenant_and_scopes_queries(self):
        with tenant_context(7):
            self.assertEqual(self.ns["trigger_manual_sync"]()["status"], "success")
        self.assertEqual(self.ns["run_document_scan_pipeline"].call_args.kwargs["tenant_id"], "7")
        for call in self.conn.execute.call_args_list:
            self.assertIn("tenant_id = :tenant_id", call.args[0])
            self.assertEqual(call.args[1]["tenant_id"], "7")

    def test_cloud_quota_failure_propagates(self):
        self.ns["os"].listdir.return_value = []
        self.ns["list_cloud_source_files"].side_effect = QuotaUnavailable("quota unavailable")
        with tenant_context(7), self.assertRaises(QuotaUnavailable):
            self.ns["trigger_manual_sync"]()
        self.assertEqual(self.ns["last_sync_time"], "N/A")


if __name__ == "__main__":
    unittest.main()

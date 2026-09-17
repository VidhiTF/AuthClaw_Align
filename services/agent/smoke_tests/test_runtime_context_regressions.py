"""Runtime regressions that need no database or destructive test fixtures."""

import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

from services.rbac_matrix import is_public_endpoint, role_allowed
from services.tenant_context import (
    get_current_request_id,
    get_current_tenant_id,
    is_tenant_context_required,
    tenant_context,
)


class RuntimeContextRegressionTests(unittest.TestCase):
    def test_canonical_health_aliases_allow_unauthenticated_probes(self):
        for path in ("/api/v1/agent/health", "/api/v1/agent/health/ready"):
            with self.subTest(path=path):
                self.assertTrue(is_public_endpoint("GET", path))
                self.assertTrue(role_allowed(None, "GET", path))
        self.assertFalse(is_public_endpoint("POST", "/api/v1/agent/executions"))
        self.assertFalse(role_allowed(None, "POST", "/api/v1/agent/executions"))

    def test_detailed_health_requires_platform_operations_access(self):
        self.assertFalse(is_public_endpoint("GET", "/health/details"))
        self.assertFalse(role_allowed(None, "GET", "/operations/health/details"))
        self.assertFalse(role_allowed("admin", "GET", "/operations/health/details"))
        self.assertTrue(role_allowed("platform_admin", "GET", "/operations/health/details"))

    def test_approval_worker_retains_authenticated_database_context(self):
        observed = []

        def create_approval(**kwargs):
            observed.append((get_current_tenant_id(), get_current_request_id(), is_tenant_context_required()))
            return {"approval_id": "approval-test"}

        store = types.ModuleType("approval_store")
        store.create_approval = create_approval
        path = Path(__file__).resolve().parents[1] / "nodes" / "approval_node.py"
        spec = importlib.util.spec_from_file_location("approval_node_regression", path)
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {"approval_store": store}):
            spec.loader.exec_module(module)

        for tenant_id in (41, 82):
            with tenant_context(tenant_id, request_id=f"req-{tenant_id}", required=True):
                result = module.approval_node({
                    "message": "Delete sensitive records", "risk_level": "HIGH",
                    "tenant_id": tenant_id, "request_id": f"req-{tenant_id}",
                })
                self.assertEqual(result["approval_status"], "PENDING_APPROVAL")
        self.assertEqual(observed, [("41", "req-41", True), ("82", "req-82", True)])
        self.assertIsNone(get_current_tenant_id())


if __name__ == "__main__":
    unittest.main()

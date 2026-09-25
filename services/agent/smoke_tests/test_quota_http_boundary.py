"""Exercise the actual main.py boundary in ASGI without booting its database.

Only the selected production definitions are extracted; collaborators are supplied
at their I/O seams. Full application startup and PostgreSQL/RLS remain separate.
"""
import ast
from datetime import datetime, timezone
import hashlib
import importlib.util
import os
import secrets
from pathlib import Path
import sys
import unittest
import types
from unittest.mock import AsyncMock, MagicMock, Mock, patch
import uuid

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from starlette.concurrency import run_in_threadpool

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services import quota_service as quota
from services.document_monitor_status import monitor_metrics_snapshot
from services.tenant_context import tenant_context, get_current_tenant_id
from approval_store import ApprovalPersistenceError


def boundary_namespace():
    names = {
        "_is_public_or_auth_path", "_tenant_id_from_request_headers",
        "tenant_database_context_middleware", "get_health", "get_readiness",
        "get_quota_metrics",
        "_tenant_tier_limit", "quota_exceeded_response", "quota_unavailable_response",
        "production_rbac_enforcement_middleware",
    }
    source = Path(__file__).resolve().parents[1] / "main.py"
    nodes = [node for node in ast.parse(source.read_text(encoding="utf-8")).body
             if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names]
    for node in nodes:
        node.decorator_list = []
    namespace = {
        "Request": Request, "Response": Response, "Header": Header,
        "HTTPException": HTTPException,
        "JSONResponse": JSONResponse, "Optional": __import__("typing").Optional,
        "os": os, "secrets": secrets, "uuid": uuid, "hashlib": hashlib,
        "tenant_context": tenant_context,
        "admit": quota.admit, "check_available": quota.check_available,
        "metrics_snapshot": quota.metrics_snapshot, "QuotaExceeded": quota.QuotaExceeded,
        "monitor_metrics_snapshot": monitor_metrics_snapshot,
        "record_unavailable": quota.record_unavailable,
        "QuotaUnavailable": quota.QuotaUnavailable,
        "authenticate_control_plane": AsyncMock(return_value=None),
        "resolve_api_key_principal": lambda key: {
            "tenant_id": 7, "sub": "service:tenant", "role": "operator"},
        "revalidate_tenant_session_payload": lambda payload, request_id=None: payload,
        "reconcile_due_approval_executions": Mock(return_value=0),
        "ApprovalPersistenceError": ApprovalPersistenceError,
        "run_in_threadpool": run_in_threadpool,
        "datetime": datetime, "timezone": timezone,
    }
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec"), namespace)
    return namespace


class QuotaHTTPBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {
            "AUTHCLAW_ENV": "development", "AUTHCLAW_RATE_LIMIT_ENABLED": "true",
            "AUTHCLAW_ALLOW_MEMORY_RATE_LIMIT": "true", "REDIS_URL": "",
            **{name: "100" for name in quota.LIMITS.values()},
        }, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        quota._memory.clear()
        self.ns = boundary_namespace()
        self.plan_lookup = self.ns["_tenant_tier_limit"]
        self.ns["decode_jwt"] = lambda token: ({"tenant_id": 7, "user_id": "alice"} if token == "valid" else None)
        self.ns["resolve_api_key_principal"] = Mock(return_value={
            "tenant_id": 7, "sub": "service:tenant", "role": "operator"})
        self.ns["_tenant_tier_limit"] = Mock(return_value=100)
        self.ns["_rbac_enforcement_enabled"] = lambda: False
        self.ns["optional_user_from_request"] = lambda request: {}
        self.calls = []
        self.app = FastAPI()
        self.app.middleware("http")(self.ns["tenant_database_context_middleware"])
        self.app.add_exception_handler(quota.QuotaExceeded, self.ns["quota_exceeded_response"])
        self.app.add_exception_handler(quota.QuotaUnavailable, self.ns["quota_unavailable_response"])

        async def handler(request: Request):
            self.calls.append(get_current_tenant_id())
            if request.url.path == "/crash":
                raise RuntimeError("downstream failed")
            if request.url.path == "/provider":
                quota.admit(get_current_tenant_id(), provider_model="resolved:model")
            return {"ok": True}

        for path in ("/chat", "/api/chat", "/api/v1/agent/executions", "/gateway/documents/redact",
                     "/internal/policy/evaluate", "/crash", "/provider", "/health/extra"):
            self.app.add_api_route(path, handler, methods=["POST"])
        self.app.add_api_route("/health", self.ns["get_health"])
        self.app.add_api_route("/health/ready", self.ns["get_readiness"])
        self.app.add_api_route("/internal/metrics/quota", self.ns["get_quota_metrics"])
        self.client = TestClient(self.app, raise_server_exceptions=False)
        self.headers = {"Authorization": "Bearer valid"}

    def test_success_executes_once_and_preserves_context(self):
        response = self.client.post("/chat", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.calls, ["7"])
        self.assertIsNone(get_current_tenant_id())

    def test_downstream_failure_executes_exactly_once(self):
        self.assertEqual(self.client.post("/crash", headers=self.headers).status_code, 500)
        self.assertEqual(self.calls, ["7"])

    def test_every_protected_alias_denied_without_downstream(self):
        self.ns["admit"] = Mock(side_effect=quota.QuotaUnavailable("unavailable"))
        for path in ("/chat", "/api/chat", "/api/v1/agent/executions", "/gateway/documents/redact",
                     "/internal/policy/evaluate", "/health/extra"):
            response = self.client.post(path, headers={**self.headers, "X-AuthClaw-Gateway": "go"})
            self.assertEqual(response.status_code, 503, path)
        self.assertEqual(self.calls, [])

    def test_unknown_plan_never_reaches_admission_or_downstream(self):
        self.ns["_tenant_tier_limit"].side_effect = RuntimeError("database failed")
        self.ns["admit"] = Mock()
        self.assertEqual(self.client.post("/chat", headers=self.headers).status_code, 503)
        self.ns["admit"].assert_not_called()
        self.assertEqual(self.calls, [])

    def test_auth_failures_keep_status_and_do_not_execute(self):
        self.assertEqual(self.client.post("/chat").status_code, 401)
        for code in (401, 403):
            self.ns["resolve_api_key_principal"].side_effect = HTTPException(code, "denied")
            self.assertEqual(self.client.post("/chat", headers={"X-API-Key": "invalid"}).status_code, code)
        self.assertEqual(self.calls, [])

    def test_outer_rbac_failures_keep_401_403_and_503(self):
        self.ns["_rbac_enforcement_enabled"] = lambda: True
        enforce = Mock()
        with patch.dict(sys.modules, {"services.rbac_matrix": types.SimpleNamespace(
            is_public_endpoint=lambda method, path: False, enforce_request_access=enforce,
        )}):
            for error, code in ((HTTPException(401, "denied"), 401), (HTTPException(403, "denied"), 403), (RuntimeError("auth state unknown"), 503)):
                enforce.side_effect = error
                self.assertEqual(self.client.post("/chat", headers=self.headers).status_code, code)
        self.assertEqual(self.calls, [])

    def test_client_identity_headers_cannot_select_subjects(self):
        self.ns["admit"] = Mock()
        self.client.post("/chat", headers={**self.headers, "X-Tenant-ID": "999", "X-User-ID": "mallory"})
        self.assertEqual(self.ns["admit"].call_args.args, (7,))
        self.assertEqual(self.ns["admit"].call_args.kwargs["user_id"], "alice")

    def test_multiple_service_keys_share_service_user(self):
        self.ns["admit"] = Mock()
        for key in ("key-a", "key-b"):
            self.assertEqual(self.client.post("/chat", headers={"X-API-Key": key}).status_code, 200)
        calls = self.ns["admit"].call_args_list
        self.assertEqual([c.kwargs["user_id"] for c in calls], ["service:tenant"] * 2)
        self.assertNotEqual(calls[0].kwargs["key_id"], calls[1].kwargs["key_id"])

    def test_exhaustion_returns_429_without_downstream(self):
        self.ns["admit"] = Mock(side_effect=quota.QuotaExceeded("user"))
        response = self.client.post("/chat", headers=self.headers)
        self.assertEqual(response.status_code, 429)
        self.assertIn("Retry-After", response.headers)
        self.assertEqual(self.calls, [])

    def test_liveness_is_coarse_and_does_not_depend_on_database_or_redis(self):
        self.ns["admit"] = Mock(side_effect=RuntimeError("down"))
        self.ns["check_available"] = Mock(side_effect=RuntimeError("down"))
        self.assertEqual(self.client.get("/health").json(), {"status": "alive", "scope": "process_liveness"})
        response = self.client.get("/health?metrics=true")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "alive", "scope": "process_liveness"})
        self.ns["check_available"].assert_not_called()

    def test_quota_metrics_require_dedicated_service_secret(self):
        self.assertEqual(self.client.get("/internal/metrics/quota").status_code, 503)
        with patch.dict(os.environ, {"AUTHCLAW_QUOTA_METRICS_SECRET": "metrics-secret"}):
            for token, status_code in ((None, 401), ("wrong", 401), ("metrics-secret", 200)):
                headers = {} if token is None else {"Authorization": f"Bearer {token}"}
                response = self.client.get("/internal/metrics/quota", headers=headers)
                self.assertEqual(response.status_code, status_code)
                if status_code == 200:
                    self.assertIn("authclaw_quota_available", response.text)

    def test_provider_quota_status_is_not_converted_to_success(self):
        with patch.dict(os.environ, {quota.LIMITS["expensive_model"]: "1"}):
            self.assertEqual(self.client.post("/provider", headers=self.headers).status_code, 200)
            self.assertEqual(self.client.post("/provider", headers=self.headers).status_code, 429)

    def test_readiness_reflects_unavailability_and_recovery(self):
        self.ns["_rbac_enforcement_enabled"] = lambda: True
        self.ns["validate_database_security"] = Mock()
        self.ns["check_available"] = Mock(side_effect=quota.QuotaUnavailable("Redis unavailable"))
        with patch.dict(sys.modules, {"database": types.SimpleNamespace(engine=Mock())}):
            response = self.client.get("/health/ready")
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.json()["checks"]["rate_limiter"], "unhealthy")
            self.ns["check_available"].side_effect = None
            self.assertEqual(self.client.get("/health/ready").status_code, 200)

    def test_real_plan_resolver_rejects_missing_unknown_and_invalid_limits(self):
        engine = MagicMock()
        conn = engine.connect.return_value.__enter__.return_value
        self.ns["text"] = lambda sql: sql
        path = Path(__file__).resolve().parents[1] / "services/tenant_plan_service.py"
        spec = importlib.util.spec_from_file_location("quota_plan_lookup_fixture", path)
        plans = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {"database": types.SimpleNamespace(engine=engine)}):
            spec.loader.exec_module(plans)
        modules = {
            "database": types.SimpleNamespace(engine=engine),
            "services.tenant_plan_service": plans,
        }
        with patch.dict(sys.modules, modules):
            for row in (None, (None, None, None), ("unknown", None, None), ("", "", "")):
                conn.execute.return_value.fetchone.return_value = row
                with self.assertRaises(quota.QuotaUnavailable):
                    self.plan_lookup(7)
            conn.execute.return_value.fetchone.return_value = ("free", None, None)
            self.assertEqual(self.plan_lookup(7), 30)
            conn.execute.return_value.fetchone.return_value = ("enterprise", "starter", "starter")
            with patch.dict(os.environ, {"AUTHCLAW_RATE_LIMIT_PER_MINUTE": "1200"}):
                self.assertEqual(self.plan_lookup(7), 60)
            conn.execute.return_value.fetchone.return_value = ("free", None, None)
            for value in ("0", "-1", "bad"):
                with patch.dict(os.environ, {"AUTHCLAW_RATE_LIMIT_FREE_RPM": value}):
                    with self.assertRaises((quota.QuotaUnavailable, ValueError)):
                        self.plan_lookup(7)
            conn.execute.side_effect = TimeoutError("lookup timeout")
            with self.assertRaises(TimeoutError):
                self.plan_lookup(7)

    def test_plan_service_cannot_display_fallback_enterprise_limits(self):
        path = Path(__file__).resolve().parents[1] / "services/tenant_plan_service.py"
        spec = importlib.util.spec_from_file_location("quota_plan_fixture", path)
        plans = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {"database": types.SimpleNamespace(engine=Mock())}):
            spec.loader.exec_module(plans)
        service = plans.TenantPlanService()
        for plan in ("", "unknown"):
            with self.assertRaises(ValueError):
                service._limits(plan)
        with self.assertRaises(ValueError):
            plans.resolve_tenant_plan(None, "", None)
        self.assertEqual(
            plans.resolve_tenant_plan("enterprise", "starter", "starter"),
            "starter",
        )
        self.assertEqual(service._limits("free")["requests_per_minute"], 30)
        for limit in ("0", "-1", "not-a-limit"):
            with patch.dict(os.environ, {"AUTHCLAW_RATE_LIMIT_FREE_RPM": limit}), self.assertRaises(ValueError):
                service._limits("free")

    def test_plan_schema_has_no_implicit_enterprise_and_registration_is_explicit(self):
        migrations = (
            Path(__file__).resolve().parents[1] / "database/migrations.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("VARCHAR(50) DEFAULT 'enterprise'", migrations)
        for column in ("subscription_tier", "plan", "tier"):
            self.assertIn(f"ALTER COLUMN {column} DROP DEFAULT", migrations)

        main = (Path(__file__).resolve().parents[1] / "main.py").read_text(
            encoding="utf-8"
        )
        registration = main[main.index("def activate_verified_registration"):]
        registration = registration[:registration.index("def ", 10)]
        self.assertIn("subscription_tier, plan, tier, plan_updated_at", registration)
        self.assertIn("'free', 'free', 'free', NOW()", registration)


if __name__ == "__main__":
    unittest.main()

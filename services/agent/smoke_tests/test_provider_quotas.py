import os
import ast
import concurrent.futures
from contextvars import copy_context
from pathlib import Path
import time
import unittest
import sys
import types
from unittest.mock import Mock, patch

from providers.anthropic_provider import AnthropicProvider
from providers.azure_openai_provider import AzureOpenAIProvider
from providers.cohere_provider import CohereProvider
from providers.gemini_provider import GeminiProvider
from providers.openai_provider import OpenAIProvider
from services.quota_service import QuotaExceeded, QuotaUnavailable
from services.tenant_context import tenant_context
from services.tenant_context import get_current_tenant_id


class ProviderQuotaTests(unittest.TestCase):
    def setUp(self):
        binding = patch("providers.base.provider_quota_tenant", side_effect=lambda tenant: tenant)
        binding.start()
        self.addCleanup(binding.stop)

    def providers(self):
        return [
            OpenAIProvider(api_key="test"),
            AnthropicProvider(api_key="test"),
            AzureOpenAIProvider(api_key="test", api_url="https://azure.invalid"),
            CohereProvider(api_key="test"),
            GeminiProvider(api_key="test", model_name="gemini-3.1-flash-lite"),
        ]

    def response(self, status=200):
        response = Mock(status_code=status)
        response.json.return_value = {
            "choices": [{"message": {"content": "ok"}}],
            "content": [{"type": "text", "text": "ok"}],
            "message": {"content": [{"type": "text", "text": "ok"}]},
            "candidates": [{"content": {"parts": [{"text": "ok"}]}}],
        }
        return response

    def test_each_direct_provider_denial_never_calls_http(self):
        for provider in self.providers():
            for error in (QuotaUnavailable("outage"), QuotaExceeded("expensive_model")):
                with self.subTest(provider=type(provider).__name__, error=type(error).__name__):
                    with tenant_context("tenant-a"), patch("providers.base.quota_service.admit", side_effect=error) as admit, patch("requests.post") as post:
                        with self.assertRaises(type(error)):
                            provider.generate("hello")
                    admit.assert_called_once()
                    post.assert_not_called()

    def test_each_success_charges_resolved_model_once(self):
        for provider in self.providers():
            with self.subTest(provider=type(provider).__name__):
                with tenant_context("tenant-a"), patch("providers.base.quota_service.admit") as admit, patch("requests.post", return_value=self.response()) as post:
                    self.assertEqual(provider.generate("hello"), "ok")
                post.assert_called_once()
                admit.assert_called_once()
                self.assertEqual(admit.call_args.args, ("tenant-a",))
                self.assertEqual(set(admit.call_args.kwargs), {"provider_model"})
                self.assertTrue(admit.call_args.kwargs["provider_model"].endswith(":" + provider.model_name))

    def test_missing_verified_tenant_denies(self):
        with tenant_context(None), patch("requests.post") as post:
            with self.assertRaises(QuotaUnavailable):
                OpenAIProvider(api_key="test").generate("hello")
        post.assert_not_called()

    def test_gemini_retry_requires_new_admission_and_stops_on_denial(self):
        with tenant_context("tenant-a"), patch("providers.base.quota_service.admit", side_effect=[None, QuotaExceeded("expensive_model")]) as admit, patch("requests.post", return_value=self.response(503)) as post, patch("time.sleep"):
            with self.assertRaises(QuotaExceeded):
                GeminiProvider(api_key="test", timeout=30).generate("hello")
        self.assertEqual(admit.call_count, 2)
        post.assert_called_once()

    def test_embeddings_quota_failure_does_not_disable_or_fallback(self):
        from rag import embeddings
        for error in (QuotaUnavailable("outage"), QuotaExceeded("expensive_model")):
            with patch.dict(os.environ, {"GOOGLE_API_KEY": "test", "AUTHCLAW_DISABLE_REMOTE_EMBEDDINGS": "false"}), patch.object(embeddings, "_remote_embeddings_disabled", False), patch.object(embeddings, "admit_provider_call", side_effect=error), patch("requests.post") as post:
                with self.assertRaises(type(error)):
                    embeddings.generate_embedding("hello")
                self.assertFalse(embeddings._remote_embeddings_disabled)
                post.assert_not_called()

    def test_llm_worker_preserves_context_and_propagates_quota_failure(self):
        # Execute the production function with audit/storage seams isolated.
        tree = ast.parse((Path(__file__).parents[1] / "nodes" / "llm_node.py").read_text(encoding="utf-8"))
        node = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "llm_node")
        provider = Mock()
        seen = []

        def generate(prompt):
            seen.append(get_current_tenant_id())
            raise QuotaUnavailable("outage")

        provider.generate.side_effect = generate
        namespace = {
            "copy_context": copy_context, "concurrent": concurrent, "time": time,
            "QuotaExceeded": QuotaExceeded, "QuotaUnavailable": QuotaUnavailable,
            "_build_prompt": lambda state: "hello", "_resolve_provider": lambda state: provider,
            "_provider_call_kwargs": lambda state: {},
            "_provider_error_metadata": lambda exc: {"code": "provider_failure"},
            "log_agent_event": Mock(), "_offline_provider_fallback": Mock(),
        }
        exec(compile(ast.Module(body=[node], type_ignores=[]), "llm_node.py", "exec"), namespace)
        with tenant_context("tenant-a"):
            with self.assertRaises(QuotaUnavailable):
                namespace["llm_node"]({"allowed": True, "tenant_id": "tenant-a"})
        self.assertEqual(seen, ["tenant-a"])
        namespace["_offline_provider_fallback"].assert_not_called()


class ProviderTenantBindingTests(unittest.TestCase):
    def test_trusted_database_binding_unifies_gateway_provider_ledger(self):
        from providers.base import provider_quota_tenant
        engine = Mock()
        connection = engine.connect.return_value.__enter__ = Mock()
        engine.connect.return_value.__exit__ = Mock(return_value=False)
        connection.return_value.execute.return_value.fetchone.return_value = ("external-tenant",)
        with patch.dict(sys.modules, {"database": types.SimpleNamespace(engine=engine)}):
            self.assertEqual(provider_quota_tenant("7"), "external-tenant")
            self.assertEqual(connection.return_value.execute.call_args.args[1], {"tenant_id": "7"})
            connection.return_value.execute.return_value.fetchone.return_value = (None,)
            self.assertEqual(provider_quota_tenant("7"), "agent:7")
            connection.return_value.execute.return_value.fetchone.return_value = None
            with self.assertRaises(QuotaUnavailable):
                provider_quota_tenant("7")

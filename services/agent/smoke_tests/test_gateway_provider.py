import unittest
from unittest.mock import Mock, patch

from providers.gateway_provider import GatewayProvider
from services.gateway_service import (
    GatewayExecutionOutcome,
    GatewayProviderUnavailableError,
    GatewayService,
)


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code
        self.ok = status_code < 400
        self.headers = {"content-type": "application/json"}

    def json(self):
        return self.payload


class GatewayProviderTests(unittest.TestCase):
    def _execute_approval(self, result):
        service = GatewayService(
            graph=Mock(invoke=Mock(return_value=result)),
            resolve_tenant=Mock(),
            decode_jwt=Mock(),
        )
        service.get_trace = Mock(return_value=[])
        service.persist_latest_message_trace = Mock()
        record = {
            "approval_id": "approval-17",
            "tenant_id": 42,
            "correlation_id": "correlation-17",
            "query": "perform approved action",
            "risk_level": "HIGH",
            "request_id": "request-17",
        }
        with (
            patch("services.gateway_service.log_agent_event"),
            patch("services.gateway_service.RegistrarService") as registrar,
        ):
            execution = service.execute_approval(
                approval_record=record,
                authorization="Bearer token",
                x_api_key=None,
                idempotency_key="operation-17",
            )
        return execution, registrar.return_value.register_gateway_request

    def test_policy_denial_has_closed_non_success_outcome(self):
        execution, register = self._execute_approval({
            "allowed": False,
            "decision": "DENY",
            "response": "blocked",
        })

        self.assertEqual(execution.outcome, GatewayExecutionOutcome.POLICY_DENIED)
        self.assertIsNone(execution.provider_operation_id)
        self.assertFalse(register.call_args.kwargs["allowed"])
        self.assertEqual(register.call_args.kwargs["status"], "blocked")

    def test_offline_fallback_is_provider_unavailable_not_success(self):
        with self.assertRaises(GatewayProviderUnavailableError):
            self._execute_approval({
                "allowed": True,
                "decision": "ALLOW",
                "provider_status": "offline_fallback",
                "response": "offline response",
            })

    def test_provider_success_requires_explicit_ok_status(self):
        execution, register = self._execute_approval({
            "allowed": True,
            "decision": "ALLOW",
            "provider_status": "ok",
            "response": "provider response",
            "provider": "openai",
            "model": "gpt-test",
        })

        self.assertEqual(execution.outcome, GatewayExecutionOutcome.SUCCEEDED)
        self.assertEqual(execution.provider_operation_id, "approval-exec-operation-17")
        self.assertTrue(register.call_args.kwargs["allowed"])
        self.assertEqual(register.call_args.kwargs["status"], "allowed")

    def test_approved_execution_identity_reaches_gateway_headers(self):
        response = Mock(ok=True, status_code=200)
        response.json.return_value = {"choices": [{"message": {"content": "ok"}}]}

        with patch("providers.gateway_provider.requests.post", return_value=response) as post:
            result = GatewayProvider("tenant-key", "openai").generate(
                "hello",
                idempotency_key="operation-17",
                request_id="approval-exec-operation-17",
            )

        self.assertEqual(result, "ok")
        self.assertEqual(post.call_args.kwargs["headers"]["Idempotency-Key"], "operation-17")
        self.assertEqual(post.call_args.kwargs["headers"]["X-Request-ID"], "approval-exec-operation-17")

    CASES = [
        ("openai", "/v1/chat/completions", {"choices": [{"message": {"content": "openai ok"}}]}, "openai ok"),
        ("anthropic", "/v1/messages", {"content": [{"type": "text", "text": "anthropic ok"}]}, "anthropic ok"),
        ("cohere", "/v2/chat", {"message": {"content": [{"type": "text", "text": "cohere ok"}]}}, "cohere ok"),
        ("azure_openai", "/openai/deployments/gpt-4o/chat/completions", {"choices": [{"message": {"content": "azure ok"}}]}, "azure ok"),
        ("gemini", "/v1/models/gemini-2.5-flash-lite:generateContent", {"candidates": [{"content": {"parts": [{"text": "gemini ok"}]}}]}, "gemini ok"),
    ]

    def test_supported_providers_use_tenant_gateway_key(self):
        for provider, expected_path, response, expected in self.CASES:
            with self.subTest(provider=provider):
                captured = {}

                def post(url, **kwargs):
                    captured.update(url=url, **kwargs)
                    return FakeResponse(response)

                with patch("providers.gateway_provider.requests.post", post):
                    result = GatewayProvider("tenant-key", provider, api_url="http://gateway:8080").generate("hello")

                self.assertEqual(result, expected)
                self.assertTrue(captured["url"].endswith(expected_path))
                self.assertEqual(captured["headers"]["Authorization"], "Bearer tenant-key")
                self.assertEqual(captured["headers"]["X-Provider"], provider)

    def test_safe_gateway_error(self):
        response = FakeResponse({"message": "sensitive provider response"}, 502)
        with patch("providers.gateway_provider.requests.post", return_value=response):
            with self.assertRaisesRegex(RuntimeError, "HTTP 502: Provider unavailable") as caught:
                GatewayProvider("tenant-key", "gemini").generate("hello")
        self.assertNotIn("sensitive provider response", str(caught.exception))


if __name__ == "__main__":
    unittest.main()

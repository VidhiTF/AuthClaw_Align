import pathlib
import unittest


class ProviderLoggingSanitizationTests(unittest.TestCase):
    def test_connection_error_retains_status_without_provider_body(self):
        source = (
            pathlib.Path(__file__).parents[1] / "services" / "provider_connection_tester.py"
        ).read_text(encoding="utf-8")
        self.assertIn('f"Provider returned HTTP {response.status_code}."', source)
        self.assertNotIn("response.text", source)

    def test_verified_log_sinks_do_not_interpolate_provider_bodies(self):
        root = pathlib.Path(__file__).parents[1]
        files = [
            root / "providers" / "gemini_provider.py",
            root / "rag" / "embeddings.py",
            root / "rag" / "compliance_analyzer.py",
            root / "document_processing" / "orchestrator.py",
            root / "services" / "provider_connection_tester.py",
        ]
        for path in files:
            with self.subTest(path=path.name):
                source = path.read_text(encoding="utf-8")
                self.assertNotIn("res.text", source)
                self.assertNotIn("response.text[:", source)
                self.assertNotIn("Full response:", source)

        main_source = (root / "main.py").read_text(encoding="utf-8")
        self.assertNotIn("body=%s", main_source)
        self.assertIn("category=%s status=%s retryable=%s", main_source)
        self.assertIn('"Gemini document chat failed: status=%s"', main_source)

    def test_gemini_credentials_use_headers_not_urls(self):
        root = pathlib.Path(__file__).parents[1]
        files = [
            root / "main.py",
            root / "providers" / "gemini_provider.py",
            root / "rag" / "embeddings.py",
            root / "rag" / "compliance_analyzer.py",
            root / "document_processing" / "orchestrator.py",
            root / "services" / "provider_connection_tester.py",
        ]
        for path in files:
            with self.subTest(path=path.name):
                source = path.read_text(encoding="utf-8")
                self.assertNotIn("?key={", source)
                self.assertNotIn('params={"key": api_key}', source)
                self.assertIn('"x-goog-api-key"', source)

    def test_agent_diagnostics_do_not_log_sensitive_content(self):
        root = pathlib.Path(__file__).parents[1]
        forbidden_by_file = {
            root / "providers" / "gemini_provider.py": [
                "Network connection failed — {type(e).__name__}: {str(e)}",
                "Unexpected exception — {type(e).__name__}: {str(e)}",
            ],
            root / "nodes" / "redact_node.py": ['print("REDACT NODE:"'],
            root / "nodes" / "risk_node.py": ['"query": query[:100]'],
            root / "nodes" / "policy_node.py": ['print(f"POLICY NODE [', 'print("POLICY NODE:"'],
            root / "nodes" / "llm_node.py": ["LLM Node Provider error: {e}", "Primary model connection failed: {str(e)}"],
            root / "redaction.py": ["Matched: {trigger", "Redacted: {trigger", "User: {trigger"],
            root / "services" / "audit_agent.py": ['file.write(f"User:', 'file.write(f"AI:'],
            root / "main.py": ["user_query[:50]", '"question": req.question', '"doc_name": doc_name'],
        }
        for path, forbidden in forbidden_by_file.items():
            source = path.read_text(encoding="utf-8")
            for value in forbidden:
                with self.subTest(path=path.name, value=value):
                    self.assertNotIn(value, source)


if __name__ == "__main__":
    unittest.main()

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


if __name__ == "__main__":
    unittest.main()

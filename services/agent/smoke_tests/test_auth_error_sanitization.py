import pathlib
import unittest


class AuthenticationErrorSanitizationSmokeTests(unittest.TestCase):
    def test_enterprise_oidc_errors_are_logged_and_generic(self):
        source = (pathlib.Path(__file__).parents[1] / "main.py").read_text(encoding="utf-8")
        oidc_source = source[source.index("def oidc_public_providers"):source.index('@app.get("/security/posture")')]
        self.assertEqual(oidc_source.count('detail="OIDC authentication failed"'), 5)
        self.assertGreaterEqual(oidc_source.count('logger.exception("OIDC'), 5)
        self.assertNotIn("detail=str(exc)) from exc", oidc_source)


if __name__ == "__main__":
    unittest.main()

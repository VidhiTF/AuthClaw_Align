import os
import time
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import main as agent_main


class DiagnosticExposureTests(unittest.TestCase):
    @staticmethod
    def _authorization(role: str) -> dict[str, str]:
        token = agent_main.create_jwt({
            "sub": "diagnostic-test",
            "role": role,
            "tenant_id": None,
            "exp": int(time.time()) + 60,
        })
        return {"Authorization": f"Bearer {token}"}

    def test_detailed_readiness_enforces_http_authentication_and_redacts_validation_errors(self):
        validation_errors = [
            "SMTP_HOST must be configured in production.",
            "AUTHCLAW_ALLOWED_ORIGINS must not use a local origin.",
            "AWS_REGION must be configured.",
        ]
        client = TestClient(agent_main.app)

        self.assertEqual(client.get("/operations/health/details").status_code, 403)
        self.assertEqual(
            client.get(
                "/operations/health/details",
                headers=self._authorization("Super Admin"),
            ).status_code,
            403,
        )

        with (
            patch.dict(os.environ, {"AUTHCLAW_ENV": "production"}, clear=False),
            patch.object(agent_main, "validate_database_security"),
            patch(
                "startup.validation.validate_production_environment",
                return_value=validation_errors,
            ),
            self.assertLogs("authclaw.gateway", level="ERROR") as captured_logs,
        ):
            response = client.get(
                "/operations/health/details",
                headers=self._authorization("Platform Admin"),
            )

        self.assertEqual(response.status_code, 503)
        body = response.json()
        self.assertEqual(body["status"], "not_ready")
        failure = body["checks"]["production_failure"]
        self.assertEqual(failure["code"], "production_configuration_invalid")
        self.assertRegex(
            failure["correlation_id"],
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        )
        serialized_body = response.text
        for variable_name in ("SMTP_HOST", "AUTHCLAW_ALLOWED_ORIGINS", "AWS_REGION"):
            self.assertNotIn(variable_name, serialized_body)
        self.assertNotIn("production_errors", body["checks"])

        protected_log = "\n".join(captured_logs.output)
        self.assertIn(failure["correlation_id"], protected_log)
        for validation_error in validation_errors:
            self.assertIn(validation_error, protected_log)


if __name__ == "__main__":
    unittest.main()

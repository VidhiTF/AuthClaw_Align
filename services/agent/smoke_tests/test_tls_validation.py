import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


SERVICE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE_ROOT))

from startup.validation import validate_production_environment


class TLSValidationTests(unittest.TestCase):
    @patch("startup.validation.SecretManager")
    def test_production_rejects_malformed_opa_https_url(self, secret_manager):
        secret_manager.return_value.backend = "aws_kms"
        environment = {
            "AUTHCLAW_ALLOWED_ORIGINS": "https://app.example.com",
            "AUTHCLAW_OPA_ENABLED": "true",
            "AUTHCLAW_OPA_POLICY_URL": "https://",
            "AUTHCLAW_RATE_LIMIT_PER_MINUTE": "60",
            "SMTP_FROM": "security@example.com",
            "SMTP_HOST": "smtp.example.com",
        }

        with patch.dict(os.environ, environment, clear=True):
            errors = validate_production_environment()

        self.assertIn("Production requires AUTHCLAW_OPA_POLICY_URL to use HTTPS.", errors)


if __name__ == "__main__":
    unittest.main()

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REGIONAL_STACK = (ROOT / "infra/terraform/modules/regional_stack/main.tf").read_text(encoding="utf-8")
REGIONAL_OUTPUTS = (ROOT / "infra/terraform/modules/regional_stack/outputs.tf").read_text(encoding="utf-8")


class ACL10CryptographyControlTests(unittest.TestCase):
    def test_managed_key_rotation_and_encrypted_storage_are_declared(self):
        self.assertIn("enable_key_rotation     = true", REGIONAL_STACK)
        self.assertGreaterEqual(REGIONAL_STACK.count("kms_key_id = aws_kms_key.main.arn"), 6)
        self.assertIn("storage_encrypted       = true", REGIONAL_STACK)
        self.assertIn("at_rest_encryption_enabled = true", REGIONAL_STACK)
        self.assertIn("transit_encryption_enabled = true", REGIONAL_STACK)
        self.assertIn("sslmode=require", REGIONAL_STACK)

    def test_external_tls_uses_managed_certificate_and_modern_policy(self):
        self.assertIn('listener_protocol     = "HTTPS"', REGIONAL_STACK)
        self.assertIn("certificate_arn   = var.certificate_arn", REGIONAL_STACK)
        self.assertIn('ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"', REGIONAL_STACK)

    def test_production_refuses_the_current_plaintext_service_topology(self):
        self.assertIn('name = "AUTHCLAW_REQUIRE_SERVICE_TLS"', REGIONAL_STACK)
        self.assertIn('var.authclaw_env != "production" || alltrue([', REGIONAL_STACK)
        self.assertIn("Production is blocked until agent, gateway, OPA, and Presidio", REGIONAL_STACK)

    def test_envelope_rotation_keeps_current_and_previous_keys_available(self):
        self.assertIn('name = "ENVELOPE_KEY_V1"', REGIONAL_STACK)
        self.assertIn('name = "ENVELOPE_KEY_V2"', REGIONAL_STACK)
        self.assertIn("value = var.secret_key_version", REGIONAL_STACK)
        self.assertIn("envelope_v2", REGIONAL_OUTPUTS)


if __name__ == "__main__":
    unittest.main()

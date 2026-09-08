import unittest

from services.control_plane_auth import sign_control_plane_request, verify_control_plane_request


class ControlPlaneAuthSmokeTests(unittest.TestCase):
    def test_signature_is_scoped_and_expires(self):
        secret = "test-internal-secret"
        timestamp = "2000000000"
        signature = sign_control_plane_request(
            secret, timestamp, "POST", "/chat", "tenant-1", "user-1", "owner"
        )
        headers = {
            "x-authclaw-timestamp": timestamp,
            "x-authclaw-tenant-id": "tenant-1",
            "x-authclaw-user-id": "user-1",
            "x-authclaw-role": "owner",
            "x-authclaw-signature": signature,
        }

        self.assertTrue(verify_control_plane_request(headers, "POST", "/chat", secret, now=2000000000))
        self.assertIsNone(verify_control_plane_request(headers, "GET", "/chat", secret, now=2000000000))
        self.assertIsNone(verify_control_plane_request(headers, "POST", "/chat", secret, now=2000000061))

    def test_role_is_normalized_only_after_signature_verification(self):
        secret = "test-internal-secret"
        timestamp = "2000000000"
        path = "/api/v1/agent/executions"
        signature = sign_control_plane_request(
            secret, timestamp, "POST", path, "tenant-1", "user-1", "Super Admin"
        )
        headers = {
            "x-authclaw-timestamp": timestamp,
            "x-authclaw-tenant-id": "tenant-1",
            "x-authclaw-user-id": "user-1",
            "x-authclaw-role": "Super Admin",
            "x-authclaw-signature": signature,
        }

        principal = verify_control_plane_request(headers, "POST", path, secret, now=2000000000)
        self.assertIsNotNone(principal)
        self.assertEqual(principal.role, "owner")

        headers["x-authclaw-role"] = "owner"
        self.assertIsNone(verify_control_plane_request(headers, "POST", path, secret, now=2000000000))

    def test_unknown_signed_role_is_rejected(self):
        secret = "test-internal-secret"
        timestamp = "2000000000"
        path = "/api/v1/agent/executions"
        signature = sign_control_plane_request(
            secret, timestamp, "POST", path, "tenant-1", "user-1", "root"
        )
        headers = {
            "x-authclaw-timestamp": timestamp,
            "x-authclaw-tenant-id": "tenant-1",
            "x-authclaw-user-id": "user-1",
            "x-authclaw-role": "root",
            "x-authclaw-signature": signature,
        }
        self.assertIsNone(verify_control_plane_request(headers, "POST", path, secret, now=2000000000))


if __name__ == "__main__":
    unittest.main()

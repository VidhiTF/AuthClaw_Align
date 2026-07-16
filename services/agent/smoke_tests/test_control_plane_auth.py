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


if __name__ == "__main__":
    unittest.main()

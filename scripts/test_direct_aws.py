"""Offline contract tests for injected secrets and exact AWS resource selection."""
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services/agent"))
from services.secret_manager import SecretManager, SecretManagerError, generate_fernet_key
from document_processing.connectors import _aws_session
from services.control_plane_auth import sign_control_plane_request, verify_control_plane_request
from cryptography.exceptions import InvalidTag


class DirectAWSChecks(unittest.TestCase):
    def test_single_key_encryption_cutover_and_snapshot_rollback(self):
        old_key, new_key = generate_fernet_key(), generate_fernet_key()
        with patch.dict(os.environ, {"AUTHCLAW_ENCRYPTION_KEY": old_key}, clear=True):
            manager = SecretManager("ecs_injected")
            old_ciphertext = manager.encrypt_for_database("synthetic-provider")
            plaintext = manager.decrypt_from_database(old_ciphertext)
            os.environ["AUTHCLAW_ENCRYPTION_KEY"] = new_key
            with self.assertRaises(InvalidTag):
                manager.decrypt_from_database(old_ciphertext)
            new_ciphertext = manager.encrypt_for_database(plaintext)
            self.assertEqual(manager.decrypt_from_database(new_ciphertext), plaintext)
            os.environ["AUTHCLAW_ENCRYPTION_KEY"] = old_key
            self.assertEqual(manager.decrypt_from_database(old_ciphertext), plaintext)
            with self.assertRaises(InvalidTag):
                manager.decrypt_from_database(new_ciphertext)

    def test_redaction_salt_cutover_requires_matching_token_state(self):
        with patch.dict(os.environ, {"AUTHCLAW_REDACTION_SALT": "old-synthetic-salt" * 3}, clear=True):
            manager = SecretManager("ecs_injected")
            previous = manager.fingerprint("synthetic-sensitive-value")
            os.environ["AUTHCLAW_REDACTION_SALT"] = "new-synthetic-salt" * 3
            self.assertNotEqual(manager.fingerprint("synthetic-sensitive-value"), previous)
            os.environ["AUTHCLAW_REDACTION_SALT"] = "old-synthetic-salt" * 3
            self.assertEqual(manager.fingerprint("synthetic-sensitive-value"), previous)

    def test_internal_key_coordinated_cutover_and_rollback(self):
        headers = {"x-authclaw-timestamp": "2000000000", "x-authclaw-tenant-id": "tenant",
                   "x-authclaw-user-id": "user", "x-authclaw-role": "owner"}
        for sender, receiver, allowed in (("old", "old", True), ("new", "old", False),
                                          ("new", "new", True), ("old", "new", False), ("old", "old", True)):
            headers["x-authclaw-signature"] = sign_control_plane_request(
                sender, "2000000000", "POST", "/chat", "tenant", "user", "owner")
            self.assertEqual(bool(verify_control_plane_request(headers, "POST", "/chat", receiver, now=2000000000)), allowed)

    def test_kms_rotation_rollback_and_denial(self):
        manager = SecretManager("ecs_injected")
        kms = Mock()
        keys = {"old": os.urandom(32), "new": os.urandom(32)}

        def generate(**request):
            key = request["KeyId"]
            return {"Plaintext": keys[key], "CiphertextBlob": key.encode()}

        def decrypt(**request):
            self.assertEqual(request["EncryptionContext"], {"authclaw:purpose": "database-field"})
            self.assertEqual(request["CiphertextBlob"], request["KeyId"].encode())
            return {"Plaintext": keys[request["KeyId"]]}

        kms.generate_data_key.side_effect, kms.decrypt.side_effect = generate, decrypt
        with patch.object(manager, "_kms_client", return_value=kms), patch.dict(os.environ, {
            "AUTHCLAW_ENVELOPE_PROVIDER": "aws_kms", "AUTHCLAW_AWS_KMS_KEY_ID": "old"}):
            old = manager.encrypt_for_database("before")
            os.environ["AUTHCLAW_AWS_KMS_KEY_ID"] = "new"
            new = manager.encrypt_for_database("after")
            self.assertEqual(manager.decrypt_from_database(old), "before")
            os.environ["AUTHCLAW_AWS_KMS_KEY_ID"] = "old"
            self.assertEqual(manager.decrypt_from_database(new), "after")
            kms.decrypt.side_effect = PermissionError("denied")
            with self.assertRaises(SecretManagerError):
                manager.decrypt_from_database(old)

    def test_injected_startup_and_missing_secret(self):
        with patch.dict(os.environ, {"JWT_SECRET": "synthetic-jwt-" * 4,
            "AUTHCLAW_ENCRYPTION_KEY": generate_fernet_key(),
            "AUTHCLAW_REDACTION_SALT": "synthetic-salt-" * 4}, clear=True):
            manager = SecretManager("ecs_injected")
            manager.validate_startup(production=True)
            with self.assertRaises(SecretManagerError):
                manager.put_secret("JWT_SECRET", "replacement")
            del os.environ["AUTHCLAW_ENCRYPTION_KEY"]
            with self.assertRaises(SecretManagerError):
                manager.validate_startup(production=True)

    def test_exact_secret_mapping_and_recoverable_delete(self):
        arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:provider-abcdef"
        with patch.dict(os.environ, {"AUTHCLAW_AWS_SECRET_ARNS": json.dumps({"provider": arn})}, clear=True):
            manager = SecretManager("ecs_injected")
            client = Mock()
            client.exceptions.ResourceNotFoundException = type("Missing", (Exception,), {})
            with patch.object(manager, "_client", return_value=client):
                manager.get_secret("provider")
                client.get_secret_value.assert_called_once_with(SecretId=arn)
                manager.put_secret("provider", "synthetic")
                client.put_secret_value.assert_called_once_with(SecretId=arn, SecretString="synthetic")
                manager.delete_secret("provider")
                client.delete_secret.assert_called_once_with(SecretId=arn, RecoveryWindowInDays=7)
                with self.assertRaises(SecretManagerError):
                    manager.get_secret("unrelated")
                self.assertEqual(client.get_secret_value.call_count, 1)
                client.put_secret_value.side_effect = client.exceptions.ResourceNotFoundException()
                with self.assertRaises(SecretManagerError):
                    manager.put_secret("provider", "synthetic")
                client.create_secret.assert_not_called()

    def test_customer_external_id_is_forwarded(self):
        boto = Mock()
        boto.client.return_value.assume_role.return_value = {"Credentials": {
            "AccessKeyId": "synthetic", "SecretAccessKey": "synthetic", "SessionToken": "synthetic"}}
        with patch.dict(sys.modules, {"boto3": boto}), patch.dict(os.environ, {
            "AUTHCLAW_AWS_ROLE_ARN": "arn:aws:iam::123456789012:role/customer",
            "AUTHCLAW_AWS_EXTERNAL_ID": "approved-customer-id"}, clear=True):
            _aws_session()
            self.assertEqual(boto.client.return_value.assume_role.call_args.kwargs["ExternalId"], "approved-customer-id")


if __name__ == "__main__":
    unittest.main()

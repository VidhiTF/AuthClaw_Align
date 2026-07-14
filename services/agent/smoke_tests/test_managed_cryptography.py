import base64
import hashlib
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.exceptions import InvalidTag

SERVICE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE_ROOT))

from services.secret_manager import KMS_ENCRYPTION_CONTEXT, SecretManager, SecretManagerError


class FakeKMS:
    def __init__(self):
        self.keys = {}
        self.requests = []

    def generate_data_key(self, **request):
        self.requests.append(("generate", request))
        key_id = request["KeyId"]
        plaintext = hashlib.sha256(key_id.encode("utf-8")).digest()
        wrapped = f"wrapped:{key_id}".encode("utf-8")
        self.keys[wrapped] = (plaintext, request.get("EncryptionContext"))
        return {"Plaintext": plaintext, "CiphertextBlob": wrapped}

    def decrypt(self, **request):
        self.requests.append(("decrypt", request))
        wrapped = request["CiphertextBlob"]
        expected_key_id = wrapped.decode("utf-8").split(":", 1)[1]
        if request["KeyId"] != expected_key_id:
            raise PermissionError("wrong key id")
        plaintext, expected_context = self.keys[wrapped]
        if request.get("EncryptionContext") != expected_context:
            raise PermissionError("wrong encryption context")
        return {"Plaintext": plaintext}


class ManagedCryptographySmokeTests(unittest.TestCase):
    def _manager(self, kms, key_id="alias/authclaw-test"):
        env = {
            "AUTHCLAW_ENVELOPE_PROVIDER": "aws_kms",
            "AUTHCLAW_AWS_KMS_KEY_ID": key_id,
            "AWS_REGION": "us-east-1",
        }
        return patch.dict(os.environ, env), SecretManager("local_env"), patch.object(SecretManager, "_kms_client", return_value=kms)

    def test_kms_envelope_is_randomized_bound_and_round_trips(self):
        kms = FakeKMS()
        env, manager, client = self._manager(kms)
        with env, client:
            first = manager.encrypt_for_database("managed-secret")
            second = manager.encrypt_for_database("managed-secret")
            self.assertNotEqual(first, second)
            self.assertNotIn("managed-secret", first)
            self.assertEqual(manager.decrypt_from_database(first), "managed-secret")
            policy = manager.selection_policy()
            self.assertEqual(policy["envelope_provider"], "aws_kms")
            self.assertTrue(policy["envelope_fail_closed"])

        payload = json.loads(base64.urlsafe_b64decode(first.split(":", 2)[2]))
        self.assertEqual(payload["key_id"], "alias/authclaw-test")
        self.assertEqual(payload["encryption_context"], KMS_ENCRYPTION_CONTEXT)
        for _operation, request in kms.requests:
            self.assertEqual(request["EncryptionContext"], KMS_ENCRYPTION_CONTEXT)

    def test_rotation_keeps_key_identifier_with_each_ciphertext(self):
        kms = FakeKMS()
        env, manager, client = self._manager(kms, "alias/authclaw-v1")
        with env, client:
            old = manager.encrypt_for_database("old-version")
            os.environ["AUTHCLAW_AWS_KMS_KEY_ID"] = "alias/authclaw-v2"
            new = manager.encrypt_for_database("new-version")
            self.assertEqual(manager.decrypt_from_database(old), "old-version")
            self.assertEqual(manager.decrypt_from_database(new), "new-version")

        old_payload = json.loads(base64.urlsafe_b64decode(old.split(":", 2)[2]))
        new_payload = json.loads(base64.urlsafe_b64decode(new.split(":", 2)[2]))
        self.assertEqual(old_payload["key_id"], "alias/authclaw-v1")
        self.assertEqual(new_payload["key_id"], "alias/authclaw-v2")

    def test_kms_failure_never_falls_back_to_local_encryption(self):
        class DeniedKMS:
            def generate_data_key(self, **_request):
                raise PermissionError("sensitive provider detail")

        env, manager, client = self._manager(DeniedKMS())
        with env, client, self.assertRaisesRegex(SecretManagerError, "PermissionError") as caught:
            manager.encrypt_for_database("must-not-fallback")
        self.assertNotIn("sensitive provider detail", str(caught.exception))

    def test_tampered_ciphertext_is_rejected(self):
        kms = FakeKMS()
        env, manager, client = self._manager(kms)
        with env, client:
            encrypted = manager.encrypt_for_database("tamper-evident")
            payload = json.loads(base64.urlsafe_b64decode(encrypted.split(":", 2)[2]))
            raw = bytearray(base64.urlsafe_b64decode(payload["ciphertext"]))
            raw[-1] ^= 1
            payload["ciphertext"] = base64.urlsafe_b64encode(raw).decode("utf-8")
            tampered = "v3:envelope:" + base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
            with self.assertRaises(InvalidTag):
                manager.decrypt_from_database(tampered)

    def test_wrong_encryption_context_is_rejected(self):
        kms = FakeKMS()
        env, manager, client = self._manager(kms)
        with env, client:
            encrypted = manager.encrypt_for_database("context-bound")
            payload = json.loads(base64.urlsafe_b64decode(encrypted.split(":", 2)[2]))
            payload["encryption_context"] = {"authclaw:purpose": "wrong-purpose"}
            encoded = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
            tampered = "v3:envelope:" + encoded
            with self.assertRaisesRegex(SecretManagerError, "PermissionError"):
                manager.decrypt_from_database(tampered)


if __name__ == "__main__":
    unittest.main()

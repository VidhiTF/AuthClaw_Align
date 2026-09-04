"""Frozen migration-040 codec. Never import from runtime application code.

CBC decryption exists only to upgrade historical rows. No legacy writer is shipped.
The AES-GCM/key-provider behavior is frozen with this historical migration.
"""

import base64
import os
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

SECRET_ENVELOPE_PREFIX = "authclaw-secret-v1:"
SECRET_ENVELOPE_V2_PREFIX = "authclaw-secret-v2:"
SUPPORTED_SECRET_PROVIDERS = {"env", "vault", "aws_kms"}


def get_encryption_key() -> bytes:
    """Gets the encryption key and pads/truncates it to 32 bytes (matching Go gateway)"""
    key_str = os.getenv("ENCRYPTION_KEY")
    if not key_str:
        key_str = os.getenv("ENVELOPE_KEY")
    if not key_str:
        if os.getenv("AUTHCLAW_ENV", "").lower() == "production":
            raise RuntimeError("ENVELOPE_KEY is required in production")
        key_str = "authclaw-default-32-byte-key-12"

    key_bytes = key_str.encode("utf-8")
    if len(key_bytes) > 32:
        return key_bytes[:32]
    elif len(key_bytes) < 32:
        return key_bytes + b"\x00" * (32 - len(key_bytes))
    return key_bytes


def _normalize_key_material(key_material: str | bytes) -> bytes:
    key_bytes = (
        key_material
        if isinstance(key_material, bytes)
        else key_material.encode("utf-8")
    )
    if len(key_bytes) > 32:
        return key_bytes[:32]
    if len(key_bytes) < 32:
        return key_bytes + b"\x00" * (32 - len(key_bytes))
    return key_bytes


def get_secret_provider() -> str:
    provider = os.getenv("AUTHCLAW_SECRET_PROVIDER", "env").strip().lower()
    if provider not in SUPPORTED_SECRET_PROVIDERS:
        raise RuntimeError(f"Unsupported AUTHCLAW_SECRET_PROVIDER: {provider}")
    return provider


def get_secret_key_version() -> str:
    return os.getenv("AUTHCLAW_SECRET_KEY_VERSION", "v1").strip() or "v1"


def _env_versioned_key(version: str) -> str:
    suffix = version.upper().replace("-", "_")
    return (
        os.getenv(f"ENVELOPE_KEY_{suffix}")
        or os.getenv("ENVELOPE_KEY")
        or os.getenv("ENCRYPTION_KEY")
        or ""
    )


def _vault_key_material(version: str) -> str:
    addr = os.getenv("VAULT_ADDR", "").rstrip("/")
    token = os.getenv("VAULT_TOKEN", "")
    path = os.getenv(
        "VAULT_SECRET_KEY_PATH", f"secret/data/authclaw/envelope/{version}"
    ).strip("/")
    field = os.getenv("VAULT_SECRET_KEY_FIELD", "key")
    if not addr or not token:
        raise RuntimeError(
            "VAULT_ADDR and VAULT_TOKEN are required for AUTHCLAW_SECRET_PROVIDER=vault"
        )
    if not addr.startswith("https://"):
        raise RuntimeError("VAULT_ADDR must use https")

    response = requests.get(
        f"{addr}/v1/{path}",
        headers={"X-Vault-Token": token},
        timeout=5,
    )
    response.raise_for_status()
    payload = response.json()
    data = payload.get("data", {})
    if isinstance(data.get("data"), dict):
        data = data["data"]
    key_material = data.get(field)
    if not key_material:
        raise RuntimeError(f"Vault secret {path} does not contain field {field}")
    return str(key_material)


def _aws_kms_key_material() -> bytes:
    encrypted_data_key = os.getenv("AWS_KMS_ENCRYPTED_DATA_KEY") or os.getenv(
        "KMS_ENCRYPTED_DATA_KEY"
    )
    if not encrypted_data_key:
        raise RuntimeError(
            "AWS_KMS_ENCRYPTED_DATA_KEY is required for AUTHCLAW_SECRET_PROVIDER=aws_kms"
        )
    try:
        import boto3

        ciphertext = base64.b64decode(encrypted_data_key)
        request = {"CiphertextBlob": ciphertext}
        key_id = os.getenv("AUTHCLAW_AWS_KMS_KEY_ID") or os.getenv("AWS_KMS_KEY_ID")
        if key_id:
            request["KeyId"] = key_id
        response = boto3.client("kms").decrypt(**request)
        return response["Plaintext"]
    except Exception as exc:
        raise RuntimeError(
            f"Failed to decrypt AWS KMS data key: {type(exc).__name__}"
        ) from exc


def get_secret_envelope_key(
    provider: str | None = None, version: str | None = None
) -> bytes:
    provider = provider or get_secret_provider()
    version = version or get_secret_key_version()
    if provider == "env":
        key_material = _env_versioned_key(version)
        if not key_material:
            if os.getenv("AUTHCLAW_ENV", "").lower() == "production":
                raise RuntimeError("ENVELOPE_KEY is required in production")
            key_material = "authclaw-default-32-byte-key-12"
        return _normalize_key_material(key_material)
    if provider == "vault":
        return _normalize_key_material(_vault_key_material(version))
    if provider == "aws_kms":
        return _normalize_key_material(_aws_kms_key_material())
    raise RuntimeError(f"Unsupported secret provider: {provider}")


def decrypt_deterministic(ciphertext_str: str) -> str:
    """Decrypts legacy deterministic redaction/provider ciphertext."""
    key = get_encryption_key()
    try:
        data = base64.b64decode(ciphertext_str)
        if len(data) < 16:
            raise ValueError("Ciphertext too short")
        iv = data[:16]
        ciphertext = data[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # PKCS7 unpadding
        padding_len = padded_plaintext[-1]
        if padding_len < 1 or padding_len > 16:
            raise ValueError("Invalid padding length")

        # Verify padding bytes
        for b in padded_plaintext[-padding_len:]:
            if b != padding_len:
                raise ValueError("Invalid padding content")

        return padded_plaintext[:-padding_len].decode("utf-8")
    except Exception as e:
        raise ValueError(f"Failed to decrypt value: {str(e)}")


def encrypt_secret(plaintext: str) -> str:
    """Encrypts provider/API secrets with randomized, versioned AES-GCM envelope encryption."""
    provider = get_secret_provider()
    version = get_secret_key_version()
    key = get_secret_envelope_key(provider, version)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    payload = base64.b64encode(nonce + ciphertext).decode("utf-8")
    return f"{SECRET_ENVELOPE_V2_PREFIX}{provider}:{version}:{payload}"


def decrypt_secret(ciphertext_str: str) -> str:
    """Decrypts randomized provider/API secrets, falling back for legacy rows."""
    if ciphertext_str.startswith(SECRET_ENVELOPE_V2_PREFIX):
        parts = ciphertext_str[len(SECRET_ENVELOPE_V2_PREFIX) :].split(":", 2)
        if len(parts) != 3:
            raise ValueError("Invalid v2 secret envelope")
        provider, version, payload = parts
        try:
            data = base64.b64decode(payload)
            if len(data) <= 12:
                raise ValueError("Ciphertext too short")
            nonce = data[:12]
            ciphertext = data[12:]
            plaintext = AESGCM(get_secret_envelope_key(provider, version)).decrypt(
                nonce, ciphertext, None
            )
            return plaintext.decode("utf-8")
        except Exception as e:
            raise ValueError(f"Failed to decrypt v2 secret: {str(e)}")

    if not ciphertext_str.startswith(SECRET_ENVELOPE_PREFIX):
        return decrypt_deterministic(ciphertext_str)

    payload = ciphertext_str[len(SECRET_ENVELOPE_PREFIX) :]
    try:
        data = base64.b64decode(payload)
        if len(data) <= 12:
            raise ValueError("Ciphertext too short")
        nonce = data[:12]
        ciphertext = data[12:]
        plaintext = AESGCM(get_encryption_key()).decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")
    except Exception as e:
        raise ValueError(f"Failed to decrypt secret: {str(e)}")

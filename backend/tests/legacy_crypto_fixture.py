"""Synthetic CBC writer exclusively for migration regression fixtures."""

import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from migration_support.secret_crypto_v040 import get_encryption_key


def encrypt_deterministic(plaintext: str) -> str:
    key = get_encryption_key()
    data = plaintext.encode()
    iv = hashlib.sha256(data + key).digest()[:16]
    padding = 16 - len(data) % 16
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    encrypted = (
        encryptor.update(data + bytes([padding]) * padding) + encryptor.finalize()
    )
    return base64.b64encode(iv + encrypted).decode()

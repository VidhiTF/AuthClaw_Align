from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets


PASSWORD_SCHEME = "pbkdf2_sha256"
PASSWORD_MIN_LENGTH = 12
DEFAULT_PASSWORD_ITERATIONS = 210_000


def _b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _iterations() -> int:
    raw = os.getenv("AUTHCLAW_PASSWORD_PBKDF2_ITERATIONS", str(DEFAULT_PASSWORD_ITERATIONS))
    return max(100_000, int(raw))


def validate_password(password: str) -> None:
    if len(password or "") < PASSWORD_MIN_LENGTH:
        raise ValueError(f"Password must be at least {PASSWORD_MIN_LENGTH} characters")


def hash_password(password: str) -> str:
    validate_password(password)
    iterations = _iterations()
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{PASSWORD_SCHEME}${iterations}${_b64e(salt)}${_b64e(digest)}"


def verify_password(password: str, encoded: str | None) -> bool:
    if not password or not encoded:
        return False
    try:
        scheme, raw_iterations, raw_salt, raw_digest = encoded.split("$", 3)
        if scheme != PASSWORD_SCHEME:
            return False
        iterations = int(raw_iterations)
        salt = _b64d(raw_salt)
        expected = _b64d(raw_digest)
    except Exception:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)

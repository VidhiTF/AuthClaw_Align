"""Independent, versioned worker-token HMACs. No legacy verification path."""

import hashlib
import hmac
import os
import re
import secrets

VERSION = re.compile(r"v[1-9][0-9]{0,3}\Z")
TOKEN = re.compile(
    r"ewt\.(v[1-9][0-9]{0,3})\.([A-Za-z0-9_-]{8})\.([A-Za-z0-9_-]{43})\Z"
)


def active_version() -> str:
    version = os.getenv("WORKER_TOKEN_HMAC_ACTIVE_VERSION", "v1")
    if not VERSION.fullmatch(version):
        raise RuntimeError("Invalid worker-token key version")
    return version


def key_for(version: str) -> bytes:
    if not VERSION.fullmatch(version):
        raise ValueError("Invalid worker-token key version")
    key = os.getenv(f"WORKER_TOKEN_HMAC_KEY_{version.upper()}", "").encode()
    if len(key) < 32:
        raise RuntimeError("Worker-token HMAC key is unavailable")
    return key


def token_version(raw: str) -> str:
    match = TOKEN.fullmatch(raw) if isinstance(raw, str) and len(raw) <= 80 else None
    if match is None:
        raise ValueError("Invalid worker token")
    return match[1]


def hash_token(raw: str) -> str:
    version = token_version(raw)
    message = b"authclaw:worker-token:v1\0" + version.encode() + b"\0" + raw.encode()
    return hmac.new(key_for(version), message, hashlib.sha256).hexdigest()


def generate() -> tuple[str, str]:
    version = active_version()
    key_for(version)
    prefix = secrets.token_urlsafe(6)
    return prefix, f"ewt.{version}.{prefix}.{secrets.token_urlsafe(32)}"

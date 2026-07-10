"""Signed audit export and offline verifier."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy.orm import Session

from app.services.audit_store import GENESIS_HASH, compute_integrity_hash, get_postgres_records, standardize_timestamp

EXPORT_FORMAT = "authclaw.audit.export.v1"
SIGNATURE_ALGORITHM = "Ed25519"


@dataclass(frozen=True)
class VerificationResult:
    verified: bool
    signature_valid: bool
    digest_valid: bool
    chain_valid: bool
    record_count: int
    tenant_id: str
    key_id: str
    errors: list[str]
    first_record_id: str
    last_record_id: str
    first_hash: str
    last_hash: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "verified": self.verified,
            "signature_valid": self.signature_valid,
            "digest_valid": self.digest_valid,
            "chain_valid": self.chain_valid,
            "record_count": self.record_count,
            "tenant_id": self.tenant_id,
            "key_id": self.key_id,
            "errors": self.errors,
            "first_record_id": self.first_record_id,
            "last_record_id": self.last_record_id,
            "first_hash": self.first_hash,
            "last_hash": self.last_hash,
        }


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _public_key_b64(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def _private_key_from_env() -> Ed25519PrivateKey:
    pem = os.getenv("AUDIT_EXPORT_SIGNING_PRIVATE_KEY_PEM", "").strip()
    if pem:
        loaded = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise RuntimeError("AUDIT_EXPORT_SIGNING_PRIVATE_KEY_PEM must contain an Ed25519 private key")
        return loaded

    raw_b64 = os.getenv("AUDIT_EXPORT_SIGNING_PRIVATE_KEY", "").strip()
    if raw_b64:
        raw = base64.b64decode(raw_b64)
        if len(raw) != 32:
            raise RuntimeError("AUDIT_EXPORT_SIGNING_PRIVATE_KEY must be base64-encoded 32-byte Ed25519 seed")
        return Ed25519PrivateKey.from_private_bytes(raw)

    if os.getenv("AUTHCLAW_ENV", "").lower() == "production":
        raise RuntimeError("AUDIT_EXPORT_SIGNING_PRIVATE_KEY_PEM or AUDIT_EXPORT_SIGNING_PRIVATE_KEY is required in production")

    seed_material = (
        os.getenv("AUDIT_EXPORT_DEV_SIGNING_SEED")
        or os.getenv("ENVELOPE_KEY")
        or os.getenv("ENCRYPTION_KEY")
        or "authclaw-dev-audit-export-signing-seed"
    )
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed_material.encode("utf-8")).digest())


def signing_key_metadata() -> dict[str, str]:
    private_key = _private_key_from_env()
    public_key = private_key.public_key()
    public_b64 = _public_key_b64(public_key)
    return {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": os.getenv("AUDIT_EXPORT_SIGNING_KEY_ID") or _sha256_hex(base64.b64decode(public_b64))[:16],
        "public_key": public_b64,
        "format": EXPORT_FORMAT,
    }


def _normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(record)
    normalized["timestamp"] = standardize_timestamp(normalized.get("timestamp"))
    normalized["frameworks_affected"] = list(normalized.get("frameworks_affected") or [])
    normalized["prior_hash"] = normalized.get("prior_hash") or GENESIS_HASH
    normalized["integrity_hash"] = normalized.get("integrity_hash") or ""
    return normalized


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _filter_records(
    records: list[dict[str, Any]],
    *,
    action: str | None = None,
    framework: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
) -> list[dict[str, Any]]:
    filtered: list[dict[str, Any]] = []
    for record in records:
        if action and record.get("action") != action:
            continue
        if framework and framework not in set(record.get("frameworks_affected") or []):
            continue
        ts = _parse_timestamp(record.get("timestamp"))
        if start and ts < start:
            continue
        if end and ts > end:
            continue
        filtered.append(record)
    return filtered


def _chain_report(records: list[dict[str, Any]]) -> tuple[bool, list[str]]:
    errors: list[str] = []
    prior_hash = records[0].get("prior_hash") or GENESIS_HASH if records else GENESIS_HASH
    for index, record in enumerate(records):
        record_prior = record.get("prior_hash") or GENESIS_HASH
        expected_integrity = compute_integrity_hash(record, record_prior)
        if record_prior != prior_hash:
            errors.append(
                f"record {index} prior_hash mismatch: expected {prior_hash}, got {record_prior}"
            )
        if record.get("integrity_hash") != expected_integrity:
            errors.append(
                f"record {index} integrity_hash mismatch for {record.get('record_id', '')}"
            )
        prior_hash = record.get("integrity_hash") or expected_integrity
    return not errors, errors


def build_signed_audit_export(
    db: Session,
    *,
    tenant_id: str,
    requested_by: str = "",
    action: str | None = None,
    framework: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
) -> dict[str, Any]:
    all_records = [_normalize_record(record) for record in get_postgres_records(db, tenant_id)]
    records = _filter_records(all_records, action=action, framework=framework, start=start, end=end)
    chain_valid, chain_errors = _chain_report(records)
    generated_at = datetime.now(tz=timezone.utc)
    first = records[0] if records else {}
    last = records[-1] if records else {}
    payload = {
        "export_id": str(uuid.uuid4()),
        "format": EXPORT_FORMAT,
        "generated_at": standardize_timestamp(generated_at),
        "tenant_id": str(tenant_id),
        "requested_by": requested_by,
        "filters": {
            "action": action or "",
            "framework": framework or "",
            "start": standardize_timestamp(start) if start else "",
            "end": standardize_timestamp(end) if end else "",
        },
        "record_count": len(records),
        "first_record_id": first.get("record_id", ""),
        "last_record_id": last.get("record_id", ""),
        "first_hash": first.get("prior_hash", GENESIS_HASH) if records else GENESIS_HASH,
        "last_hash": last.get("integrity_hash", GENESIS_HASH) if records else GENESIS_HASH,
        "chain_valid": chain_valid,
        "chain_errors": chain_errors,
        "records": records,
    }
    payload_bytes = _canonical_bytes(payload)
    private_key = _private_key_from_env()
    public_key = private_key.public_key()
    signature = private_key.sign(payload_bytes)
    public_b64 = _public_key_b64(public_key)
    return {
        "format": EXPORT_FORMAT,
        "payload": payload,
        "digest": {
            "algorithm": "SHA-256",
            "value": _sha256_hex(payload_bytes),
        },
        "signature": {
            "algorithm": SIGNATURE_ALGORITHM,
            "key_id": os.getenv("AUDIT_EXPORT_SIGNING_KEY_ID") or _sha256_hex(base64.b64decode(public_b64))[:16],
            "public_key": public_b64,
            "value": base64.b64encode(signature).decode("ascii"),
            "signed_payload": "payload",
        },
    }


def verify_signed_audit_export(artifact: dict[str, Any]) -> VerificationResult:
    errors: list[str] = []
    if artifact.get("format") != EXPORT_FORMAT:
        errors.append(f"unsupported export format: {artifact.get('format', '')}")

    payload = artifact.get("payload")
    if not isinstance(payload, dict):
        payload = {}
        errors.append("missing payload")

    payload_bytes = _canonical_bytes(payload)
    expected_digest = _sha256_hex(payload_bytes)
    digest = artifact.get("digest") if isinstance(artifact.get("digest"), dict) else {}
    digest_valid = digest.get("algorithm") == "SHA-256" and digest.get("value") == expected_digest
    if not digest_valid:
        errors.append("payload digest mismatch")

    signature = artifact.get("signature") if isinstance(artifact.get("signature"), dict) else {}
    signature_valid = False
    key_id = str(signature.get("key_id", ""))
    try:
        if signature.get("algorithm") != SIGNATURE_ALGORITHM:
            raise ValueError("unsupported signature algorithm")
        public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(str(signature.get("public_key", ""))))
        public_key.verify(base64.b64decode(str(signature.get("value", ""))), payload_bytes)
        signature_valid = True
    except (InvalidSignature, ValueError, TypeError, KeyError, binascii.Error) as exc:
        errors.append(f"signature verification failed: {exc}")

    records = payload.get("records") if isinstance(payload.get("records"), list) else []
    normalized_records = [_normalize_record(record) for record in records if isinstance(record, dict)]
    if len(normalized_records) != len(records):
        errors.append("records must be JSON objects")
    chain_valid, chain_errors = _chain_report(normalized_records)
    errors.extend(chain_errors)

    record_count = int(payload.get("record_count") or 0)
    if record_count != len(normalized_records):
        errors.append(f"record_count mismatch: expected {record_count}, got {len(normalized_records)}")

    first = normalized_records[0] if normalized_records else {}
    last = normalized_records[-1] if normalized_records else {}
    first_record_id = str(first.get("record_id", ""))
    last_record_id = str(last.get("record_id", ""))
    first_hash = str(first.get("prior_hash", GENESIS_HASH)) if normalized_records else GENESIS_HASH
    last_hash = str(last.get("integrity_hash", GENESIS_HASH)) if normalized_records else GENESIS_HASH
    if payload.get("first_record_id", "") != first_record_id:
        errors.append("first_record_id mismatch")
    if payload.get("last_record_id", "") != last_record_id:
        errors.append("last_record_id mismatch")
    if payload.get("first_hash", GENESIS_HASH) != first_hash:
        errors.append("first_hash mismatch")
    if payload.get("last_hash", GENESIS_HASH) != last_hash:
        errors.append("last_hash mismatch")
    if bool(payload.get("chain_valid")) != chain_valid:
        errors.append("payload chain_valid does not match verifier result")

    verified = signature_valid and digest_valid and chain_valid and not errors
    return VerificationResult(
        verified=verified,
        signature_valid=signature_valid,
        digest_valid=digest_valid,
        chain_valid=chain_valid,
        record_count=len(normalized_records),
        tenant_id=str(payload.get("tenant_id", "")),
        key_id=key_id,
        errors=errors,
        first_record_id=first_record_id,
        last_record_id=last_record_id,
        first_hash=first_hash,
        last_hash=last_hash,
    )

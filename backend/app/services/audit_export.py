"""AuthClaw audit export format v2 and offline verification."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from sqlalchemy.orm import Session

from app.services.audit_store import (
    GENESIS_HASH,
    compute_integrity_hash,
    get_postgres_records,
    standardize_timestamp,
)

EXPORT_FORMAT = "authclaw.audit.export.v2"
SIGNATURE_ALGORITHM = "Ed25519"
VERIFIER_VERSION = "2.0.0"


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
        return self.__dict__.copy()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


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
            raise RuntimeError("AUDIT_EXPORT_SIGNING_PRIVATE_KEY_PEM must be Ed25519")
        return loaded

    raw_b64 = os.getenv("AUDIT_EXPORT_SIGNING_PRIVATE_KEY", "").strip()
    if raw_b64:
        raw = base64.b64decode(raw_b64)
        if len(raw) != 32:
            raise RuntimeError("AUDIT_EXPORT_SIGNING_PRIVATE_KEY must encode 32 bytes")
        return Ed25519PrivateKey.from_private_bytes(raw)

    if os.getenv("AUTHCLAW_ENV", "").lower() == "production":
        raise RuntimeError("an audit export signing private key is required in production")
    seed = os.getenv(
        "AUDIT_EXPORT_DEV_SIGNING_SEED",
        "authclaw-dev-audit-export-signing-seed",
    )
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed.encode()).digest())


def signing_key_metadata() -> dict[str, str]:
    public_key = _private_key_from_env().public_key()
    encoded = _public_key_b64(public_key)
    return {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": os.getenv("AUDIT_EXPORT_SIGNING_KEY_ID")
        or _sha256_hex(base64.b64decode(encoded))[:16],
        "public_key": encoded,
        "format": EXPORT_FORMAT,
    }


def trusted_signing_keys_from_env() -> dict[str, Any]:
    """Load the independently configured offline trust registry."""
    configured = os.getenv("AUDIT_EXPORT_TRUSTED_KEYS_JSON", "").strip()
    if configured:
        value = json.loads(configured)
        if not isinstance(value, dict):
            raise RuntimeError("AUDIT_EXPORT_TRUSTED_KEYS_JSON must be an object")
        return value
    if os.getenv("AUTHCLAW_ENV", "").lower() == "production":
        return {}
    metadata = signing_key_metadata()
    return {
        metadata["key_id"]: {
            "public_key": metadata["public_key"],
            "status": "active",
        }
    }


def _trusted_public_key(
    registry: Mapping[str, Any],
    key_id: str,
) -> Ed25519PublicKey:
    entry = registry.get(key_id)
    if entry is None:
        raise ValueError(f"unknown signing key ID: {key_id}")
    if isinstance(entry, str):
        public_key, status = entry, "active"
    elif isinstance(entry, Mapping):
        public_key = str(entry.get("public_key", ""))
        status = str(entry.get("status", "active")).lower()
    else:
        raise ValueError(f"invalid trust entry for key ID: {key_id}")
    if status != "active":
        raise ValueError(f"signing key ID is {status}: {key_id}")
    raw = base64.b64decode(public_key, validate=True)
    if len(raw) != 32:
        raise ValueError("trusted Ed25519 public key must contain 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def _normalize_record(record: dict[str, Any], fallback_sequence: int) -> dict[str, Any]:
    normalized = dict(record)
    normalized["timestamp"] = standardize_timestamp(normalized.get("timestamp"))
    normalized["frameworks_affected"] = sorted(
        set(normalized.get("frameworks_affected") or [])
    )
    normalized["tenant_sequence"] = int(
        normalized.get("tenant_sequence") or fallback_sequence
    )
    normalized["chain_version"] = int(normalized.get("chain_version") or 1)
    normalized["idempotency_key"] = str(normalized.get("idempotency_key") or "")
    normalized["canonical_payload"] = str(normalized.get("canonical_payload") or "")
    normalized["prior_hash"] = normalized.get("prior_hash") or GENESIS_HASH
    normalized["integrity_hash"] = normalized.get("integrity_hash") or ""
    return normalized


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return (
        parsed.replace(tzinfo=timezone.utc)
        if parsed.tzinfo is None
        else parsed.astimezone(timezone.utc)
    )


def _matches(
    record: dict[str, Any],
    *,
    action: str | None,
    framework: str | None,
    start: datetime | None,
    end: datetime | None,
) -> bool:
    timestamp = _parse_timestamp(record["timestamp"])
    return not (
        (action and record.get("action") != action)
        or (framework and framework not in record["frameworks_affected"])
        or (start and timestamp < start)
        or (end and timestamp > end)
    )


def _contiguous_selection(
    records: list[dict[str, Any]],
    *,
    action: str | None,
    framework: str | None,
    start: datetime | None,
    end: datetime | None,
) -> tuple[list[dict[str, Any]], list[str]]:
    selected = [
        index
        for index, record in enumerate(records)
        if _matches(
            record,
            action=action,
            framework=framework,
            start=start,
            end=end,
        )
    ]
    if not selected:
        return [], []
    included = records[selected[0] : selected[-1] + 1]
    selected_ids = [records[index]["record_id"] for index in selected]
    return included, selected_ids


def _chain_report(records: list[dict[str, Any]]) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if not records:
        return True, errors
    prior_hash = records[0]["prior_hash"]
    prior_sequence = records[0]["tenant_sequence"] - 1
    tenant_id = records[0].get("tenant_id")
    seen: set[str] = set()
    for index, record in enumerate(records):
        record_id = str(record.get("record_id", ""))
        if record_id in seen:
            errors.append(f"record {index} duplicates record_id {record_id}")
        seen.add(record_id)
        if record.get("tenant_id") != tenant_id:
            errors.append(f"record {index} injects a different tenant")
        if record["tenant_sequence"] != prior_sequence + 1:
            errors.append(f"record {index} tenant_sequence is not contiguous")
        if record["prior_hash"] != prior_hash:
            errors.append(f"record {index} prior_hash mismatch")
        if compute_integrity_hash(record, record["prior_hash"]) != record["integrity_hash"]:
            errors.append(f"record {index} integrity_hash mismatch for {record_id}")
        prior_sequence = record["tenant_sequence"]
        prior_hash = record["integrity_hash"]
    return not errors, errors


def _verifier_checksum() -> str:
    path = Path(__file__).resolve().parents[2] / "scripts" / "verify_audit_export.py"
    return _sha256_hex(path.read_bytes()) if path.exists() else ""


def _control_links(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    links: dict[str, list[str]] = {}
    for record in records:
        for framework in record["frameworks_affected"]:
            links.setdefault(framework, []).append(record["record_id"])
    return [
        {
            "control_id": framework,
            "record_ids": record_ids,
            "reference": "docs/compliance/GDPR_SOC2_CONTROL_MATRIX.md",
        }
        for framework, record_ids in sorted(links.items())
    ]


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
    all_records = [
        _normalize_record(record, index)
        for index, record in enumerate(get_postgres_records(db, tenant_id), 1)
    ]
    records, selected_ids = _contiguous_selection(
        all_records,
        action=action,
        framework=framework,
        start=start,
        end=end,
    )
    chain_valid, chain_errors = _chain_report(records)
    first, last = (records[0], records[-1]) if records else ({}, {})
    key = signing_key_metadata()
    records_digest = _sha256_hex(_canonical_bytes(records))
    manifest = {
        "format_version": EXPORT_FORMAT,
        "export_id": str(uuid.uuid4()),
        "generated_at": standardize_timestamp(datetime.now(tz=timezone.utc)),
        "tenant_id": str(tenant_id),
        "requested_by": requested_by,
        "sequence_range": {
            "start": first.get("tenant_sequence", 0),
            "end": last.get("tenant_sequence", 0),
        },
        "record_count": len(records),
        "starting_anchor": first.get("prior_hash", GENESIS_HASH),
        "final_chain_root": last.get("integrity_hash", GENESIS_HASH),
        "selection": {
            "filters": {
                "action": action or "",
                "framework": framework or "",
                "start": standardize_timestamp(start) if start else "",
                "end": standardize_timestamp(end) if end else "",
            },
            "selected_record_ids": selected_ids,
            "proof_records_retained": len(records) - len(selected_ids),
        },
        "control_links": _control_links(records),
        "proof": {
            "algorithm": "SHA-256",
            "records_sha256": records_digest,
            "chain_valid_at_export": chain_valid,
            "chain_errors": chain_errors,
        },
        "signing": {
            "trusted_key_id": key["key_id"],
            "algorithm": SIGNATURE_ALGORITHM,
        },
        "verification": {
            "command": (
                "python backend/scripts/verify_audit_export.py "
                "--trusted-keys trusted-keys.json export.json"
            ),
            "verifier_version": VERIFIER_VERSION,
            "verifier_sha256": _verifier_checksum(),
        },
    }
    signed_body = {"manifest": manifest, "records": records}
    body_bytes = _canonical_bytes(signed_body)
    signature = _private_key_from_env().sign(body_bytes)
    return {
        "format": EXPORT_FORMAT,
        **signed_body,
        "digest": {"algorithm": "SHA-256", "value": _sha256_hex(body_bytes)},
        "signature": {
            "algorithm": SIGNATURE_ALGORITHM,
            "key_id": key["key_id"],
            "value": base64.b64encode(signature).decode("ascii"),
        },
    }


def verify_signed_audit_export(
    artifact: dict[str, Any],
    *,
    trusted_keys: Mapping[str, Any] | None = None,
) -> VerificationResult:
    errors: list[str] = []
    if artifact.get("format") != EXPORT_FORMAT:
        errors.append(f"unsupported export format: {artifact.get('format', '')}")
    manifest = artifact.get("manifest")
    records = artifact.get("records")
    if not isinstance(manifest, dict):
        manifest = {}
        errors.append("missing manifest")
    if not isinstance(records, list):
        records = []
        errors.append("missing records")

    signed_body = {"manifest": manifest, "records": records}
    body_bytes = _canonical_bytes(signed_body)
    digest = artifact.get("digest") if isinstance(artifact.get("digest"), dict) else {}
    digest_valid = (
        digest.get("algorithm") == "SHA-256"
        and digest.get("value") == _sha256_hex(body_bytes)
    )
    if not digest_valid:
        errors.append("signed-body digest mismatch")

    signature = artifact.get("signature") if isinstance(artifact.get("signature"), dict) else {}
    key_id = str(signature.get("key_id", ""))
    signature_valid = False
    try:
        if signature.get("algorithm") != SIGNATURE_ALGORITHM:
            raise ValueError("unsupported signature algorithm")
        registry = trusted_keys if trusted_keys is not None else trusted_signing_keys_from_env()
        public_key = _trusted_public_key(registry, key_id)
        public_key.verify(
            base64.b64decode(str(signature.get("value", "")), validate=True),
            body_bytes,
        )
        signature_valid = True
    except (InvalidSignature, ValueError, TypeError, binascii.Error) as exc:
        errors.append(f"signature verification failed: {exc}")
        from app.services.event_backbone import increment_metric

        increment_metric("audit_export_signing_key_failures_total")

    normalized = [
        _normalize_record(record, index)
        for index, record in enumerate(records, 1)
        if isinstance(record, dict)
    ]
    if len(normalized) != len(records):
        errors.append("records must be JSON objects")
    chain_valid, chain_errors = _chain_report(normalized)
    errors.extend(chain_errors)

    proof = manifest.get("proof") if isinstance(manifest.get("proof"), dict) else {}
    if proof.get("records_sha256") != _sha256_hex(_canonical_bytes(records)):
        errors.append("records proof digest mismatch")
    if manifest.get("record_count") != len(normalized):
        errors.append("record_count mismatch")

    first, last = (normalized[0], normalized[-1]) if normalized else ({}, {})
    sequence_range = (
        manifest.get("sequence_range")
        if isinstance(manifest.get("sequence_range"), dict)
        else {}
    )
    if sequence_range.get("start", 0) != first.get("tenant_sequence", 0):
        errors.append("starting tenant sequence mismatch")
    if sequence_range.get("end", 0) != last.get("tenant_sequence", 0):
        errors.append("ending tenant sequence mismatch")
    if manifest.get("starting_anchor", GENESIS_HASH) != first.get(
        "prior_hash", GENESIS_HASH
    ):
        errors.append("starting anchor mismatch")
    if manifest.get("final_chain_root", GENESIS_HASH) != last.get(
        "integrity_hash", GENESIS_HASH
    ):
        errors.append("final chain root mismatch")
    signing = manifest.get("signing") if isinstance(manifest.get("signing"), dict) else {}
    if signing.get("trusted_key_id") != key_id:
        errors.append("manifest signing key ID mismatch")

    verified = signature_valid and digest_valid and chain_valid and not errors
    if not verified:
        from app.services.event_backbone import increment_metric

        increment_metric("audit_export_verification_failures_total")
    return VerificationResult(
        verified=verified,
        signature_valid=signature_valid,
        digest_valid=digest_valid,
        chain_valid=chain_valid,
        record_count=len(normalized),
        tenant_id=str(manifest.get("tenant_id", "")),
        key_id=key_id,
        errors=errors,
        first_record_id=str(first.get("record_id", "")),
        last_record_id=str(last.get("record_id", "")),
        first_hash=str(first.get("prior_hash", GENESIS_HASH)),
        last_hash=str(last.get("integrity_hash", GENESIS_HASH)),
    )

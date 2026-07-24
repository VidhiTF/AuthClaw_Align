"""Generate synthetic ACL-21 export artifacts for review and tamper drills."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services import audit_export


TENANT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def sample_records() -> list[dict]:
    records = []
    prior_hash = "GENESIS"
    for sequence, action in enumerate(("allow", "block", "allow"), 1):
        record_id = f"bbbbbbbb-bbbb-4bbb-8bbb-{sequence:012d}"
        canonical = json.dumps(
            {
                "record_id": record_id,
                "tenant_id": TENANT_ID,
                "tenant_sequence": sequence,
                "chain_version": 2,
                "action": action,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        integrity_hash = hashlib.sha256((canonical + prior_hash).encode()).hexdigest()
        records.append(
            {
                "record_id": record_id,
                "tenant_id": TENANT_ID,
                "tenant_sequence": sequence,
                "idempotency_key": f"sample:{sequence}",
                "chain_version": 2,
                "canonical_payload": canonical,
                "timestamp": datetime(
                    2026,
                    7,
                    20,
                    10,
                    0,
                    sequence,
                    tzinfo=timezone.utc,
                ),
                "actor_id": "",
                "actor_type": "gateway",
                "action": action,
                "policy_id": "",
                "provider": "sample",
                "model": "offline",
                "reason": "Synthetic ACL-21 evidence",
                "prompt_count": 0,
                "request_size": 0,
                "response_status": 200,
                "duration_ms": 1,
                "frameworks_affected": ["SOC2"],
                "execution_trace": '["synthetic"]',
                "request_id": f"sample-{sequence}",
                "prior_hash": prior_hash,
                "integrity_hash": integrity_hash,
            }
        )
        prior_hash = integrity_hash
    return records


def main() -> None:
    os.environ["AUDIT_EXPORT_DEV_SIGNING_SEED"] = "acl21-public-sample-only"
    os.environ.pop("AUDIT_EXPORT_SIGNING_KEY_ID", None)
    records = sample_records()
    audit_export.get_postgres_records = lambda _db, _tenant: records
    artifact = audit_export.build_signed_audit_export(
        object(),
        tenant_id=TENANT_ID,
        requested_by="acl21-evidence-generator",
        action="allow",
    )
    metadata = audit_export.signing_key_metadata()
    trusted_keys = {
        metadata["key_id"]: {
            "public_key": metadata["public_key"],
            "status": "active",
        }
    }
    output = ROOT / "docs" / "compliance" / "evidence"
    output.mkdir(parents=True, exist_ok=True)
    artifact_path = output / "acl21-sample-export.json"
    registry_path = output / "acl21-sample-trusted-keys.json"
    artifact_path.write_text(
        json.dumps(artifact, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    registry_path.write_text(
        json.dumps(trusted_keys, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    verification = audit_export.verify_signed_audit_export(
        artifact,
        trusted_keys=trusted_keys,
    )
    if not verification.verified:
        raise RuntimeError(verification.errors)
    print(f"{artifact_path} sha256={hashlib.sha256(artifact_path.read_bytes()).hexdigest()}")
    print(f"{registry_path} sha256={hashlib.sha256(registry_path.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()

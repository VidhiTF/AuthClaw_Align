"""
hash_chain.py — SHA-256 hash chaining for immutable audit records.

Each audit record includes:
  - prior_hash: the integrity_hash of the immediately preceding record for this tenant
  - integrity_hash: SHA256(canonical_json + prior_hash)

The chain starts with prior_hash = "GENESIS" for the first record per tenant.
"""

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

_BACKEND_PATH = Path(__file__).resolve().parents[1] / "backend"
if _BACKEND_PATH.exists() and str(_BACKEND_PATH) not in sys.path:
    sys.path.insert(0, str(_BACKEND_PATH))

from app.services.audit_utils import (
    canonical_audit_record,
    standardize_timestamp,
    standardize_uuid,
)

GENESIS_HASH = "GENESIS"


def canonical_json(record: dict[str, Any]) -> str:
    """Return a deterministic JSON representation of the record (excluding chain fields)."""
    return json.dumps(canonical_audit_record(record), sort_keys=True, separators=(",", ":"))


def compute_integrity_hash(record: dict[str, Any], prior_hash: str) -> str:
    """Compute SHA-256(canonical_json + prior_hash)."""
    data = canonical_json(record) + prior_hash
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def verify_chain(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Verify the hash chain across a list of records ordered by (tenant_id, timestamp, record_id).

    Returns a list of dicts with fields:
      record_id, tenant_id, valid (bool), expected_hash, actual_hash
    """
    results = []
    prior_by_tenant: dict[str, str] = {}

    for record in records:
        tenant_id = record.get("tenant_id", "")
        prior_hash = prior_by_tenant.get(tenant_id, GENESIS_HASH)

        expected = compute_integrity_hash(record, prior_hash)
        actual = record.get("integrity_hash", "")

        results.append(
            {
                "record_id": record.get("record_id", ""),
                "tenant_id": tenant_id,
                "valid": expected == actual,
                "expected_hash": expected,
                "actual_hash": actual,
            }
        )
        # Advance prior hash regardless of validity (continue checking downstream).
        prior_by_tenant[tenant_id] = actual or expected

    return results

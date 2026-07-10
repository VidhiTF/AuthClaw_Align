"""
tests/test_hash_chain.py — Unit tests for hash_chain.py
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import hashlib
import json

from hash_chain import (
    GENESIS_HASH,
    canonical_json,
    compute_integrity_hash,
    verify_chain,
)


def make_record(record_id: str, tenant_id: str, action: str = "allow") -> dict:
    return {
        "record_id": record_id,
        "tenant_id": tenant_id,
        "timestamp": "2024-01-01T00:00:00Z",
        "actor_id": "gateway",
        "actor_type": "system",
        "action": action,
        "policy_id": "pol-001",
        "provider": "gemini",
        "model": "gemini-2.0-flash-lite",
        "reason": "Allowed",
        "prompt_count": 1,
        "request_size": 100,
        "response_status": 200,
        "duration_ms": 42,
        "frameworks_affected": [],
        "execution_trace": "[]",
    }


class TestCanonicalJson:
    def test_excludes_chain_fields(self):
        record = make_record("r1", "t1")
        record["prior_hash"] = "abc"
        record["integrity_hash"] = "def"
        record["created_at"] = "2024-01-01"
        result = canonical_json(record)
        data = json.loads(result)
        assert "prior_hash" not in data
        assert "integrity_hash" not in data
        assert "created_at" not in data

    def test_is_deterministic(self):
        record = make_record("r1", "t1")
        assert canonical_json(record) == canonical_json(record)

    def test_sorted_keys(self):
        record = make_record("r1", "t1")
        result = canonical_json(record)
        # Keys should be sorted
        data = json.loads(result)
        keys = list(data.keys())
        assert keys == sorted(keys)


class TestComputeIntegrityHash:
    def test_genesis_first_record(self):
        record = make_record("r1", "t1")
        h = compute_integrity_hash(record, GENESIS_HASH)
        expected_input = canonical_json(record) + GENESIS_HASH
        expected = hashlib.sha256(expected_input.encode("utf-8")).hexdigest()
        assert h == expected

    def test_chained_hash(self):
        r1 = make_record("r1", "t1")
        h1 = compute_integrity_hash(r1, GENESIS_HASH)
        r2 = make_record("r2", "t1")
        h2 = compute_integrity_hash(r2, h1)
        # h2 must be different from h1
        assert h1 != h2
        # h2 must incorporate h1
        expected = hashlib.sha256(
            (canonical_json(r2) + h1).encode("utf-8")
        ).hexdigest()
        assert h2 == expected

    def test_different_tenants_produce_different_chains(self):
        r_a = make_record("r1", "tenant-a")
        r_b = make_record("r1", "tenant-b")
        h_a = compute_integrity_hash(r_a, GENESIS_HASH)
        h_b = compute_integrity_hash(r_b, GENESIS_HASH)
        # Different tenant_id in record → different canonical JSON → different hash
        assert h_a != h_b


class TestVerifyChain:
    def _build_chain(self, tenant_id: str, count: int) -> list[dict]:
        """Build a valid hash-chained list of records."""
        records = []
        prior = GENESIS_HASH
        for i in range(count):
            rec = make_record(f"r{i}", tenant_id)
            rec["prior_hash"] = prior
            rec["integrity_hash"] = compute_integrity_hash(rec, prior)
            prior = rec["integrity_hash"]
            records.append(rec)
        return records

    def test_valid_chain(self):
        records = self._build_chain("t1", 5)
        results = verify_chain(records)
        assert all(r["valid"] for r in results), results

    def test_tampered_record(self):
        records = self._build_chain("t1", 3)
        # Tamper with the second record's action field
        records[1]["action"] = "TAMPERED"
        # But keep the original integrity_hash (unchanged)
        results = verify_chain(records)
        # Record at index 1 must be invalid
        assert not results[1]["valid"]

    def test_multi_tenant_chain(self):
        records_a = self._build_chain("tenant-a", 3)
        records_b = self._build_chain("tenant-b", 2)
        # Interleave for realism
        combined = [records_a[0], records_b[0], records_a[1], records_b[1], records_a[2]]
        results = verify_chain(combined)
        assert all(r["valid"] for r in results), results

    def test_empty_chain(self):
        assert verify_chain([]) == []

    def test_single_record_genesis(self):
        rec = make_record("r1", "t1")
        rec["prior_hash"] = GENESIS_HASH
        rec["integrity_hash"] = compute_integrity_hash(rec, GENESIS_HASH)
        results = verify_chain([rec])
        assert results[0]["valid"]

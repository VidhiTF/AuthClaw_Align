"""Local end-to-end audit transport verification harness.

This is a deterministic LOCAL-SIMULATION harness. It reuses the production
consumer validation/idempotency/hash-chain path while simulating transport ack,
retry and redrive semantics for Kafka and SQS FIFO.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import consumer
from consumer import InvalidAuditEvent, RetryableMirrorError, SequenceGapError
from hash_chain import verify_chain
from transport import AuditMessage

TENANT_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
TENANT_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


@dataclass
class Store:
    rows: list[dict[str, Any]] = field(default_factory=list)
    fail_once: set[str] = field(default_factory=set)

    def exists(self, record_id: str) -> bool:
        return any(row["record_id"] == record_id for row in self.rows)

    def tail(self, tenant_id: str) -> tuple[int, str]:
        rows = [row for row in self.rows if row["tenant_id"] == tenant_id]
        if not rows:
            return 0, "GENESIS"
        row = max(rows, key=lambda value: value["tenant_sequence"])
        return int(row["tenant_sequence"]), row["integrity_hash"]

    def insert(self, row: dict[str, Any]) -> bool:
        record_id = row["record_id"]
        if record_id in self.fail_once:
            self.fail_once.remove(record_id)
            raise OSError("LOCAL-SIMULATION transient durable commit failure")
        if self.exists(record_id):
            return False
        self.rows.append(dict(row))
        return True


def _event(tenant_id: str, sequence: int, prefix: str, prior_hash: str = "GENESIS") -> dict[str, Any]:
    record_id = f"{prefix}-{sequence:012d}"
    canonical = {
        "tenant_id": tenant_id,
        "record_id": record_id,
        "tenant_sequence": sequence,
        "chain_version": 2,
        "action": "audit.transport.verify",
    }
    canonical_payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    integrity_hash = hashlib.sha256((canonical_payload + prior_hash).encode("utf-8")).hexdigest()
    return {
        "id": record_id,
        "tenant_id": tenant_id,
        "tenant_sequence": sequence,
        "idempotency_key": f"local-e2e:{record_id}",
        "chain_version": 2,
        "canonical_payload": canonical_payload,
        "timestamp": datetime(2026, 9, 1, 0, sequence, tzinfo=timezone.utc).isoformat(),
        "actor_id": "local-e2e",
        "actor_type": "harness",
        "action": "audit.transport.verify",
        "prior_hash": prior_hash,
        "integrity_hash": integrity_hash,
    }


def _fixture_events() -> list[dict[str, Any]]:
    a1 = _event(TENANT_A, 1, "10000000-0000-4000-8000")
    b1 = _event(TENANT_B, 1, "20000000-0000-4000-8000")
    a2 = _event(TENANT_A, 2, "10000000-0000-4000-8000", a1["integrity_hash"])
    b2 = _event(TENANT_B, 2, "20000000-0000-4000-8000", b1["integrity_hash"])
    transient = _event(TENANT_A, 3, "10000000-0000-4000-8000", a2["integrity_hash"])
    duplicate = dict(b1)
    tampered = _event(TENANT_B, 3, "20000000-0000-4000-8000", b2["integrity_hash"])
    tampered["integrity_hash"] = "0" * 64
    poison = _event(TENANT_A, 4, "10000000-0000-4000-8000", "broken-prior")
    return [a1, b1, a2, b2, duplicate, transient, tampered, poison]


def _install_store(store: Store) -> None:
    consumer.audit_event_exists = lambda _client, record_id: store.exists(record_id)
    consumer.get_tenant_tail = lambda _client, tenant_id: store.tail(tenant_id)
    consumer.insert_audit_event = lambda _client, row: store.insert(row)


def _process_transport(name: str) -> dict[str, Any]:
    store = Store()
    events = _fixture_events()
    transient_id = events[5]["id"]
    store.fail_once.add(transient_id)
    _install_store(store)
    acked: list[str] = []
    retried: list[str] = []
    dlq: list[str] = []
    attempts = defaultdict(int)
    pending = [
        AuditMessage(value=event, offset=index, _position=None, group_id=event["tenant_id"])
        for index, event in enumerate(events)
    ]

    for _round in range(1, 5):
        if not pending:
            break
        next_pending: list[AuditMessage] = []
        failed_groups: set[str] = set()
        for message in pending:
            record_id = str(message.value.get("id", ""))
            group_id = message.group_id
            if group_id in failed_groups:
                next_pending.append(message)
                continue
            attempts[record_id] += 1
            try:
                consumer._process_message(None, message.value)
                acked.append(record_id)
            except (SequenceGapError, RetryableMirrorError):
                retried.append(record_id)
                failed_groups.add(group_id)
                next_pending.append(message)
            except InvalidAuditEvent:
                if name == "kafka" or attempts[record_id] >= 3:
                    dlq.append(record_id)
                    acked.append(record_id)
                else:
                    retried.append(record_id)
                    failed_groups.add(group_id)
                    next_pending.append(message)
        pending = next_pending

    rows_by_tenant: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in store.rows:
        rows_by_tenant[row["tenant_id"]].append(row)
    chain_checks = {
        tenant: all(item["valid"] for item in verify_chain(sorted(rows, key=lambda row: row["tenant_sequence"])))
        for tenant, rows in rows_by_tenant.items()
    }
    return {
        "transport": name,
        "mode": "LOCAL-SIMULATION",
        "input_events": len(events),
        "durable_events": len(store.rows),
        "durable_ids": [row["record_id"] for row in store.rows],
        "per_tenant_sequence": {
            tenant: [row["tenant_sequence"] for row in sorted(rows, key=lambda row: row["tenant_sequence"])]
            for tenant, rows in rows_by_tenant.items()
        },
        "final_chain_heads": {tenant: store.tail(tenant)[1] for tenant in rows_by_tenant},
        "duplicates_collapsed": len([row for row in store.rows if row["record_id"] == events[4]["id"]]) == 1,
        "transient_retried_and_committed": transient_id in retried and store.exists(transient_id),
        "tampered_failed_closed": events[6]["id"] in dlq and not store.exists(events[6]["id"]),
        "poison_reached_dlq": events[7]["id"] in dlq and not store.exists(events[7]["id"]),
        "tenant_failure_isolated": store.exists(events[3]["id"]),
        "acked_ids": acked,
        "retry_ids": retried,
        "dlq_ids": dlq,
        "chain_valid": chain_checks,
    }


def _write_report(path: Path, results: list[dict[str, Any]], commands: list[str]) -> None:
    lines = [
        "# Audit transport local E2E comparison",
        "",
        "Mode: `LOCAL-SIMULATION` — not AWS, production, or release evidence.",
        "",
        "## Commands used",
        "",
        *[f"- `{command}`" for command in commands],
        "",
        "## Results",
        "",
        "| Transport | Input | Durable | Duplicate | Retry | DLQ | Chains |",
        "|---|---:|---:|---|---|---|---|",
    ]
    for result in results:
        lines.append(
            "| {transport} | {input_events} | {durable_events} | {dup} | {retry} | {dlq} | {chains} |".format(
                transport=result["transport"],
                input_events=result["input_events"],
                durable_events=result["durable_events"],
                dup="PASS" if result["duplicates_collapsed"] else "FAIL",
                retry="PASS" if result["transient_retried_and_committed"] else "FAIL",
                dlq="PASS" if result["poison_reached_dlq"] else "FAIL",
                chains="PASS" if all(result["chain_valid"].values()) else "FAIL",
            )
        )
    lines.extend(["", "## Sanitized detail", "", "```json", json.dumps(results, indent=2, sort_keys=True), "```", ""])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--transport", choices=["kafka", "sqs_fifo", "both", "local_fallback"], default="both")
    parser.add_argument("--evidence", default="infra/security/audit-transport-local-e2e.md")
    args = parser.parse_args()
    transports = ["kafka", "sqs_fifo"] if args.transport == "both" else [args.transport]
    if args.transport == "local_fallback":
        transports = ["kafka"]
    results = [_process_transport(transport) for transport in transports]
    commands = [
        "docker compose -p authclaw-audit-e2e -f docker-compose.yml -f docker-compose.audit-e2e.yml --profile audit-e2e up -d kafka kafka-init clickhouse localstack",
        f"python audit_consumer/local_e2e.py --transport {args.transport} --evidence {args.evidence}",
        "docker compose -p authclaw-audit-e2e -f docker-compose.yml -f docker-compose.audit-e2e.yml --profile audit-e2e down --remove-orphans",
    ]
    _write_report(Path(args.evidence), results, commands)
    print(json.dumps(results, indent=2, sort_keys=True))
    return 0 if all(all(result["chain_valid"].values()) and result["poison_reached_dlq"] for result in results) else 1


if __name__ == "__main__":
    sys.exit(main())

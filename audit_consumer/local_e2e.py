"""Local end-to-end audit transport verification harness.

This is a deterministic LOCAL-SIMULATION harness. It reuses the production
consumer validation/idempotency/hash-chain path while simulating transport ack,
retry and redrive semantics for Kafka and SQS FIFO.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import consumer
from consumer import InvalidAuditEvent, RetryableMirrorError, SequenceGapError
from hash_chain import verify_chain
from transport import AuditMessage
from transport import KafkaAuditConsumer, SQSFIFOAuditConsumer

TENANT_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
TENANT_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
TENANT_PREFIX = "70000000-0000-4000-8000"


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
        "timestamp": (datetime(2026, 9, 1, tzinfo=timezone.utc) + timedelta(seconds=sequence)).isoformat(),
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



def _drain_adapter(name: str, adapter: Any, ch_client: Any, expected: int) -> dict[str, Any]:
    acked: list[str] = []
    retried: list[str] = []
    dlq: list[str] = []
    deadline = time.time() + 30
    while time.time() < deadline:
        for batch in adapter.poll(timeout_ms=1000):
            failed_groups: set[str] = set()
            for message in batch:
                record_id = str(message.value.get("id", ""))
                if message.group_id in failed_groups:
                    continue
                try:
                    adapter.begin(message)
                    if message.validation_error is not None:
                        raise message.validation_error
                    consumer._process_message(ch_client, message.value)
                    adapter.ack(message)
                    acked.append(record_id)
                except (SequenceGapError, RetryableMirrorError):
                    adapter.retry(message)
                    retried.append(record_id)
                    failed_groups.add(message.group_id)
                    break
                except InvalidAuditEvent:
                    dlq.append(record_id)
                    adapter.retry(message)
                    failed_groups.add(message.group_id)
                    break
        durable = ch_client.query("SELECT count() FROM authclaw.audit_events").result_rows[0][0]
        if durable >= expected:
            break
    adapter.close()
    rows = [
        {"record_id": row[0], "tenant_id": row[1], "tenant_sequence": row[2], "canonical_payload": row[3], "integrity_hash": row[4]}
        for row in ch_client.query(
            "SELECT toString(record_id), toString(tenant_id), tenant_sequence, canonical_payload, integrity_hash "
            "FROM authclaw.audit_events ORDER BY tenant_id, tenant_sequence"
        ).result_rows
    ]
    rows_by_tenant: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        rows_by_tenant[row["tenant_id"]].append(row)
    return {
        "transport": name,
        "mode": "LOCAL-SIMULATION",
        "adapter_path": "REAL-LOCAL-TRANSPORT",
        "input_events": expected,
        "durable_events": len(rows),
        "durable_ids": [row["record_id"] for row in rows],
        "per_tenant_sequence": {
            tenant: [row["tenant_sequence"] for row in sorted(rows, key=lambda row: row["tenant_sequence"])]
            for tenant, rows in rows_by_tenant.items()
        },
        "final_chain_heads": {tenant: sorted(items, key=lambda row: row["tenant_sequence"])[-1]["integrity_hash"] for tenant, items in rows_by_tenant.items()},
        "acked_ids": acked,
        "retry_ids": retried,
        "dlq_ids": dlq,
        "chain_valid": {
            tenant: all(item["valid"] for item in verify_chain(sorted(rows, key=lambda row: row["tenant_sequence"])))
            for tenant, rows in rows_by_tenant.items()
        },
    }


def _process_real_adapters() -> list[dict[str, Any]]:
    import importlib.util

    repo_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo_root))
    from backend.app.services import audit_transport as backend_transport
    from clickhouse_writer import get_client

    events = _fixture_events()[:4]
    deadline = time.time() + 30
    while True:
        try:
            ch_client = get_client("localhost", 8123, "authclaw", "authclaw", "authclaw")
            break
        except Exception:
            if time.time() >= deadline:
                raise
            time.sleep(1)
    ch_client.command("TRUNCATE TABLE authclaw.audit_events")
    topic = f"audit.e2e.{int(time.time())}"
    os.environ.setdefault("KAFKA_BROKERS", "localhost:9092")
    os.environ["KAFKA_AUDIT_TOPIC"] = topic
    os.environ["KAFKA_TOPICS"] = topic
    os.environ["KAFKA_GROUP_ID"] = f"authclaw-audit-e2e-{int(time.time())}"
    backend_transport.AUDIT_EVENTS_TOPIC = topic
    kafka_pub = backend_transport.KafkaAuditPublisher()
    for event in events:
        kafka_pub.publish(event["tenant_id"], event, event["id"])
    kafka_pub.publish(events[0]["tenant_id"], events[0], events[0]["id"])
    kafka_result = _drain_adapter("kafka", KafkaAuditConsumer(lambda *_args: None), ch_client, len(events))
    kafka_result["duplicates_collapsed"] = kafka_result["durable_events"] == len(events)

    agent_spec = importlib.util.spec_from_file_location(
        "agent_audit_transport", repo_root / "services" / "agent" / "services" / "audit_transport.py"
    )
    agent_transport = importlib.util.module_from_spec(agent_spec)
    assert agent_spec and agent_spec.loader
    sys.modules[agent_spec.name] = agent_transport
    agent_spec.loader.exec_module(agent_transport)
    os.environ["KAFKA_REST_URL"] = "http://localhost:8082"
    legacy_event = {"event_type": "agent.decision", "request_id": "legacy-request", "tenant_id": 7}
    from kafka.admin import KafkaAdminClient, NewTopic

    admin = KafkaAdminClient(bootstrap_servers="localhost:9092")
    try:
        admin.create_topics([NewTopic(agent_transport.AGENT_LEGACY_AUDIT_EVENTS_TOPIC, 1, 1)])
    except Exception:
        pass
    admin.close()
    agent_publisher = agent_transport.make_audit_publisher(timeout=5, required=True)
    deadline = time.time() + 30
    while True:
        try:
            agent_publisher.publish(agent_transport.AGENT_LEGACY_AUDIT_EVENTS_TOPIC, legacy_event)
            break
        except Exception:
            if time.time() >= deadline:
                raise
            time.sleep(1)
    kafka_result["legacy_agent_kafka_shape"] = legacy_event

    import boto3

    os.environ["AUTHCLAW_ALLOW_LOCAL_AWS_ENDPOINTS"] = "true"
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
    os.environ["SQS_ENDPOINT_URL"] = os.getenv("SQS_ENDPOINT_URL", "http://localhost:4566")
    sqs = boto3.client("sqs", region_name=os.environ["AWS_DEFAULT_REGION"], endpoint_url=os.environ["SQS_ENDPOINT_URL"])
    suffix = str(time.time_ns())
    dlq_url = sqs.create_queue(
        QueueName=f"authclaw-audit-e2e-dlq-{suffix}.fifo",
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "false"},
    )["QueueUrl"]
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    queue_name = f"authclaw-audit-e2e-{suffix}.fifo"
    queue_url = sqs.create_queue(
        QueueName=queue_name,
        Attributes={
            "FifoQueue": "true", "ContentBasedDeduplication": "false", "VisibilityTimeout": "10",
            "RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 2}),
        },
    )["QueueUrl"]
    os.environ["SQS_AUDIT_QUEUE_URL"] = queue_url
    ch_client.command("TRUNCATE TABLE authclaw.audit_events")
    sqs_pub = backend_transport.SQSFIFOAuditPublisher()
    for event in events:
        sqs_pub.publish(event["tenant_id"], event, event["id"])
    sqs_pub.publish(events[0]["tenant_id"], events[0], events[0]["id"])
    sqs_result = _drain_adapter("sqs_fifo", SQSFIFOAuditConsumer(lambda *_args: None), ch_client, len(events))
    sqs_result["duplicates_collapsed"] = sqs_result["durable_events"] == len(events)

    poison = _fixture_events()[6]
    sqs_pub.publish(poison["tenant_id"], poison, poison["id"])
    os.environ["SQS_LONG_POLL_SECONDS"] = "1"
    os.environ["SQS_VISIBILITY_TIMEOUT_SECONDS"] = "10"
    poison_consumer = SQSFIFOAuditConsumer(lambda *_args: None)
    receives = 0
    deadline = time.time() + 30
    while receives < 2 and time.time() < deadline:
        for batch in poison_consumer.poll(timeout_ms=1000):
            for message in batch:
                receives += 1
                try:
                    poison_consumer.begin(message)
                    consumer._process_message(ch_client, message.value)
                except InvalidAuditEvent:
                    poison_consumer.retry(message)
    deadline = time.time() + 15
    dlq_messages: list[dict[str, Any]] = []
    while not dlq_messages and time.time() < deadline:
        poison_consumer.poll(timeout_ms=1000)
        dlq_messages = sqs.receive_message(QueueUrl=dlq_url, WaitTimeSeconds=1).get("Messages", [])
    poison_consumer.close()
    sqs_result["transient_retried_and_committed"] = receives >= 2
    sqs_result["poison_reached_dlq"] = bool(dlq_messages)
    return [kafka_result, sqs_result]


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
                dup="PASS" if result.get("duplicates_collapsed") else "N/A",
                retry="PASS" if result.get("transient_retried_and_committed") else "N/A",
                dlq="PASS" if result.get("poison_reached_dlq") else "N/A",
                chains="PASS" if all(result["chain_valid"].values()) else "FAIL",
            )
        )
    lines.extend(["", "## Sanitized detail", "", "```json", json.dumps(results, indent=2, sort_keys=True), "```", ""])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, round((len(ordered) - 1) * pct))
    return round(ordered[index] * 1000, 3)


def _benchmark_events(
    *,
    event_count: int,
    tenant_count: int,
    tenant_skew: float,
    payload_size: int,
) -> list[dict[str, Any]]:
    tails = defaultdict(lambda: "GENESIS")
    sequences = defaultdict(int)
    events = []
    hot_cutoff = max(1, int(event_count * tenant_skew))
    for index in range(event_count):
        tenant_index = 1 if index < hot_cutoff else (index % tenant_count) + 1
        tenant_id = f"{TENANT_PREFIX}-{tenant_index:012d}"
        sequences[tenant_id] += 1
        event = _event(tenant_id, sequences[tenant_id], f"{tenant_index:08d}-0000-4000-8000", tails[tenant_id])
        if payload_size:
            event["padding"] = "x" * max(0, payload_size - len(json.dumps(event, sort_keys=True)))
        tails[tenant_id] = event["integrity_hash"]
        events.append(event)
    return events


def _resource_usage() -> dict[str, Any]:
    names = [
        "authclaw-audit-e2e-kafka",
        "authclaw-audit-e2e-clickhouse",
        "authclaw-audit-e2e-localstack",
    ]
    try:
        output = subprocess.check_output(
            ["docker", "stats", "--no-stream", "--format", "{{json .}}", *names],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        rows = [json.loads(line) for line in output.splitlines() if line.strip()]
        if rows:
            return {"available": True, "source": "docker stats --no-stream", "containers": rows}
    except Exception:  # noqa: BLE001
        pass
    return {
        "available": False,
        "source": "docker stats not collected by harness; use compose command in evidence for container-level sampling",
    }


def _benchmark_transport(name: str, events: list[dict[str, Any]], args: argparse.Namespace) -> dict[str, Any]:
    store = Store()
    _install_store(store)
    publish_latencies: list[float] = []
    e2e_latencies: list[float] = []
    attempts = defaultdict(int)
    acked: list[str] = []
    retried: list[str] = []
    dlq: list[str] = []
    published_at: dict[str, float] = {}
    pending: list[AuditMessage] = []
    transient_every = round(1 / args.transient_failure_rate) if args.transient_failure_rate > 0 else 0
    duplicate_every = round(1 / args.duplicate_delivery_rate) if args.duplicate_delivery_rate > 0 else 0
    start = time.perf_counter()
    sent_messages = 0
    for index, event in enumerate(events, start=1):
        tick = time.perf_counter()
        record_id = event["id"]
        published_at[record_id] = tick
        pending.append(AuditMessage(value=event, offset=index, _position=None, group_id=event["tenant_id"]))
        sent_messages += 1
        if duplicate_every and index % duplicate_every == 0:
            pending.append(AuditMessage(value=dict(event), offset=index, _position=None, group_id=event["tenant_id"]))
            sent_messages += 1
        if transient_every and index % transient_every == 0:
            store.fail_once.add(record_id)
        publish_latencies.append(time.perf_counter() - tick)

    publish_end = time.perf_counter()
    recovery_start = publish_end
    for _round in range(1, 8):
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
                e2e_latencies.append(time.perf_counter() - published_at[record_id])
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
    end = time.perf_counter()

    rows_by_tenant: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in store.rows:
        rows_by_tenant[row["tenant_id"]].append(row)
    ordered = {
        tenant: sorted(rows, key=lambda row: row["tenant_sequence"])
        for tenant, rows in rows_by_tenant.items()
    }
    chain_valid = {
        tenant: all(item["valid"] for item in verify_chain(rows))
        for tenant, rows in ordered.items()
    }
    ordering_valid = all(
        [row["tenant_sequence"] for row in rows] == list(range(1, len(rows) + 1))
        for rows in ordered.values()
    )
    durable_ids = {row["record_id"] for row in store.rows}
    duplicate_count = sent_messages - len(events)
    return {
        "transport": name,
        "mode": "LOCAL-SIMULATION",
        "event_size_bytes": len(json.dumps(events[0], sort_keys=True).encode("utf-8")) if events else 0,
        "published_events": len(events),
        "durable_events": len(store.rows),
        "publish_throughput_eps": round(len(events) / max(publish_end - start, 0.000001), 2),
        "consumer_throughput_eps": round(len(store.rows) / max(end - publish_end, 0.000001), 2),
        "publish_latency_ms": {"p50": _percentile(publish_latencies, 0.50), "p95": _percentile(publish_latencies, 0.95), "p99": _percentile(publish_latencies, 0.99)},
        "end_to_end_latency_ms": {"p50": _percentile(e2e_latencies, 0.50), "p95": _percentile(e2e_latencies, 0.95), "p99": _percentile(e2e_latencies, 0.99)},
        "backlog_drain_recovery_ms": round((end - recovery_start) * 1000, 3),
        "retry_count": len(retried),
        "duplicate_delivery_count": duplicate_count,
        "failure_count": len(dlq),
        "ordering_violations": 0 if ordering_valid else 1,
        "hash_chain_violations": sum(0 if valid else 1 for valid in chain_valid.values()),
        "missing_events": len(set(event["id"] for event in events) - durable_ids),
        "unexplained_duplicates": max(0, len(store.rows) - len(durable_ids)),
        "final_chain_heads": {tenant: rows[-1]["integrity_hash"] for tenant, rows in ordered.items() if rows},
        "per_tenant_sequence": {tenant: [row["tenant_sequence"] for row in rows] for tenant, rows in ordered.items()},
        "container_resources": _resource_usage(),
        "integrity_passed": ordering_valid and all(chain_valid.values()) and not pending and len(store.rows) == len(set(event["id"] for event in events)),
    }


def _write_benchmark(markdown_path: Path, json_path: Path, payload: dict[str, Any]) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    lines = [
        "# Audit transport local benchmark",
        "",
        "Mode: `LOCAL-SIMULATION`.",
        "",
        "These LocalStack/Redpanda/local harness results cannot determine AWS cost, production capacity, or the final transport decision.",
        "",
        f"Commit: `{payload['commit']}`",
        f"Started: `{payload['started_at']}`",
        f"Completed: `{payload['completed_at']}`",
        "",
        "## Configuration",
        "",
        "```json",
        json.dumps(payload["configuration"], indent=2, sort_keys=True),
        "```",
        "",
        "## Results",
        "",
        "| Transport | Published | Durable | Publish eps | Consumer eps | E2E p95 ms | Retries | Duplicates | Failures | Integrity |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for result in payload["results"]:
        lines.append(
            f"| {result['transport']} | {result['published_events']} | {result['durable_events']} | "
            f"{result['publish_throughput_eps']} | {result['consumer_throughput_eps']} | "
            f"{result['end_to_end_latency_ms']['p95']} | {result['retry_count']} | "
            f"{result['duplicate_delivery_count']} | {result['failure_count']} | "
            f"{'PASS' if result['integrity_passed'] else 'FAIL'} |"
        )
    lines.extend(["", "## Commands used", "", *[f"- `{command}`" for command in payload["commands"]], ""])
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.write_text("\n".join(lines), encoding="utf-8")


def _run_benchmark(args: argparse.Namespace) -> int:
    started = datetime.now(tz=timezone.utc).isoformat()
    events = _benchmark_events(
        event_count=args.event_count,
        tenant_count=args.tenant_count,
        tenant_skew=args.tenant_skew,
        payload_size=args.payload_size,
    )
    results = [_benchmark_transport(transport, events, args) for transport in ["kafka", "sqs_fifo"]]
    completed = datetime.now(tz=timezone.utc).isoformat()
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:  # noqa: BLE001
        commit = "unknown"
    payload = {
        "mode": "LOCAL-SIMULATION",
        "started_at": started,
        "completed_at": completed,
        "commit": commit,
        "environment": {
            "python": sys.version.split()[0],
            "platform": sys.platform,
        },
        "configuration": {
            "event_count": args.event_count,
            "tenant_count": args.tenant_count,
            "tenant_skew": args.tenant_skew,
            "payload_size": args.payload_size,
            "producer_concurrency": args.producer_concurrency,
            "consumer_concurrency": args.consumer_concurrency,
            "transient_failure_rate": args.transient_failure_rate,
            "duplicate_delivery_rate": args.duplicate_delivery_rate,
        },
        "commands": [
            "docker compose -p authclaw-audit-e2e -f docker-compose.yml -f docker-compose.audit-e2e.yml --profile audit-e2e up -d kafka kafka-init clickhouse localstack",
            "python audit_consumer/local_e2e.py --benchmark --transport both",
            "docker compose -p authclaw-audit-e2e -f docker-compose.yml -f docker-compose.audit-e2e.yml --profile audit-e2e down --remove-orphans",
        ],
        "results": results,
    }
    _write_benchmark(Path(args.benchmark_markdown), Path(args.benchmark_json), payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if all(result["integrity_passed"] for result in results) else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--transport", choices=["kafka", "sqs_fifo", "both", "local_fallback"], default="both")
    parser.add_argument("--evidence", default="infra/security/audit-transport-local-e2e.md")
    parser.add_argument("--benchmark", action="store_true")
    parser.add_argument("--real-adapters", action="store_true")
    parser.add_argument("--benchmark-json", default="infra/security/audit-transport-local-benchmark.json")
    parser.add_argument("--benchmark-markdown", default="infra/security/audit-transport-local-benchmark.md")
    parser.add_argument("--event-count", type=int, default=200)
    parser.add_argument("--tenant-count", type=int, default=4)
    parser.add_argument("--tenant-skew", type=float, default=0.5)
    parser.add_argument("--payload-size", type=int, default=512)
    parser.add_argument("--producer-concurrency", type=int, default=2)
    parser.add_argument("--consumer-concurrency", type=int, default=2)
    parser.add_argument("--transient-failure-rate", type=float, default=0.02)
    parser.add_argument("--duplicate-delivery-rate", type=float, default=0.05)
    args = parser.parse_args()
    if args.benchmark:
        return _run_benchmark(args)
    if args.real_adapters:
        results = _process_real_adapters()
    else:
        transports = ["kafka", "sqs_fifo"] if args.transport == "both" else [args.transport]
        if args.transport == "local_fallback":
            transports = ["kafka"]
        results = [_process_transport(transport) for transport in transports]
    commands = [
        "docker compose -p authclaw-audit-e2e -f docker-compose.yml -f docker-compose.audit-e2e.yml --profile audit-e2e up -d kafka kafka-init clickhouse localstack",
        f"python audit_consumer/local_e2e.py {'--real-adapters' if args.real_adapters else f'--transport {args.transport}'} --evidence {args.evidence}",
        "docker compose -p authclaw-audit-e2e -f docker-compose.yml -f docker-compose.audit-e2e.yml --profile audit-e2e down --remove-orphans",
    ]
    _write_report(Path(args.evidence), results, commands)
    print(json.dumps(results, indent=2, sort_keys=True))
    return 0 if all(
        all(result["chain_valid"].values())
        and result["durable_events"] == result["input_events"]
        and (result.get("adapter_path") or result.get("poison_reached_dlq"))
        and (result["transport"] != "sqs_fifo" or result.get("poison_reached_dlq"))
        for result in results
    ) else 1


if __name__ == "__main__":
    sys.exit(main())

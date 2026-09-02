import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import local_e2e  # noqa: E402


def test_local_e2e_kafka_and_sqs_are_equivalent(tmp_path):
    evidence = tmp_path / "audit-e2e.md"
    results = [local_e2e._process_transport("kafka"), local_e2e._process_transport("sqs_fifo")]

    local_e2e._write_report(evidence, results, ["LOCAL-SIMULATION"])
    detail = json.loads(evidence.read_text().split("```json\n", 1)[1].split("\n```", 1)[0])

    assert detail[0]["durable_ids"] == detail[1]["durable_ids"]
    assert detail[0]["final_chain_heads"] == detail[1]["final_chain_heads"]
    assert all(result["duplicates_collapsed"] for result in detail)
    assert all(result["transient_retried_and_committed"] for result in detail)
    assert all(result["poison_reached_dlq"] for result in detail)
    assert all(result["tenant_failure_isolated"] for result in detail)


def test_local_e2e_benchmark_verifies_integrity():
    class Args:
        transient_failure_rate = 0.1
        duplicate_delivery_rate = 0.2

    events = local_e2e._benchmark_events(
        event_count=20,
        tenant_count=2,
        tenant_skew=0.5,
        payload_size=256,
    )

    results = [local_e2e._benchmark_transport("kafka", events, Args()), local_e2e._benchmark_transport("sqs_fifo", events, Args())]

    assert results[0]["durable_events"] == results[1]["durable_events"] == 20
    assert results[0]["final_chain_heads"] == results[1]["final_chain_heads"]
    assert all(result["integrity_passed"] for result in results)
    assert all(result["duplicate_delivery_count"] == 4 for result in results)

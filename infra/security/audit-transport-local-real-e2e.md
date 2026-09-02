# Audit transport local E2E comparison

Mode: `LOCAL-SIMULATION` — not AWS, production, or release evidence.

## Commands used

- `docker compose -p authclaw-audit-e2e -f docker-compose.yml -f docker-compose.audit-e2e.yml --profile audit-e2e up -d kafka kafka-init clickhouse localstack`
- `python audit_consumer/local_e2e.py --real-adapters --evidence infra/security/audit-transport-local-real-e2e.md`
- `docker compose -p authclaw-audit-e2e -f docker-compose.yml -f docker-compose.audit-e2e.yml --profile audit-e2e down --remove-orphans`

## Results

| Transport | Input | Durable | Duplicate | Retry | DLQ | Chains |
|---|---:|---:|---|---|---|---|
| kafka | 4 | 4 | PASS | N/A | N/A | PASS |
| sqs_fifo | 5 | 5 | PASS | PASS | PASS | PASS |

## Sanitized detail

```json
[
  {
    "acked_ids": [
      "10000000-0000-4000-8000-000000000001",
      "20000000-0000-4000-8000-000000000001",
      "10000000-0000-4000-8000-000000000002",
      "20000000-0000-4000-8000-000000000002",
      "10000000-0000-4000-8000-000000000001"
    ],
    "adapter_path": "REAL-LOCAL-TRANSPORT",
    "chain_valid": {
      "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa": true,
      "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb": true
    },
    "dlq_ids": [],
    "duplicates_collapsed": true,
    "durable_events": 4,
    "durable_ids": [
      "10000000-0000-4000-8000-000000000001",
      "10000000-0000-4000-8000-000000000002",
      "20000000-0000-4000-8000-000000000001",
      "20000000-0000-4000-8000-000000000002"
    ],
    "final_chain_heads": {
      "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa": "43aee6ea009f1ac62932f1cd821b6e6cdcf18c132be4df4edfcabef510d40a34",
      "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb": "747f12e3c57659faa582e14ae7f4bd17f5a0739ef6eba3f435ae6674abfbf272"
    },
    "input_events": 4,
    "legacy_agent_kafka_shape": {
      "event_type": "agent.decision",
      "request_id": "legacy-request",
      "tenant_id": 7
    },
    "mode": "LOCAL-SIMULATION",
    "per_tenant_sequence": {
      "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa": [
        1,
        2
      ],
      "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb": [
        1,
        2
      ]
    },
    "retry_ids": [],
    "transport": "kafka"
  },
  {
    "acked_ids": [
      "10000000-0000-4000-8000-000000000001",
      "10000000-0000-4000-8000-000000000002",
      "20000000-0000-4000-8000-000000000001",
      "20000000-0000-4000-8000-000000000002",
      "10000000-0000-4000-8000-000000000003"
    ],
    "adapter_path": "REAL-LOCAL-TRANSPORT",
    "chain_valid": {
      "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa": true,
      "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb": true
    },
    "dlq_ids": [],
    "duplicates_collapsed": true,
    "durable_events": 5,
    "durable_ids": [
      "10000000-0000-4000-8000-000000000001",
      "10000000-0000-4000-8000-000000000002",
      "10000000-0000-4000-8000-000000000003",
      "20000000-0000-4000-8000-000000000001",
      "20000000-0000-4000-8000-000000000002"
    ],
    "final_chain_heads": {
      "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa": "45b5e6d6ac787fad050b3d615ec3dfdcbdccf63d368e366a20965151cbfda43e",
      "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb": "747f12e3c57659faa582e14ae7f4bd17f5a0739ef6eba3f435ae6674abfbf272"
    },
    "input_events": 5,
    "mode": "LOCAL-SIMULATION",
    "per_tenant_sequence": {
      "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa": [
        1,
        2,
        3
      ],
      "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb": [
        1,
        2
      ]
    },
    "poison_reached_dlq": true,
    "retry_ids": [
      "10000000-0000-4000-8000-000000000003"
    ],
    "transient_acknowledged": true,
    "transient_durable_id": "10000000-0000-4000-8000-000000000003",
    "transient_receive_count": 2,
    "transient_retried_and_committed": true,
    "transport": "sqs_fifo"
  }
]
```

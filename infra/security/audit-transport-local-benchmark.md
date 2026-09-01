# Audit transport local benchmark

Mode: `LOCAL-SIMULATION`.

These LocalStack/Redpanda/local harness results cannot determine AWS cost, production capacity, or the final transport decision.

Commit: `d7c62cfe0b2d32cff25dc167c76ac21377fbb841`
Started: `2026-09-01T10:23:23.484879+00:00`
Completed: `2026-09-01T10:23:27.706477+00:00`

## Configuration

```json
{
  "consumer_concurrency": 2,
  "duplicate_delivery_rate": 0.05,
  "event_count": 200,
  "payload_size": 512,
  "producer_concurrency": 2,
  "tenant_count": 4,
  "tenant_skew": 0.5,
  "transient_failure_rate": 0.02
}
```

## Results

| Transport | Published | Durable | Publish eps | Consumer eps | E2E p95 ms | Retries | Duplicates | Failures | Integrity |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| kafka | 200 | 200 | 721240.79 | 4450.49 | 42.647 | 4 | 10 | 0 | PASS |
| sqs_fifo | 200 | 200 | 674308.46 | 4971.34 | 38.338 | 4 | 10 | 0 | PASS |

## Commands used

- `docker compose -p authclaw-audit-e2e -f docker-compose.yml -f docker-compose.audit-e2e.yml --profile audit-e2e up -d kafka kafka-init clickhouse localstack`
- `python audit_consumer/local_e2e.py --benchmark --transport both`
- `docker compose -p authclaw-audit-e2e -f docker-compose.yml -f docker-compose.audit-e2e.yml --profile audit-e2e down --remove-orphans`

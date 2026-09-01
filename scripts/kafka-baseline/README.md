# Kafka audit stream baseline kit

This kit supports **Task 1**: establish a production-ready baseline for AuthClaw’s
current Kafka audit stream before any transport migration.

## Scope covered

- Producers and consumers:
  - Gateway Kafka producer (`gateway/kafka.go`)
  - Backend outbox publisher (`backend/app/services/event_backbone.py`)
  - Agent event pipeline (`services/agent/services/event_pipeline.py`)
  - Audit consumer and DLQ path (`audit_consumer/consumer.py`)
- Topic and policy inventory:
  - `gateway.traffic`
  - `audit.events`
  - `audit.deadletter`
- Replay strategy checkpoints:
  - PostgreSQL outbox + `audit_log_metadata` replay
  - Consumer reset behavior (`auto_offset_reset=earliest`, offset commit points)
  - DLQ volume and retry handling
- Cost and operational signals:
  - Infra shape (cluster size, storage, cost by service)
  - NAT/endpoint and private connectivity impact when using MSK/SQS/Kinesis alternatives

## Security posture of the collection scripts

- The scripts **never write raw payloads** to output files.
- Tenant IDs and event IDs are handled as opaque values for aggregation.
- Raw outputs are timestamped and include endpoint/env metadata in a redacted snapshot.
- If AWS is used, all commands are read-only and should run under least-privilege
  credentials.

## Requirements

- Bash shell
- `bash`, `awk`, `sed`, `tr`, `date`, `jq`, `curl`
- Kafka CLI (`rpk` or `kafka-topics.sh` + `kafka-consumer-groups.sh`)
- Optional for message-size sampling: `kcat`
- Optional for DB/replay checks: `psql`
- Optional for AWS cost/operations: `aws` CLI + `jq`

## Quick start (local dry-run)

```bash
AUTHCLAW_BASELINE_ENV=local \
KAFKA_BOOTSTRAP=localhost:9092 \
METRICS_WINDOW_SECONDS=180 \
./scripts/kafka-baseline/collect_kafka_audit_baseline.sh
```

The command prints output path and creates a timestamped evidence directory.

## Live environment execution checklist

- Set `KAFKA_BOOTSTRAP` to the target bootstrap endpoint.
- Set service metrics URLs for live counters:
  - `GATEWAY_METRICS_URL` (gateway `/metrics`)
  - `BACKEND_METRICS_URL` (backend `/metrics`)
  - `AUDIT_CONSUMER_METRICS_URL` (audit-consumer `/metrics`)
- Use read-only DB credentials for `DATABASE_URL` when collecting replay and backlog evidence.
- Optionally set `AWS_REGION` and `AWS_MSK_CLUSTER_ARN` for AWS cost signals.
- Ensure the sampling window covers a representative tenant and traffic pattern.

## Output and report

- All outputs are written under `artifacts/kafka-baseline/<UTC timestamp>/`.
- `kafka_baseline_result_template.md` is the expected evidence sheet for ADR inputs.
- Raw command output files are preserved for rerun and audit.

## Reproducibility

All collection inputs are stored in:
- `metadata.json`
- `collection.env`
- `metrics_window.txt`

No command can mutate Kafka state; all commands are observations or read-only queries.


# Runbook: Kafka Audit Stream Baseline (Task 1)

## Objective

Create a production-ready, repeatable Kafka baseline for AuthClaw’s audit stream before any
transport migration decision. This is the gating evidence for ADRs comparing Kafka vs SQS FIFO vs Kinesis.

## Files in scope

- `scripts/kafka-baseline/collect_kafka_audit_baseline.sh`
- `scripts/kafka-baseline/README.md`
- `infra/observability/kafka_baseline_prometheus_dashboard.json`
- `infra/observability/acl21-alerts.yml`

## Pre-run controls

- Confirm no migration or transport edits are needed before this run.
- Confirm run window represents **real load** (prefer 60–120 min, or a representative
  traffic cycle). Label as `representative_load: true`.
- Ensure no secrets are printed by adding redacted env files and non-admin credentials.
- Use least privilege read-only access for PostgreSQL, ClickHouse, and Kafka management.

## Executable evidence workflow

1. Choose output folder:
   - `export AUTHCLAW_BASELINE_ENV=production`
   - `export KAFKA_BOOTSTRAP=...`
   - optional: `export GATEWAY_METRICS_URL=http://...`
2. Run:
   - `./scripts/kafka-baseline/collect_kafka_audit_baseline.sh`
3. Validate generated artifacts exist and include:
   - `metadata.json`
   - `collection.env`
   - `consumer_groups.txt`
   - `topic_baseline_raw_*.txt`
   - `message_profile_*.json`
   - `gateway_metrics.txt`, `backend_metrics.txt`, `audit_consumer_metrics.txt` (if endpoints available)
   - `kafka_baseline_result_template.md`
4. Fill the generated template with interpreted values from:
   - topic retention and partition replication
   - message sample average/max size
   - producer/consumer counters and lag
   - outbox backlog and replay evidence
   - DLQ/retry indicators
   - cost and overhead snapshots.
5. Tag outputs as:
   - environment (`staging`/`production`)
   - representative load window
   - operator and command versions.

## KPI mapping

### Peak and average events/sec

- **Primary signals**
  - `backend_audit_outbox_published_total` delta over window
  - `authclaw_gateway_audit_outbox_writes_total` delta over window
  - consumer metrics (`audit_consumer_messages_seen_total`)
- **Derived signals**
  - p99 lag and backlogged rows under traffic spikes.

### Average and max event size

- `scripts/kafka-baseline/collect_kafka_audit_baseline.sh` writes:
  - `message_profile_<topic>.json` for average and max bytes from sample messages.
- Keep sample window and limit in metadata.

### Partitions, replication, consumer groups, consumer lag

- Kafka metadata from:
  - `kafka_cluster_inventory.txt`
  - `consumer_groups.txt`
- Confirm producer partitioning and replay behavior:
  - `gateway.kafka.go`: `Key = tenant_id` and DLQ topic key `tenant_id`.

### Retention and replay usage

- Kafka topic retention config: `topic_baseline_raw_<topic>.txt`
- Replay feasibility:
  - PostgreSQL authoritative chain
  - `audit_log_metadata` + `audit_outbox` relationship
  - consumer auto-offset semantics from `audit_consumer.py`
  - no production workload dependence on event bus retained-history replay should be explicitly marked.

### DLQ/retry and failure volume

- DLQ volume:
  - `audit_consumer_dlq_published_total` and `audit_consumer_dlq_publish_failures_total` from consumer counters
  - `backend_audit_publish_failures_total`, `audit_consumer_clickhouse_insert_failures_total`
- Retry behavior from database checkpoints / replay tables.

### Infrastructure and operational overhead

- Kafka cluster sizing and type from AWS `msk` descriptors (or equivalent source).
- Operational overhead from:
  - `aws ce` cost query for MSK and NAT/public egress
  - VPC endpoint availability and private path audit
  - broker metrics for throughput/error/throughput-cost correlation.

## Dashboard

- Import `infra/observability/kafka_baseline_prometheus_dashboard.json` in your
  Grafana stack for a prewired view of:
  - audit publish/commit/error counters
  - outbox backlog/age
  - consumer lag
  - DLQ throughput
  - gateway/backoff and verification counters.

## Do not fabricate

- Values not captured live must be labeled `LIVE-MISSING`.
- If tooling is unavailable (`kcat`, `psql`, `aws`, or metrics endpoint absent), mark
  the corresponding KPI as blocked and record the reason in the final report.
- Do not use stale values from local development as production baseline values.

## Definition of done

- Reproducible command set checked into code.
- Evidence generated with timestamps, environment detail, and tool/version fingerprint.
- All required KPIs in the template either populated with measured data or explicitly
  blocked with blocker reason.
- Findings directly cited in ADR input for Kafka vs Kinesis vs SQS FIFO.


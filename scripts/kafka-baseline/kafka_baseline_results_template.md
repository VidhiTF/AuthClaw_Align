# Kafka audit baseline evidence template

## Baseline run metadata

- run_id:
- environment:
- region/account:
- sample window:
- bootstrap endpoint:
- topics:
- metrics window (sec):
- representative-load justification:
- collector version:
- collected_at_utc_start:
- collected_at_utc_end:

## Evidence sources used

- `metadata.json`
- `collection.env`
- `kafka_cluster_inventory.txt`
- `topic_baseline_raw_<topic>.txt`
- `consumer_groups.txt`
- `message_profile_<topic>.json`
- `<service>_metrics.txt`
- `replay_and_dedup_sql.md`
- `retention_and_replay_signals.txt`
- `aws_cost_and_ops.md`

## KPI results

1. Peak events/sec:
2. Average events/sec:
3. Average event size:
4. Maximum event size:
5. Traffic per tenant:
6. Partitions:
7. Replication factor:
8. Producer error rate:
9. Consumer throughput:
10. Consumer lag:
11. Required retention period:
12. Replay usage:
13. Ordering requirement (tenant/global):
14. DLQ/retry volumes:
15. Infrastructure & operational overhead:
16. Cost proxy / benchmark window:

## Methodology notes

- Are metrics from metrics endpoints direct read from services?
- Were topic-level samples collected from broker messages or only broker metadata?
- Which tooling was unavailable (if any)?
- What is the production/live evidence scope and any blackout periods?

## ADR impact mapping

- Transport decision inputs supported:
  - Ordered per-tenant sequence verified?
  - Replay dependency proven absent or present?
  - Throughput/size limits that exceed SQS FIFO limits?
  - Consumer group lag and restart cost characteristics?
  - Cost and operational overhead comparisons prepared?
- Recommendation:

## Blockers / follow-ups

- Unmeasured KPI:
- Root cause for missing data:
- Required re-run actions:


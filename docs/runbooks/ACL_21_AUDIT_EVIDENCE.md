# ACL-21 audit evidence operator runbook

## Signals

Alert on sustained non-zero rates or gauges for:

- append failures and idempotency collisions;
- outbox backlog and oldest-row age;
- Kafka publish failure and consumer lag;
- tenant sequence gaps and DLQ publications;
- ClickHouse insert failures and mirror drift;
- export verification and signing-key failures.

Suggested initial thresholds are: append or signing failure `> 0` for 5 minutes,
oldest outbox age `> 300s`, any sequence gap `> 60s`, mirror drift `> 0`, and
consumer lag above the tenant traffic SLO for 10 minutes.

## Recovery

1. PostgreSQL outage: stop accepting fail-open evidence writes, restore
   PostgreSQL, then confirm new appends and outbox creation.
2. Kafka outage: leave `audit_outbox.published_at` null. Restore Kafka and
   trigger any gateway/backend audit request or run the application outbox
   drainer. Confirm publication in `tenant_sequence` order.
3. ClickHouse outage: restore ClickHouse. The consumer must retry without
   committing failed offsets. If the mirror was lost, call the PostgreSQL to
   ClickHouse replay endpoint or `replay_postgres_to_clickhouse`.
4. Sequence gap: compare pending outbox rows with PostgreSQL for the tenant.
   Publish the missing lower sequence first. Do not send a gap directly to DLQ.
5. Key failure: remove revoked keys from signing, keep them in the verifier
   registry with `status: revoked`, activate the replacement key, and retain
   old active keys only for their approved verification period.

Useful checks:

```sql
SELECT tenant_id, count(*) AS backlog, min(created_at) AS oldest
FROM audit_outbox WHERE published_at IS NULL GROUP BY tenant_id;

SELECT tenant_id, min(tenant_sequence), max(tenant_sequence), count(*)
FROM audit_log_metadata GROUP BY tenant_id;
```

## Additive rollback

Revert application writers and consumers without downgrading migration 028.
Do not delete audit/outbox rows, drop evidence columns, disable the immutable
trigger, renumber tenant sequences, or restore ClickHouse into PostgreSQL.
After rollback, record the deployment boundary and verify the final ACL-21
chain root before accepting evidence from another writer.

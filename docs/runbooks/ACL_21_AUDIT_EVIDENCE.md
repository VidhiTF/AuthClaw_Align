# ACL-21 audit evidence operator runbook

## Signals

Alert on sustained non-zero rates or gauges for:

- append failures and idempotency collisions;
- outbox backlog and oldest-row age;
- local recovery backlog, oldest-record age, replay failures, and storage scan failures;
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
3. Local recovery: deployed gateways use the encrypted, backed-up EFS access
   point at `/var/lib/authclaw-gateway`, reachable through a gateway-only security
   group; keep any custom `AUDIT_OUTBOX_PATH` on
   equivalently durable shared storage. The gateway writes immutable, atomic
   `*.ready` files, so gateway processes cannot overwrite one another. After
   PostgreSQL returns, an authenticated request schedules a bounded background
   replay for its tenant through the canonical idempotent append path. Recovery
   runs one tenant at a time with a 64-tenant admission bound; saturation applies
   request backpressure until a slot is free. Each 100-record turn automatically
   requeues remaining work. Partial progress is atomically checkpointed
   so the next attempt starts at the first uncommitted record. On restart,
   complete stale temp files and a previously claimed legacy file are resumed; corrupt
   temp/ready files remain visible and raise the scan-failure alert. The former
   single NDJSON file is atomically claimed and deterministically split for the
   same replay path. Never delete or edit recovery files manually. A tenant with
   no new traffic needs an authenticated request to trigger replay; if backlog
   age remains above five minutes, restore database/storage access and issue an
   authenticated audited gateway request for that tenant, then verify both backlog gauges return
   to zero.
4. ClickHouse outage: restore ClickHouse. The consumer must retry without
   committing failed offsets. If the mirror was lost, call the PostgreSQL to
   ClickHouse replay endpoint or `replay_postgres_to_clickhouse`.
   Compose runs `infra/clickhouse/migrate.sh` before the backend and consumer.
   Re-running it is safe. An ACL-21 schema upgrade preserves the old mirror as
   `audit_events_acl21_legacy`, creates a clean current table, and requires a
   PostgreSQL-to-ClickHouse replay. Keep the legacy table until the consistency
   endpoint confirms matching counts, hashes, and sequences.
5. Sequence gap: compare pending outbox rows with PostgreSQL for the tenant.
   Publish the missing lower sequence first. Do not send a gap directly to DLQ.
6. Key failure: remove revoked keys from signing, keep them in the verifier
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

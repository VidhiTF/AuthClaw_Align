# AuthClaw Multi-Region DR Runbook

This runbook covers the Terraform-managed RDS cross-region read-replica model for SRS NFR-3.1.

AuthClaw's HA target is active-active compute with active-standby data writes. Both regions can run ECS services behind Route53 failover records, but only the primary PostgreSQL instance accepts writes until the secondary read replica is promoted.

## Normal State

- Primary region ECS services write to the primary RDS PostgreSQL instance.
- Secondary region ECS services point at the secondary RDS read replica.
- The secondary database remains read-only until promotion.
- Route53 failover records may exist, but database failover is not complete until the replica is promoted.

## Failover Preconditions

- Confirm the primary region outage or planned failover decision.
- Check RDS replica lag in the secondary region.
- Confirm the secondary ECS services, OPA, Presidio, Redis, and ALB are healthy.
- Pause background jobs or remediation workers in the primary region if it is still partially reachable.

## Promotion Flow

1. Capture the failover start timestamp and current replica lag.

2. Promote the secondary RDS read replica in the AWS console or with AWS CLI:

```bash
aws rds promote-read-replica \
  --region <secondary-region> \
  --db-instance-identifier <secondary-db-identifier>
```

3. Wait until the promoted database is `available`.

4. Confirm the promoted endpoint accepts writes:

```bash
psql "$DATABASE_URL" -c "create table if not exists dr_write_probe(id text primary key);"
psql "$DATABASE_URL" -c "insert into dr_write_probe(id) values ('promotion-check') on conflict do nothing;"
```

5. Run pending migrations against the promoted database if the app version changed since the last verified standby test.

6. Route traffic to the secondary ALB:

- If Route53 failover is manual, update the active record.
- If Route53 health-based failover is enabled, confirm the secondary ALB target is healthy and primary is withdrawn.

7. Verify Route53 serves the secondary target:

```bash
dig +short <domain>
```

8. Verify AuthClaw health:

```bash
curl -fsS https://<domain>/api/lite-health
curl -fsS https://<domain>:8000/health
curl -fsS https://<domain>:8080/health
```

9. Run the gateway latency benchmark against the failover domain and retain the JSON artifact.

10. Verify audit-chain correctness against the promoted database.

11. Create `ha-failover-evidence.json` with:

- promotion start and completion time
- observed replica lag
- Route53 switch time
- p95/p99 gateway latency after failover
- audit-chain verification result

12. Validate the evidence:

```bash
python scripts/ha_failover_evidence.py ha-failover-evidence.json
```

The validator enforces 99.99% availability target evidence, promoted-replica workflow proof, Route53 failover proof, chaos coverage for primary region and primary database loss, RTO/RPO ceilings, post-failover latency, write correctness, and audit-chain correctness.

## Failback

Treat failback as a new planned migration:

- Create a new replica from the promoted secondary back to the original primary region.
- Verify replication lag and application compatibility.
- Schedule a maintenance window.
- Promote/switch only after write quiescence and audit-chain verification.

Do not point traffic back at the old primary database unless it has been rebuilt or resynchronized from the promoted database.

# ACL-24 Beta Recovery And Load Evidence

This is the controlled-beta procedure and evidence contract for ACL-24. The
checked-in JSON is synthetic schema proof, not evidence that a live beta drill
has run. Attach only the redacted live `acl24-evidence.json`, command logs, and
artifact checksums to Jira.

## Release gates

The drill passes only when `scripts/acl24_evidence.py` accepts the live evidence
with these defaults:

- gateway p95 at most 900 ms and p99 at most 1200 ms;
- error rate exactly 0;
- peak ECS CPU at most 85 percent;
- rollback and post-load recovery within 300 seconds;
- no ALB 5xx responses or active alarms;
- all restore, rollback, smoke, audit-chain, redaction, and CI checks true.
- every scenario records request/status counts, p50/p95/p99, throughput, and
  error rate, with CloudWatch evidence from before, during, and after load.

Do not loosen a threshold after a run. A release owner must approve any changed
threshold before the maintenance window and record it in the Jira issue.

## Safety boundary

1. Use the `controlled-beta` GitHub environment and its required approval.
2. Quiesce beta writes before the baseline export and snapshot.
3. Record the live RDS ARN, Alembic revision, ECS task definitions, alarms, and
   release SHA before changing anything.
4. Restore to a new identifier beginning `acl24-restore-`; never restore over,
   rename, delete, or modify the live beta database.
5. Keep the restored database private, encrypted, deletion protection off, and
   attached only to the existing private DB subnet and data security group.
6. Verify the restored database from a one-off ECS task. Use a temporary secret
   and temporary execution-role grant; never place a database URL in task
   definition environment variables, logs, workflow outputs, or artifacts.
7. Remove the temporary ECS task definition, secret, role grant, and restored
   instance only after their exact identifiers have been checked twice and the
   evidence has been retained.

The separate agent database is outside the minimum app-database proof. Repeat
the same isolated procedure for it only when the approved beta scope includes
agent persistence.

## Baseline and snapshot

Set explicit values; do not use wildcard discovery for a destructive command:

```bash
export ACL24_SOURCE_DB='authclaw-controlled-beta-primary-postgres'
export ACL24_SNAPSHOT="acl24-${GITHUB_RUN_ID}-app"
export ACL24_RESTORE="acl24-restore-${GITHUB_RUN_ID}-app"
test "$ACL24_SOURCE_DB" != "$ACL24_RESTORE"
case "$ACL24_RESTORE" in acl24-restore-*) ;; *) exit 1 ;; esac
```

Capture and retain:

```bash
git rev-parse HEAD
alembic current
aws rds describe-db-instances --db-instance-identifier "$ACL24_SOURCE_DB"
aws ecs describe-services --cluster authclaw-controlled-beta-primary-cluster \
  --services authclaw-controlled-beta-primary-backend \
  authclaw-controlled-beta-primary-gateway \
  authclaw-controlled-beta-primary-console
aws cloudwatch describe-alarms --state-value ALARM
```

Generate a safe sentinel gateway request with a unique `X-Request-ID`, wait for
its audit record, export the tenant audit chain, and verify it offline:

```bash
python backend/scripts/verify_audit_export.py \
  --trusted-keys trusted-keys.json pre-drill-audit-export.json \
  > audit-export-verification.json
```

The export may contain beta data and must not be attached. Attach only the
redacted verifier result and its SHA-256 digest. The evidence must record that
the export was signed, signature-verified, and generated before the drill.

Create and restore the encrypted snapshot:

```bash
aws rds create-db-snapshot \
  --db-instance-identifier "$ACL24_SOURCE_DB" \
  --db-snapshot-identifier "$ACL24_SNAPSHOT"
aws rds wait db-snapshot-available \
  --db-snapshot-identifier "$ACL24_SNAPSHOT"

# Copy the source DB subnet group and VPC security-group IDs exactly.
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier "$ACL24_RESTORE" \
  --db-snapshot-identifier "$ACL24_SNAPSHOT" \
  --db-subnet-group-name '<private-db-subnet-group>' \
  --vpc-security-group-ids '<data-security-group-id>' \
  --no-publicly-accessible --no-multi-az --no-deletion-protection
aws rds wait db-instance-available --db-instance-identifier "$ACL24_RESTORE"
aws rds describe-db-instances --db-instance-identifier "$ACL24_RESTORE" \
  --query 'DBInstances[0].{Encrypted:StorageEncrypted,Public:PubliclyAccessible,Status:DBInstanceStatus}'
```

The one-off ECS verification must prove the Alembic revision, sentinel presence,
table counts, and complete audit chain match the quiesced baseline. A mismatch
fails the drill; do not mark it as an expected timing difference.

## Application and database rollback

Use the captured task definitions from
`.github/workflows/deploy-controlled-beta.yml`. Update each exact service to its
recorded definition, wait for stability, and retain the command log:

```bash
aws ecs update-service --cluster '<cluster>' --service '<service>' \
  --task-definition '<previous-task-definition-arn>' --force-new-deployment
aws ecs wait services-stable --cluster '<cluster>' --services '<all-services>'
```

Run login, gateway, and audit smoke checks. Generate a post-rollback event and
verify that it extends the valid pre-rollback chain. Database rollback proof is
the isolated restored instance; do not run a destructive Alembic downgrade on
the live beta database. Migration 028 intentionally retains immutable audit
rows and its mutation guard during application rollback.

## Targeted load and recovery

Run the existing dependency-free benchmark at each approved concurrency level:

```bash
python scripts/gateway_latency_benchmark.py \
  --gateway-url 'https://<beta-gateway>' \
  --scenarios allow,redact,block,stream \
  --requests 100 --concurrency 5 --warmup 5 \
  --p95-threshold-ms 900 --p99-threshold-ms 1200 \
  --max-failure-rate 0 --json-output gateway-benchmark-c05.json
```

Repeat for concurrency 10 and 20. If real provider traffic is not explicitly
approved, use the configured beta mock provider for the load run and record one
separate low-volume real-provider smoke result.

For the complete baseline/load/recovery window, export CloudWatch metric data
for ECS CPU and memory, RDS CPU/connections/free memory/read/write latency, ALB
5xx and target response time, and Redis CPU. After load, poll health and alarms
until every service is healthy and utilization has recovered, or five minutes
has elapsed. Record the measured recovery time; a timeout fails the drill.

## Evidence validation and cleanup

Copy `infra/security/acl24-evidence.example.json` outside the repository, replace
every example value with measured redacted evidence, compute artifact SHA-256
digests, then run:

```bash
python scripts/acl24_evidence.py acl24-evidence.json
```

Only after validation succeeds, delete the exact isolated restore target:

```bash
case "$ACL24_RESTORE" in acl24-restore-*) ;; *) exit 1 ;; esac
test "$ACL24_RESTORE" != "$ACL24_SOURCE_DB"
aws rds delete-db-instance --db-instance-identifier "$ACL24_RESTORE" \
  --skip-final-snapshot --no-delete-automated-backups
aws rds wait db-instance-deleted --db-instance-identifier "$ACL24_RESTORE"
```

Retain the source snapshot according to the approved evidence-retention period.
Do not delete it in the drill workflow.

## Local compatibility evidence

Local and CI tests prove the validator, audit migration, benchmark, and pulled
code remain compatible. They do not satisfy the live backup/restore acceptance
criterion. Record commands and results here before review:

| Check | Result |
| --- | --- |
| ACL-24 evidence validator tests | Passed locally, 2026-07-21 |
| Gateway benchmark unit tests | Passed locally, 2026-07-21 |
| Fresh Alembic `001` through `034` migration | Passed against `authclaw_test`, 2026-07-21 |
| Audit export/store, migration 028, onboarding, and access-request tests | 78 passed; required backend subset 155 passed |
| Go gateway tests | Required CI selection passed; full suite compatibility fixtures repaired |
| Console checks | 18 unit tests, lint, typecheck, and production build passed |
| Agent and SDK checks | 15 agent smoke tests and 2 SDK tests passed |
| Local mock-provider load check | 40/40 requests behaved correctly with 0% errors; performance gate rejected local Windows/debug latency |
| Hosted required CI and live beta drill | Pending; local results are not beta evidence |

The local load run used ten requests per scenario at concurrency five. Observed
p95/p99 values were: allow 734.0/799.2 ms, redact 1604.2/1621.2 ms, block
260.2/272.7 ms, and stream 512.0/513.4 ms. The unchanged 900/1200 ms gate
correctly failed on the redact path and on gateway-overhead limits. Do not use
this local run as ACL-24 acceptance evidence or relax the beta thresholds because
of it.

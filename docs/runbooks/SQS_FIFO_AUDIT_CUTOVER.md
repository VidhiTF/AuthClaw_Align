# SQS FIFO audit transport cutover and rollback checklist

This runbook is a template for production deployment verification. It does not
authorize provisioning, traffic cutover, Kafka removal, or an ADR status change.

## Evidence collection

1. Export Terraform outputs from the intended workspace:
   - `terraform output -json > terraform-output.json`
2. Run the read-only collector:
   - `python scripts/sqs_audit_deployment_readiness.py --terraform-output-json terraform-output.json --live`
3. Attach the generated JSON and Markdown evidence to the release record.
4. Treat any `FAIL` as a release blocker.
5. Treat any `LIVE-EVIDENCE-PENDING` as not yet proven; do not convert it to PASS
   without captured live output.

## Prechecks

- Confirm `audit_stream_transport` remains `kafka` until human cutover approval.
- Confirm deployed images and commit SHAs match the intended release.
- Confirm queue, DLQ, redrive, redrive-allow, KMS, alarms, IAM and VPC endpoint
  checks are PASS.
- Confirm ECS task definitions contain no static AWS credentials.
- Confirm producers have send-only SQS permissions and the consumer has
  receive/delete/change-visibility only.
- Confirm rollback target Kafka brokers/topics and audit consumer task definition
  remain deployable.

## Canary

- Use an explicit canary tenant and record the canary audit record IDs.
- Record tenant sequence before and after the canary.
- Verify final ClickHouse/Postgres hash-chain evidence.
- Confirm no ordinary production messages were consumed or deleted by the
  verification collector.

## Cutover approval gate

- Security, backend owner and release manager approve the evidence.
- Confirm rollback owner is online.
- Confirm monitoring windows and alarm destinations are active.
- Only after approval, change `audit_stream_transport` to `sqs_fifo` through the
  normal Terraform/deployment process.

## Monitoring

- Watch audit queue age/depth, DLQ age/depth, ECS task health, consumer retry
  count, duplicate count, ClickHouse insert failures and hash-chain violations.
- If DLQ depth rises or chain validation fails, stop the cutover and rollback.

## Rollback to Kafka

1. Revert `audit_stream_transport` to `kafka`.
2. Redeploy producer and audit-consumer task definitions.
3. Confirm Kafka producer publish metrics recover.
4. Preserve SQS queue/DLQ messages for forensic review; do not purge.
5. Reconcile audit chains across Postgres, ClickHouse and SQS/Kafka evidence.

## Post-cutover reconciliation

- Compare canary IDs, tenant sequence, final chain heads and DLQ counts.
- Attach final reconciliation evidence and approval notes to the release record.
- Kafka decommissioning is out of scope until the approved rollback window and
  retention obligations are satisfied.

# SQS FIFO audit deployment readiness

Mode: `LIVE-EVIDENCE-PENDING`

This collector is read-only by default and never performs cutover.

| Check | Status | Evidence |
|---|---|---|
| audit queue attributes | LIVE-EVIDENCE-PENDING | queue attributes were not collected |
| SQS alarms | LIVE-EVIDENCE-PENDING | Terraform alarm names unavailable |
| consumer cannot send | LIVE-EVIDENCE-PENDING | consumer role unavailable |
| SQS VPC endpoint | LIVE-EVIDENCE-PENDING | live AWS collection not requested |
| ECS services/task definitions | LIVE-EVIDENCE-PENDING | cluster or service names unavailable |
| Kafka rollback/default remains configured | LIVE-EVIDENCE-PENDING | confirm audit_stream_transport remains kafka until approved cutover |
| commit/image digest match | LIVE-EVIDENCE-PENDING | compare deployed task definition images with intended release digest |
| canary audit chain | LIVE-EVIDENCE-PENDING | record canary IDs, tenant sequence and final chain after explicit deployment canary |

## Commands

- `terraform output -json > terraform-output.json`
- `python scripts/sqs_audit_deployment_readiness.py --terraform-output-json terraform-output.json --live`
- `aws sqs get-queue-attributes --attribute-names All`
- `aws cloudwatch describe-alarms --alarm-names <audit_sqs.alarm_names>`
- `aws iam simulate-principal-policy for producer/consumer task roles`
- `aws ec2 describe-vpc-endpoints --vpc-endpoint-ids <network_path.interface_endpoint_ids.sqs>`
- `aws ecs describe-services and describe-task-definition for backend/gateway/agent/audit_consumer`

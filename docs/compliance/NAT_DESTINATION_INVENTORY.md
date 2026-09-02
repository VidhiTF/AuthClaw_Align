# NAT Destination Inventory

## Purpose

This is the required evidence format for every AuthClaw public-egress dependency. Configuration review identifies possible destinations; VPC Flow Logs and service-owner confirmation establish the authoritative production inventory. Completion requires no unexplained NAT destination during the observation window.

## Configured Candidates

| Workload | Destination or source setting | Expected path | Status |
| --- | --- | --- | --- |
| Gateway | `OPENAI_BASE_URL=https://api.openai.com` | NAT | Candidate; confirm enabled tenants |
| Gateway | `ANTHROPIC_BASE_URL=https://api.anthropic.com` | NAT | Candidate; confirm enabled tenants |
| Gateway | `COHERE_BASE_URL=https://api.cohere.ai` | NAT | Candidate; confirm enabled tenants |
| Gateway | `GEMINI_BASE_URL=https://generativelanguage.googleapis.com` | NAT | Candidate; confirm enabled tenants |
| Gateway | `AZURE_OPENAI_BASE_URL` | NAT or approved private connectivity | Destination not configured in the production example |
| Gateway | AWS Bedrock | AWS private endpoint if separately configured; otherwise NAT | Bedrock endpoint is not part of this change |
| Backend | `SMTP_HOST=email-smtp.<aws-region>.amazonaws.com:587` | NAT or approved private connectivity | Production example uses SES SMTP |
| Backend/Gateway/Audit consumer | `KAFKA_BROKERS` | Approved MSK/private connectivity preferred; NAT only when explicitly approved | Deployment value required |
| Backend/Audit consumer | `CLICKHOUSE_HOST:CLICKHOUSE_PORT` | Approved private connectivity preferred; NAT only when explicitly approved | Deployment value required |
| ECS workloads | ECR API and Docker | Interface endpoints | Implemented |
| ECS workloads | CloudWatch Logs | Interface endpoint | Implemented |
| ECS workloads | Secrets Manager | Interface endpoint | Implemented |
| ECS workloads | KMS | Interface endpoint | Implemented |
| VPC workloads | S3 | Gateway endpoint | Implemented |
| VPC workloads | DynamoDB | Gateway endpoint | Implemented; no new task-role permissions granted |

## Authoritative Evidence

Complete one row for every observed or approved destination:

| Account | Region | Environment | Source service/task | Destination FQDN | Resolved IP/CIDR | Port/protocol | Business purpose | Path (NAT/private endpoint/private link) | Data classification | Owner | Approval/ticket | Flow-log query/artifact | Last verified |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Pending | Pending | production | Pending | Pending | Pending | Pending | Pending | Pending | Pending | Pending | Pending | Pending | Pending |

## Completion Gate

Before production rollout:

1. Export deployed task definitions and secret references for every ECS service.
2. Resolve all configured model-provider, SMTP, Kafka, ClickHouse, webhook, and customer-integration destinations.
3. Query VPC Flow Logs for each private subnet over an approved representative observation window.
4. Reconcile every public destination to an approved row above; investigate or deny unexplained destinations.
5. Record whether SMTP, Kafka, and ClickHouse use NAT or private connectivity.
6. Attach the inventory, query, raw export location, reviewer, and approval ticket to the production change.

Because NAT is not an egress firewall, production requires a separately approved destination-control design where policy demands allowlisting. Security groups alone do not restrict outbound traffic by FQDN.

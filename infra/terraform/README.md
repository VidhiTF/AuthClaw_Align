# AuthClaw Terraform

> **Architecture gate:** [ADR-0002](../../docs/adr/0002-aws-url-environment-boundary.md)
> defines the proposed public URL and private-origin contract. This Terraform is an
> earlier baseline with an internet-facing ALB and must not be deployed as the approved
> staging/production edge until ACL-14 implements that ADR and Binod records approval.

This directory is the SRS NFR-3.1 baseline for deploying AuthClaw as a multi-region AWS stack.

It creates a primary regional stack and, by default, a warm secondary regional stack. Each region includes:

- VPC with public/private subnets across availability zones
- Public ALB listeners for console, backend API, and gateway
- ECS/Fargate services for console, backend, gateway, OPA, and Presidio
- Private Cloud Map service discovery for internal service URLs
- Encrypted RDS PostgreSQL and encrypted ElastiCache Redis
- Optional RDS cross-region read replica for the secondary database
- KMS key, Secrets Manager entries, and CloudWatch log groups
- Optional audit consumer wired to managed Kafka/MSK and ClickHouse endpoints
- Optional Route53 primary/secondary failover alias record

## Usage

Copy the example variables, set image tags and cloud-specific values, then plan:

```bash
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform plan -var-file=terraform.tfvars
```

The example defaults use `authclaw_env = "staging"` so the stack can be validated before production-only dependencies are configured. For a production deployment, set:

- `authclaw_env = "production"`
- `domain_name`
- `primary_certificate_arn`
- `secondary_certificate_arn`
- `smtp_host`
- `smtp_from`
- production image digests instead of floating `latest` tags

The OPA image must include the AuthClaw Rego policy bundle from `infra/opa`, or use an equivalent OPA bundle configuration baked into the image.

## Multi-Region Model

The root module deploys regional stacks with separate KMS keys, Redis clusters, ECS services, and secrets. Route53 failover can point the same public name at the primary or secondary ALB.

By default, `enable_cross_region_db_replica = true` creates the secondary PostgreSQL database as an encrypted RDS cross-region read replica of the primary database. The secondary region receives its own database connection secrets that point at the replica endpoint and use the primary database password. After promotion, the replica endpoint becomes writable without rotating application secrets.

This gives AuthClaw a concrete warm-standby RPO/RTO story for data writes:

- RPO is bounded by RDS asynchronous replication lag.
- RTO is the time to promote the replica, confirm write readiness, and route traffic to the secondary ALB.
- The secondary database is read-only until promotion, so AuthClaw is active-active for warm compute capacity and active-standby for writes.
- Automated Route53 failover must be paired with replica promotion automation or a documented manual promotion decision.

Set `enable_cross_region_db_replica = false` only when you intentionally want isolated regional test databases. See `DR_RUNBOOK.md` for the promotion flow.

## HA Evidence Gate

Production failover evidence must pass the stdlib validator before claiming SRS NFR-3.1 closure:

```bash
python scripts/ha_failover_evidence.py infra/terraform/ha_failover_evidence.example.json
```

Replace the example with the captured live-run artifact. The gate rejects missing Route53 failover proof, missing promoted-read-replica workflow proof, RTO/RPO breaches, missing post-failover latency, or missing write/audit correctness checks.

## Audit Integrations

Kafka and ClickHouse are treated as managed external services:

- Set `kafka_brokers` for gateway/backend audit publication.
- Set `clickhouse_host`, `clickhouse_*`, and `enable_audit_consumer = true` to run the audit consumer.
- Create MSK topics from `../kafka/topics.yaml`: `gateway.traffic`, `audit.events`, and `audit.deadletter`.
- Use tenant-keyed partitioning (`tenant_id`) so each tenant's audit chain is consumed in order.

This keeps the regional AuthClaw stack portable while still making the audit path explicit in IaC.

## NAT and Private AWS Paths

`nat_gateway_mode` controls outbound Internet topology in both regional stacks:

- `single` creates one NAT Gateway and routes every private subnet through it. Use this lower-cost mode for development and staging.
- `per_az` creates one NAT Gateway per public subnet and routes each private subnet to the NAT in the same availability zone. Production must use this mode after the rollout gates in the runbook are satisfied.

Every private subnet has its own route table. The S3 gateway endpoint is associated with all private route tables; DynamoDB is intentionally omitted until a runtime dependency is confirmed. ECR API, ECR Docker, CloudWatch Logs, Secrets Manager, and KMS use private-DNS interface endpoints. Their security group accepts TCP 443 only from the regional ECS application security group.

The first state-backed plan after this change must prove that the existing singleton EIP, NAT Gateway, and route tables move to key `"0"` without replacement. Do not apply a plan that deletes or replaces the existing NAT/EIP identity. See [NAT_EGRESS_RUNBOOK.md](../../docs/runbooks/NAT_EGRESS_RUNBOOK.md) for migration, validation, rollback, monitoring, and production approval gates.

Example environment choices:

```hcl
# Development and staging
nat_gateway_mode = "single"

# Production, after approval gates
nat_gateway_mode = "per_az"
```

Run the deterministic topology tests locally:

```bash
terraform fmt -check -recursive
terraform init -backend=false
terraform validate
terraform test
```

## Operations Notes

- The backend image should run migrations before serving traffic, either in its entrypoint or via a one-off ECS task using the same `backend_database_url` secret.
- Configure ACM certificates in every region where HTTPS listeners are used.
- Test RDS replica promotion regularly; Terraform creates the standby path, but operations prove the RTO.
- Avoid committing real `*.tfvars` files; only `*.tfvars.example` is tracked.

## Finding-status migration 047

Revision 047 rejects non-canonical values already present in `public.findings`; it
does not silently rewrite them. Before the maintenance window, run this read-only
preflight with a maintenance identity and obtain an explicit disposition for every
returned status:

```sql
SELECT status, count(*)
FROM public.findings
WHERE status NOT IN (
  'OPEN', 'ACKNOWLEDGED', 'IN_PROGRESS', 'AWAITING_APPROVAL',
  'RESOLVED', 'FALSE_POSITIVE', 'ACCEPTED_RISK'
)
GROUP BY status
ORDER BY status;
```

Use this coupled rollout so an old process is never restarted against an
unexpected schema head:

1. Build and deploy the compatibility backend and gateway with
   `expected_db_revision = "046,047"`; confirm both services are healthy on 046.
2. Apply migration 047 in the same controlled maintenance window and confirm both
   services remain healthy on 047.
3. Set `expected_db_revision = "047"` and perform a rolling restart so the
   temporary compatibility allowance is removed.

Do not leave `046,047` configured after the migration. Before 047 is applied, the
safe rollback is the previous image and revision 046. After writes have occurred
under the new constraint, prefer a forward fix; downgrading removes the database
constraint and requires a separately approved data-integrity decision.

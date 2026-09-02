# NAT Egress Rollout and Recovery

## Scope

This runbook covers the Terraform NAT topology, private AWS service endpoints, validation, and rollback. It does not authorize a production deployment. NAT provides source translation and availability-zone-local routing; it is not an egress firewall or destination allowlist.

## Topology

| Environment | `nat_gateway_mode` | Intended result |
| --- | --- | --- |
| Development | `single` | One NAT Gateway; all private route tables target key `"0"` |
| Staging | `single` | One NAT Gateway; all private route tables target key `"0"` |
| Production | `per_az` | One NAT Gateway per enabled AZ; each private subnet targets its same-key NAT |

The root setting applies to both primary and secondary stacks. Public and private subnet lists must remain one-to-one and in the same AZ order.

S3 and DynamoDB gateway endpoints attach to every private route table. Interface endpoints for ECR API, ECR Docker, CloudWatch Logs, Secrets Manager, and KMS use private DNS and accept TCP 443 only from the ECS application security group.

Endpoint policies initially use the AWS default full-access policy. IAM task roles remain the authorization boundary. The security owner must approve any later endpoint-policy restriction after the destination inventory is complete, because over-restricting ECR can break access to S3-backed image layers.

## Required Evidence Before Production

Do not run a production apply until all items are recorded in the change ticket:

1. Production account IDs, regions, enabled AZs, and deployed public/private subnet mappings.
2. The authoritative Terraform state addresses from `terraform state list`.
3. A state-backed plan showing the existing EIP, NAT Gateway, public route table, private route table, and default routes moving to key `"0"` with no delete or replacement.
4. A completed [NAT destination inventory](../compliance/NAT_DESTINATION_INVENTORY.md), backed by configuration review and VPC Flow Logs.
5. A completed [NAT cost baseline](../compliance/NAT_COST_BASELINE.md), projected per-AZ increase, approved budget threshold, budget owner, and notification destination.
6. Named deployment approver and rollback operator.
7. Secondary-region readiness evidence for images, data, secrets, IAM, endpoints, DNS, SMTP, Kafka, ClickHouse, and model-provider integrations.

The checked-in `moved` blocks match the singleton resource addresses in this configuration. If deployed state differs, stop and reconcile it before changing the blocks.

## Preflight

```bash
terraform fmt -check -recursive
terraform init
terraform validate
terraform test
terraform state list
terraform plan -var-file=<approved-production.tfvars> -out=nat-rollout.tfplan
terraform show -json nat-rollout.tfplan
```

The reviewer must reject any unintended destroy/replace action, cross-AZ private route, missing endpoint, or public endpoint-security-group CIDR.

## Rollout

1. Apply the state-preserving indexed-resource migration while mode remains `single`.
2. Verify the original EIP public address and NAT Gateway identity are preserved at key `"0"`.
3. Verify every private subnet has a `0.0.0.0/0` route and AWS service endpoint traffic resolves privately.
4. Set the root `nat_gateway_mode = "per_az"`. Because the current root manages both regions with one value and one state, create and review a saved secondary-only plan:

   ```bash
   terraform plan -target=module.secondary -out=nat-secondary.tfplan
   terraform show nat-secondary.tfplan
   ```

5. Apply only the reviewed `nat-secondary.tfplan` during the approved change window. The targeted operation is limited to this staged regional migration; immediately follow it with a full plan so unrelated drift is not hidden.
6. Validate application startup, ECR pulls, log delivery, secret/KMS access, external integrations, route locality, alarms, and dashboard data.
7. Perform a controlled non-production NAT-unavailable drill. Success means the affected path alarms, recovery restores the intended route, and no unrelated AZ route changes.
8. Obtain approval, run and review a full state-backed plan, and apply that saved plan to complete the primary-region change and reconcile the entire root.

The design does not automatically route an AZ to another AZ's NAT. If one NAT fails, private workloads in that AZ lose public egress while private endpoint traffic remains available. Recovery is an explicit, approved route change or NAT replacement.

## Monitoring

Each NAT has alarms for:

- `ErrorPortAllocation`: maximum greater than zero for three consecutive five-minute periods.
- `PacketsDropCount`: dropped packets exceed 0.01 percent of packets seen for two consecutive five-minute periods.
- `IdleTimeoutCount`: anomaly detection outside the two-standard-deviation band for three consecutive five-minute periods.

The regional dashboard shows active, attempted, and established connections plus bytes sent and received by NAT/AZ. Alarm actions must be attached to the approved operations notification topic before production.

## Rollback

1. Stop rollout and preserve the failed plan/apply output.
2. Identify every private default route and its current NAT target from Terraform state and AWS route tables.
3. Route all private subnets back to the preserved key `"0"` NAT and verify application egress.
4. Confirm no route references newly created NAT Gateways.
5. Change `nat_gateway_mode` back to `single`, review the state-backed plan, and only then remove unused NAT Gateways/EIPs through Terraform.
6. Re-run endpoint, application, alarm, and route-locality checks and attach results to the change ticket.

Never delete a NAT Gateway or EIP while a private route still targets it. Do not remove the `moved` blocks until every managed state has completed the migration.

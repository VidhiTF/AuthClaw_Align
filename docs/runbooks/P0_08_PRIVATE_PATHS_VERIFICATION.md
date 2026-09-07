# P0-08 private AWS paths verification and rollback

## Purpose and completion rule

This runbook produces the live staging evidence required to promote the private
AWS-service paths implemented by P0-08. It covers the services inventoried in
[`P0_08_RUNTIME_AWS_SERVICE_INVENTORY.md`](../compliance/P0_08_RUNTIME_AWS_SERVICE_INVENTORY.md).

Chunk 3 is repository-complete when this runbook and its fail-closed evidence
validator are present and tested. P0-08 is operationally complete only after a real
staging exercise passes the validator and Security and Platform owners approve its
artifacts. The example JSON is a template and is never acceptable evidence.

Do not perform the NAT exercise in production. Do not delete a NAT gateway or EIP.
Changing a default route is an outage-capable action and requires an approved change,
two operators, a restoration timer, and a tested AWS access path that does not depend
on the route being changed.

## Inputs and owners

Record these before starting:

- staging AWS account ID, Region, VPC, cluster, service names, and deployed Git commit;
- selected `audit_stream_transport` (`kafka` or `sqs_fifo`);
- exact S3 bucket, KMS key, secret, and STS role allowlists;
- Terraform state workspace and immutable evidence location;
- change ticket, exercise operator, rollback operator, Security approver, and Platform approver;
- allowed public/NAT destinations from
  [`NAT_DESTINATION_INVENTORY.md`](../compliance/NAT_DESTINATION_INVENTORY.md).

The evidence location must be access controlled and immutable or versioned. Never
capture secret values, data keys, credentials, authorization headers, or message
bodies in evidence.

## 1. Validate Chunks 1 and 2 locally

From the repository root:

```bash
python -m unittest scripts/test_p008_private_paths_evidence.py -v
terraform -chdir=infra/terraform fmt -check -recursive
terraform -chdir=infra/terraform init -backend=false
terraform -chdir=infra/terraform validate
terraform -chdir=infra/terraform test
```

Confirm the inventory references resolve and independently review the Terraform plan.
The Kafka plan must contain six interface endpoints; the SQS FIFO plan must contain
seven. Neither plan may contain Kinesis or DynamoDB endpoints.

## 2. Save, review, and apply one staging plan

Set all required staging inputs, including the exact ARN allowlists, then create a
saved plan using the real remote state configuration:

```bash
terraform -chdir=infra/terraform init
terraform -chdir=infra/terraform plan -out=p008-staging.tfplan -var-file=staging.tfvars
terraform -chdir=infra/terraform show -json p008-staging.tfplan
```

Store the human-readable plan and JSON plan as evidence. A second operator must prove
the plan does not replace `aws_eip`, `aws_nat_gateway`, `aws_route_table`, `aws_subnet`,
or `aws_vpc`. Apply exactly the reviewed saved plan, not a newly calculated plan:

```bash
terraform -chdir=infra/terraform apply p008-staging.tfplan
```

Stop and roll back if the live result differs from the reviewed plan.

## 3. Prove endpoint topology and DNS

Capture `describe-vpc-endpoints`, endpoint network interfaces, private route tables,
and endpoint policies. Verify:

- ECR API, ECR registry, Logs, Secrets Manager, KMS, and STS interface endpoints are
  `available`, use private DNS, span at least two required Availability Zones, and
  accept TCP 443 only from the application security group;
- SQS has the same properties only when `audit_stream_transport=sqs_fifo`;
- S3 is the only gateway endpoint and is associated with every private route table;
- endpoint policies contain the TLS-deny statement and the reviewed resource and
  principal scopes;
- Kinesis and DynamoDB endpoints are absent.

From a disposable task in each required private Availability Zone, resolve the
standard regional AWS hostnames and capture only the answers and endpoint ENI private
addresses. They must match for every interface service. Confirm the S3 destination
uses the S3 prefix-list route. Set `AWS_STS_REGIONAL_ENDPOINTS=regional` and prove the
regional STS hostname is used.

## 4. Establish the allowed baseline

Before disabling NAT routes, start fresh task revisions and prove:

- images pull from approved ECR repositories;
- ECS injects approved secrets and every task creates and writes its log stream;
- enabled application paths successfully call the approved KMS key, same-Region S3
  scope, regional STS role, and Secrets Manager scope;
- SQS producers and consumer work when SQS FIFO is selected;
- task metadata supplies temporary role credentials and no static AWS access key is
  present in task configuration or environment.

Record API name, redacted resource ARN, task ARN, Availability Zone, timestamp,
request ID, and result. Store application and service logs without response payloads.

## 5. Rehearse loss of NAT for covered AWS calls

Snapshot every affected route table and its current default route. Verify from tags
and Terraform state that every target belongs to the staging VPC. Configure an
independent timed restoration procedure and have the rollback operator verify it.

Under the approved change, make the private-subnet NAT default routes unavailable.
Do not delete NAT gateways, EIPs, route tables, or subnets. Record the route state and
time, then repeat all probes from section 4 using newly started tasks in each required
Availability Zone. Covered regional AWS calls must succeed. Public model providers,
external Kafka/ClickHouse, IAM, Bedrock, cross-Region S3, and other destinations in the
NAT inventory may fail and do not count as endpoint failures.

Immediately restore the exact saved default routes. Verify the route-table state,
task stability, and every approved public path. If any covered probe fails, restore
routes first and treat the exercise as failed.

## 6. Prove policy denials

Using disposable non-production resources selected by Security, attempt the same API
shape against one out-of-scope ECR repository, log group, secret, KMS key, STS role,
and S3 bucket/key. Add an out-of-scope SQS queue in SQS FIFO mode. Each attempt must
return an authorization denial while its paired approved call continues to succeed.

The denial target must belong to the test account and contain no production data.
Capture request IDs and redacted ARNs, never secret or object contents. An invalid
resource name, DNS failure, or timeout is not policy-denial evidence.

## 7. Prove the network path

Query VPC Flow Logs for the exercise window and correlate task ENIs, endpoint ENIs,
NAT ENIs, and request timestamps. For every covered call, retain evidence that traffic
used an endpoint ENI or the S3 gateway route and did not use NAT. Investigate every
unexplained public AWS destination; the gate requires the final unexplained list to be
empty.

## 8. Rehearse rollback

Rollback is restoration, not infrastructure deletion:

1. Restore all saved NAT default routes and verify public-path health.
2. Deploy the last known-good task definitions and wait for ECS services to stabilize.
3. Revert the P0-08 Terraform commit, produce and review a new saved plan, and apply it
   only when rollback of endpoint/IAM configuration is required.
4. Do not delete endpoint infrastructure while tasks or rollback images depend on it.
5. Capture service events, task health, routes, and the final Terraform plan/state.

## 9. Validate and approve the evidence bundle

Copy
[`p008-private-paths-evidence.example.json`](../../infra/security/p008-private-paths-evidence.example.json)
to an ignored evidence directory. Replace every placeholder with live evidence and set
the deployment audit transport. Validate it with the matching mode:

```bash
python scripts/p008_private_paths_evidence.py path/to/p008-staging-evidence.json \
  --audit-transport kafka \
  --output-md path/to/p008-staging-evidence.md
```

Use `--audit-transport sqs_fifo` for the SQS plan. Exit code `0` and status `PASS` are
required. The validator rejects placeholders, wrong endpoint sets, missing private DNS
proof, protected network replacement, incomplete restoration, unexplained public AWS
destinations, missing denial tests, missing artifacts, and missing approvals.

Security and Platform owners must review the raw artifacts before signing the bundle.
A passing JSON file without corresponding immutable artifacts is not evidence.

## Promotion gates

P0-08 may be marked complete only when:

1. Chunk 1 inventory decisions and repository references are reviewed and current.
2. Chunk 2 deterministic tests, security scan, state-backed plan, endpoint/IAM scopes,
   and non-replacement check pass.
3. Chunk 3 staging exercises pass in every required Availability Zone with NAT routes
   unavailable, followed by verified restoration and rollback.
4. The validator returns `0`, every referenced artifact is reviewed, and Security and
   Platform approvals are recorded.
5. Any remaining NAT destinations have explicit owners and are not represented as
   covered by P0-08.

# P0-08 Runtime AWS-service inventory

- Status: Chunks 1–3 implemented in the repository; state-backed plan, AWS staging exercise, approvals, and live-path evidence pending
- Inventory date: 2026-09-03
- Scope: repository runtime, ECS task bootstrap, deployment automation, and operator paths
- Authority: this inventory records observed repository behavior; the
  [deployment-readiness task list](../AWS_DEPLOYMENT_READINESS_TASK_LIST.md) is a
  requirements source, not an executable runbook

## Decision summary

| Service | Endpoint decision | NAT decision |
| --- | --- | --- |
| S3 | Required gateway endpoint in every private route table | Not required for same-Region S3 through the gateway endpoint; retain a reviewed NAT path for cross-Region or nonstandard S3 destinations until flow evidence proves otherwise |
| ECR API and registry | Both interface endpoints are required | Not required for normal pulls from private ECR; first-time pull-through-cache retrieval remains outside this guarantee |
| CloudWatch Logs | Interface endpoint is required | Not required for ECS `awslogs` delivery |
| Secrets Manager | Interface endpoint is required | Not required for ECS secret injection or enabled application calls |
| KMS | Interface endpoint is required | Not required for direct KMS calls; service-to-service KMS use is not a workload network path |
| SQS | Required only when `audit_stream_transport = "sqs_fifo"` | Not required for SQS mode when its interface endpoint is enabled |
| STS | **Required for the production runtime feature set** | Not required after a regional STS interface endpoint is added and callers are forced to the regional endpoint |
| Kinesis Data Streams | **Not required** | No endpoint or NAT allowance is justified because there is no runtime caller and ADR-0011 has not selected Kinesis |
| DynamoDB | **Not required** | No endpoint or NAT allowance is justified because there is no runtime caller, configuration, or IAM grant |

Terraform now creates S3, ECR API, ECR registry, Logs, Secrets Manager, KMS, and STS
endpoints, and adds SQS only in SQS mode. The endpoint security group is private and
multi-AZ, every endpoint has an explicit policy, and optional application permissions
are fail-closed behind exact ARN allowlists. Live AWS evidence remains required before
the production readiness task can be closed. Use the controlled
[`P0_08_PRIVATE_PATHS_VERIFICATION.md`](../runbooks/P0_08_PRIVATE_PATHS_VERIFICATION.md)
runbook and its fail-closed evidence validator; the example evidence file is not proof
of a completed exercise.

## Classification rules

This inventory separates three identities that should not be conflated:

1. **Task execution role / ECS platform path** — Fargate retrieves images and
   injected secrets and starts the `awslogs` driver before application code runs.
2. **Task role / application path** — backend, gateway, agent, and audit-consumer
   SDK calls execute with the task role or with explicitly supplied customer
   credentials.
3. **Deployment/operator path** — GitHub-hosted runners and operator workstations are
   outside the workload VPC, so their AWS calls do not justify workload VPC endpoints.

An IAM trust policy containing `sts:AssumeRole` for `ecs-tasks.amazonaws.com` is not
itself a task network call to STS. The confirmed STS requirement comes from application
SDK calls described below.

## Confirmed workload and platform calls

| Service and caller | Confirmed API actions | Resource scope to enforce | DNS and network path | Endpoint / NAT result |
| --- | --- | --- | --- | --- |
| **S3 — ECS/Fargate image pull** for every task and database job declared in [`regional_stack/main.tf`](../../infra/terraform/modules/regional_stack/main.tf) | ECR-managed image-layer reads from the regional S3 starport bucket | AWS-owned ECR layer bucket for the deployment Region, limited by the S3 endpoint policy | Regional S3 name → S3 gateway prefix-list route on every private route table | Existing `com.amazonaws.<region>.s3` gateway endpoint is required; no NAT for this path |
| **S3 — backend AWS API and document sync** in [`endpoints/aws.py`](../../backend/app/api/v1/endpoints/aws.py) | `s3:ListBucket` (including HeadBucket), `s3:GetObject` metadata via HeadObject | Configured `AWS_S3_BUCKET`; list limited to `tenant-<tenant_id>/`, object metadata limited to that prefix | Regional S3 SDK name → gateway endpoint | Existing endpoint is required; same-Region path needs no NAT |
| **S3 — backend document remediation** in [`orchestrator/connectors.py`](../../backend/app/orchestrator/connectors.py) | `s3:ListBucket`, `s3:GetObject`, `s3:PutObject` | Configured bucket; tenant document keys plus `.authclaw-rollback/<workflow>/<action>/...` | Regional S3 SDK name → gateway endpoint | Existing endpoint is required; same-Region path needs no NAT |
| **S3 — backend customer cloud connector** in [`cloud_connectors.py`](../../backend/app/services/cloud_connectors.py) | `s3:ListAllMyBuckets`, `s3:PutBucketPublicAccessBlock` | Customer account and connector-approved bucket ARN; credentials are customer supplied | Connector-selected regional S3 name → local regional gateway only when compatible | Endpoint is required for same-Region calls; cross-Region customer scope must be measured and may require NAT or a separately approved design |
| **S3 — agent document connector and security scan** in [`document_processing/connectors.py`](../../services/agent/document_processing/connectors.py) | `s3:ListAllMyBuckets`, `s3:ListBucket`, `s3:GetObject`, `s3:GetBucketPublicAccessBlock`, `s3:GetEncryptionConfiguration`, `s3:GetBucketVersioning`, `s3:GetBucketLogging`, `s3:GetBucketPolicyStatus` | Customer role and connector-approved bucket ARNs/object prefixes | Connector-selected regional S3 name → gateway when same Region | Existing endpoint is required; cross-Region behavior is an explicit Chunk 2 evidence gate |
| **ECR API / ECR registry — ECS/Fargate platform** for all configured container images | `ecr:GetAuthorizationToken`, `ecr:BatchCheckLayerAvailability`, `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer`; registry pull protocol | Only approved regional repositories/digests supplied by `container_images`; token retrieval necessarily uses `Resource: *` | `api.ecr.<region>.amazonaws.com` and `<account>.dkr.ecr.<region>.amazonaws.com` → private-DNS interface endpoint ENIs on TCP 443; layers then use S3 | Existing `ecr.api` and `ecr.dkr` endpoints plus S3 are required; no NAT for ordinary private-ECR pulls |
| **CloudWatch Logs — ECS `awslogs` driver** for every service, sidecar, audit consumer, and database job | `logs:CreateLogStream`, `logs:PutLogEvents` | `/authclaw/<stack-name>/<service-or-job>` log groups and streams only | `logs.<region>.amazonaws.com` → private-DNS interface endpoint ENIs on TCP 443 | Existing Logs endpoint is required; no NAT |
| **Secrets Manager — ECS/Fargate task bootstrap** for configured task-definition `secrets` | `secretsmanager:GetSecretValue`; `kms:Decrypt` on the regional stack key when needed | The explicit AuthClaw secret ARNs and optional ClickHouse password ARN listed in `aws_iam_role_policy.task_secrets` | `secretsmanager.<region>.amazonaws.com` → private-DNS interface endpoint ENIs on TCP 443 | Existing endpoint is required; no NAT |
| **Secrets Manager — agent `SecretManager`** in [`secret_manager.py`](../../services/agent/services/secret_manager.py), when the AWS backend is enabled | `secretsmanager:GetSecretValue`, `secretsmanager:PutSecretValue`, `secretsmanager:CreateSecret`, `secretsmanager:DeleteSecret` | Tenant/provider secret namespace; create/delete must not be granted to the ECS execution role | Same regional Secrets Manager DNS → interface endpoint | Existing endpoint is required for this supported mode; application task-role policy is missing |
| **KMS — backend envelope provider** in [`crypto.py`](../../backend/app/core/crypto.py), when `AUTHCLAW_SECRET_PROVIDER=aws_kms` | `kms:Decrypt` | Configured AuthClaw KMS key ARN and required encryption context | `kms.<region>.amazonaws.com` → private-DNS interface endpoint ENIs on TCP 443 | Existing KMS endpoint is required; application task-role grant/configuration is missing, and current Terraform selects `env` instead |
| **KMS — agent envelope provider** in [`secret_manager.py`](../../services/agent/services/secret_manager.py), when AWS KMS is enabled | `kms:GenerateDataKey`, `kms:Decrypt` | Configured AuthClaw KMS key ARN, encryption context `authclaw-purpose=provider-credentials` | Same regional KMS DNS → interface endpoint | Existing endpoint is required for this supported mode; application task-role policy is missing |
| **SQS — backend and gateway publishers** in [`audit_transport.py`](../../backend/app/services/audit_transport.py) and [`sqs_fifo.go`](../../gateway/sqs_fifo.go) | `sqs:SendMessage` | Regional AuthClaw audit FIFO queue ARN only | Queue URL host `sqs.<region>.amazonaws.com` → private-DNS interface endpoint ENIs on TCP 443 | Conditional endpoint is correct for `sqs_fifo`; no NAT in that mode |
| **SQS — audit consumer** in [`transport.py`](../../audit_consumer/transport.py) | `sqs:ReceiveMessage`, `sqs:ChangeMessageVisibility`, `sqs:DeleteMessage` | Regional AuthClaw audit FIFO queue ARN only; DLQ is controlled by the queue redrive policy | Same regional SQS DNS → interface endpoint | Conditional endpoint is correct for `sqs_fifo`; no NAT in that mode |
| **STS — backend connector verification** in [`cloud_connectors.py`](../../backend/app/services/cloud_connectors.py) | `sts:GetCallerIdentity` | Supplied connector principal; STS has no resource-level ARN for this action | `sts.<region>.amazonaws.com` → private-DNS interface endpoint | STS endpoint is implemented and regional endpoint mode is forced; live DNS/path proof remains |
| **STS — agent document connector and remediation runtime** in [`document_processing/connectors.py`](../../services/agent/document_processing/connectors.py) and [`remediation_runtime.py`](../../services/agent/services/remediation_runtime.py) | `sts:AssumeRole` | Exact approved customer role ARN(s), external-ID/trust constraints, bounded session name and duration | Regional STS DNS → private-DNS interface endpoint | Endpoint and fail-closed role ARN allowlist are implemented; live assumption/denial proof remains |

AWS documents that Fargate platform 1.4.0 and later requires both ECR interface
endpoints plus the S3 gateway endpoint, and that Fargate `awslogs` without internet
egress requires the Logs endpoint. It also notes a first-pull exception for ECR
pull-through cache rules. See [Amazon ECR interface VPC endpoints](https://docs.aws.amazon.com/AmazonECR/latest/userguide/vpc-endpoints.html).
Private DNS allows unchanged regional SDK hostnames to resolve to interface endpoint
ENIs; AWS recommends endpoint ENIs in at least two Availability Zones. See
[Access AWS services through AWS PrivateLink](https://docs.aws.amazon.com/vpc/latest/privatelink/privatelink-access-aws-services.html).

## Explicit negative decisions

### Kinesis Data Streams — not required

No runtime package creates a Kinesis client, no Kinesis stream ARN or name is passed to
a deployed task, and no task-role policy grants Kinesis actions. Kinesis appears only
as an option in [ADR-0011](../adr/0011-audit-transport-selection.md). That ADR is
`Proposed`, selects SQS FIFO only as the provisional target, and makes Kinesis a future
alternative if retained-stream replay or independent cursor evidence emerges. An
unselected alternative is not sufficient grounds for an endpoint. If the ADR is
revised to select Kinesis, this inventory and the endpoint/IAM design must be revised
before provisioning.

### DynamoDB — not required

There is no runtime DynamoDB client construction, table configuration, table ARN, or
IAM action in the reviewed workload paths. The omission of a DynamoDB gateway endpoint
from Terraform and from [`NAT_DESTINATION_INVENTORY.md`](NAT_DESTINATION_INVENTORY.md)
is therefore intentional. Add it only when a concrete caller, actions, table/index
ARNs, consistency model, and data-owner approval are recorded.

### SQS — conditional, not universally required

ADR-0011 does not authorize production cutover. Terraform defaults to `kafka` and only
creates the SQS queue, endpoint, task roles, and environment when
`audit_stream_transport = "sqs_fifo"`. That is consistent with the ADR. Chunk 2 must
test both endpoint sets: six always-on interface endpoints after adding STS, and seven
when SQS FIFO is selected. No Kinesis endpoint is a valid outcome in either plan.

## Reconciliation with current Terraform and ADR-0011

| Control | Repository state | Chunk 1 judgment |
| --- | --- | --- |
| Private subnets and DNS | Interface endpoints span every private subnet and enable private DNS in [`regional_stack/main.tf`](../../infra/terraform/modules/regional_stack/main.tf) | Correct topology; retain multi-AZ endpoint ENIs |
| Endpoint security group | TCP 443 ingress is limited to `aws_security_group.app`; no public CIDR ingress | Correct source boundary for deployed ECS tasks |
| S3 route coverage | The S3 gateway endpoint is attached to all private route tables | Correct for regional S3 and ECR layer delivery |
| Required interface services | ECR API, ECR registry, Logs, Secrets Manager, KMS, and STS are always present | Implemented; live-path evidence pending |
| Conditional audit endpoint | SQS is added only for `sqs_fifo` | Correct and consistent with proposed ADR-0011 and Kafka rollback |
| Endpoint policies | Explicit policies cover S3 and every interface endpoint | Implemented with TLS denial, execution/application principal separation, scoped stack resources, and fail-closed optional allowlists; AWS denial exercises pending |
| ECS execution IAM | Managed execution policy plus an inline secret/KMS policy | Kept for image pull, logs, and task secret injection; application permissions are not added to it |
| ECS application IAM | Backend, gateway, agent, and audit consumer have separate task roles; optional permissions require exact ARN inputs | Implemented in Terraform; state migration and live allowed/denied calls pending |
| Runtime secret selection | Terraform sets `AUTHCLAW_SECRET_PROVIDER=env`; ECS injects values from Secrets Manager | Direct backend KMS and agent secret-backend calls are supported code paths, not the currently selected deployment mode; endpoint stays required, task grants must follow the approved feature matrix |

The existing SQS task-role actions and queue/KMS resource scopes in
[`sqs_audit.tf`](../../infra/terraform/modules/regional_stack/sqs_audit.tf) match the
confirmed producer and consumer calls. The IAM entries `sqs:GetQueueAttributes` and
`sqs:GetQueueUrl` are not directly called by the current adapters; retain them only if
an SDK/deployment test demonstrates they are necessary.

AWS states that an endpoint without an explicit endpoint policy receives full service
access. See [Amazon ECR endpoint policies](https://docs.aws.amazon.com/AmazonECR/latest/userguide/vpc-endpoints.html)
and [Amazon SQS VPC endpoint policies](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-internetwork-traffic-privacy.html).

## Deployment and operational calls outside the workload VPC

[`deploy-controlled-beta.yml`](../../.github/workflows/deploy-controlled-beta.yml)
uses GitHub OIDC/STS, S3 and KMS for Terraform state, ECR for image promotion, ECS for
service updates, and CloudWatch for alarm checks. Those calls originate on a
GitHub-hosted runner and do not traverse these VPC endpoints. The same applies to
operator Terraform/CLI calls unless a runner is deliberately placed in the VPC.

Two adjacent runtime AWS APIs still require an approved path and prevent a blanket
claim that NAT is unnecessary:

| Caller | Call | Current path decision |
| --- | --- | --- |
| Backend AWS status endpoint in [`endpoints/aws.py`](../../backend/app/api/v1/endpoints/aws.py) | `bedrock:ListFoundationModels` when Bedrock is enabled | Not covered by current endpoints; use a separately designed Bedrock endpoint or an approved NAT destination |
| Backend customer connector in [`cloud_connectors.py`](../../backend/app/services/cloud_connectors.py) | `iam:GetAccountSummary`, `iam:ListUsers` | Not covered by the P0-08 endpoint set; keep an approved NAT/private path and record it in the destination inventory |

NAT also remains necessary for enabled public model providers, SES SMTP, public
GitHub/GCP/Azure connectors, and any externally hosted Kafka or ClickHouse endpoint,
as tracked in [`NAT_DESTINATION_INVENTORY.md`](NAT_DESTINATION_INVENTORY.md). P0-08
removes NAT as a dependency only for the explicitly covered regional AWS paths.

## Chunk 2 entry gates

Chunk 2 may begin only when all of the following are recorded in the change review:

1. Architecture, Security, and the runtime owners approve this caller/action/resource
   inventory, including the decision to add STS and not add Kinesis or DynamoDB.
2. Each target environment records Region, enabled runtime features, audit transport,
   S3 bucket Regions, approved customer role ARNs, and whether Bedrock/IAM connector
   calls are supported in that environment.
3. The owner chooses one production IAM outcome for each optional direct runtime path:
   create a dedicated least-privilege task role or disable and fail closed on that
   feature. Static long-lived AWS credentials are not an accepted production outcome.
4. The NAT destination inventory has an owner and an evidence location for all public
   destinations that remain after private endpoint routing.
5. A rollback owner and maintenance window are named; rollback is limited to reverting
   endpoint/IAM configuration and restoring the previous task definition, not deleting
   NAT infrastructure.

## Chunk 2 implementation and acceptance gates

Chunk 2 is complete only when all of the following pass:

1. Terraform adds the regional STS interface endpoint, keeps SQS conditional, and adds
   neither Kinesis nor DynamoDB.
2. Explicit least-privilege policies are attached to S3, ECR API/registry, Logs,
   Secrets Manager, KMS, STS, and conditional SQS endpoints. Policies allow only the
   approved principals, actions, resources, and Regions from this inventory.
3. Dedicated task-role policies match enabled application calls; the ECS execution role
   remains limited to image pull, log delivery, and task-definition secret injection.
4. Terraform tests prove: S3 attaches to every private route table; each interface
   endpoint spans all required AZs; private DNS is enabled; endpoint ingress is only
   TCP 443 from application tasks; default mode has exactly six interface services;
   SQS mode has exactly seven; Kinesis and DynamoDB are absent.
5. `terraform fmt -check`, `terraform validate`, Terraform tests, policy linting, and a
   reviewed state-backed plan pass without replacing the existing NAT gateways, EIPs,
   VPC, subnets, or route tables.
6. In non-production, DNS evidence shows each standard regional hostname resolving to
   the intended private endpoint (or the S3 gateway route), including explicit regional
   STS behavior.
7. With NAT routes made unavailable under an approved reversible exercise, new tasks
   pull images, retrieve injected secrets, start logging, perform direct KMS/Secrets
   calls for enabled modes, assume a test role through STS, access same-Region S3, and
   publish/consume SQS when selected.
8. VPC Flow Logs and service logs show no NAT dependency for covered calls and no
   unexplained public AWS destination. Cross-Region S3 and every adjacent/public path
   are either privately routed, explicitly approved for NAT, or disabled fail-closed.
9. Endpoint-policy denial tests prove that an out-of-scope repository, log group,
   secret, key, queue, role, and S3 bucket/key are rejected without disrupting allowed
   operations.
10. Rollback is rehearsed, evidence is attached to the change, and Security and
    Platform owners approve promotion to the next P0-08 chunk.

AWS supports `com.amazonaws.<region>.sts` through PrivateLink and recommends regional
STS endpoints; see [AWS services that integrate with PrivateLink](https://docs.aws.amazon.com/vpc/latest/privatelink/aws-services-privatelink-support.html)
and [AWS STS Regions and endpoints](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_region-endpoints.html).
KMS interface endpoints can carry all KMS API operations without NAT; see
[Connect to AWS KMS through a VPC endpoint](https://docs.aws.amazon.com/kms/latest/developerguide/kms-vpc-endpoint.html).

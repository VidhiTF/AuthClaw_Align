# AuthClaw Pre-AWS Deployment Task List

## Purpose

This is the implementation and decision backlog that must be completed before an AWS production deployment. It is based on the current repository, not only on the architecture-plan document.

Gateway latency benchmarking is intentionally excluded because it is tracked separately. Functional, security, migration, recovery, and capacity evidence are still required before production.

## Repository-Grounded Corrections

| Topic | Current repository state | Required conclusion |
| --- | --- | --- |
| Audit transport | Gateway, backend, agent, audit consumer, Compose, and Terraform are Kafka/MSK-specific. PostgreSQL is the authoritative audit chain and ClickHouse is a rebuildable mirror. | Do not automatically replace Kafka with Kinesis. Decide between SQS FIFO and Kinesis from measured requirements; SQS FIFO is the simpler fit unless retained-stream replay or throughput proves otherwise. |
| Audit replay | ClickHouse can be rebuilt from PostgreSQL; no business workflow consumes Kafka replayed history. Ordering is tenant-scoped. | Kafka retention is not required for evidence recovery. Preserve PostgreSQL replay and tenant ordering during any transport change. |
| PostgreSQL | Terraform provisions the main RDS instance and a separate agent RDS instance. | Consolidation is real infrastructure and data-migration work, not only a connection-string change. |
| Graviton | ECS task definitions are Fargate and do not set `runtime_platform`. CI builds ordinary single-platform images. | ARM64 images and task configuration are required. Moving to ECS on EC2 is a separate decision; ARM64 and multi-container tasks can run on Fargate. |
| Gateway, OPA, Presidio | They are three separate ECS services connected through service discovery. | Co-location requires a combined task definition, localhost endpoints, health dependencies, resource allocation, and removal of unnecessary exposure/discovery. |
| ECR retention | Terraform already creates immutable, KMS-encrypted repositories with scan-on-push and a lifecycle policy retaining 30 images. | The document's “no lifecycle policy” statement is outdated. Modify retention only after protecting deployed and rollback releases. |
| Networking | Each regional stack has one NAT Gateway and no VPC endpoints. | Add endpoints based on actual AWS-service destinations. Decide whether production requires one NAT per Availability Zone. |
| Container security | CI scans images and deployment uses digests, but task definitions use one shared execution role and omit several runtime hardening controls. | Add per-service permissions, runtime hardening, SBOMs, signing, and deploy-time verification. |
| Observability | Terraform creates log groups, unhealthy-target alarms, and ECS CPU alarms. | Memory, task-count, database, Redis, queue/audit, NAT, application-error, and rollback signals remain. |

## Target Deployment Decisions

The following decisions must be recorded before implementation branches diverge.

### ADR-1: Choose the production audit transport

**Recommended default:** replace production Kafka/MSK with SQS FIFO, not Kinesis, if the measured event rate fits SQS FIFO and PostgreSQL remains the replay source.

Why this matches the repository:

- PostgreSQL `audit_log_metadata` and `audit_outbox` are authoritative.
- ClickHouse is a derived mirror and can be replayed from PostgreSQL.
- Required ordering is within a tenant, not across tenants.
- SQS FIFO can use `tenant_id` as `MessageGroupId`.
- The stable audit record ID can be used as `MessageDeduplicationId`.
- A redrive policy and DLQ satisfy the failed-event path without operating brokers, topics, partitions, or consumer groups.

Choose Kinesis instead only if one of these requirements is demonstrated:

- Consumers must independently replay retained stream history rather than replaying PostgreSQL.
- The measured event rate or payload pattern exceeds the approved SQS FIFO design.
- Multiple independent real-time consumers need stream cursors and retention.
- Shard-level stream processing is an explicit product requirement.

The ADR must record event rate, event size, ordering scope, replay source, consumer count, retention, failure handling, cost, and operational ownership.

### ADR-2: Choose the compute launch model

**Recommended rollout:** use ARM64 Fargate first, then move to an EC2 Graviton capacity provider only if cost, host tuning, or placement-control evidence justifies the extra operations.

ARM64 does not itself require ECS on EC2. Co-locating gateway, OPA, and Presidio in one task also works on Fargate. If ECS on EC2 remains the approved target, the backlog must include the Auto Scaling group, launch template, capacity provider, instance patching, draining, scaling, and recovery work listed below.

### ADR-3: Confirm the database isolation model

Use one RDS PostgreSQL instance with separate backend and agent ownership. Prefer separate databases when the two migration systems must remain independent; use separate schemas only if cross-database operational needs make that necessary. In either model:

- Use separate login roles and secrets.
- Do not grant the agent access to backend-owned objects.
- Preserve backend row-level-security enforcement.
- Keep the agent's historical integer tenant model outside the canonical ACL-21 audit chain unless a separately approved identity migration is performed.

### ADR-4: Confirm regional and recovery scope

The Terraform root can create a primary regional stack and a secondary regional stack with an RDS read replica. Before deployment, decide:

- Staging and production regions.
- Single-region versus warm-standby production.
- RPO and RTO.
- Whether failover DNS is enabled.
- Who promotes the RDS replica and who declares failback.
- Whether ClickHouse and the chosen audit transport are regional, replicated, or rebuilt after failover.

## Required Work

### P0-01 — Freeze environment, account, and state boundaries

**What needs to be done**

- Use separate staging and production AWS accounts, or document and enforce an equivalent isolation boundary.
- Create separate Terraform state keys and variable sets for each environment.
- Provision the remote state bucket, encryption key, locking mechanism, versioning, access logging, and recovery policy before applying the application stack.
- Configure GitHub Actions to assume a narrowly scoped AWS role through OIDC; do not store long-lived AWS keys.
- Restrict production applies to an approved protected environment and branch.
- Record region, account ID, state key, deployment role ARN, domain, and certificate ARN without recording secret values.

**Done when**

- A read-only plan proves staging cannot modify production resources.
- State recovery and access are tested.
- The deployment workflow uses short-lived role credentials.

### P0-02 — Implement the chosen audit transport

**Current code affected**

- `gateway/kafka.go` and gateway audit publication.
- `backend/app/services/event_backbone.py` and all backend producers.
- `services/agent/services/event_pipeline.py`.
- `audit_consumer/consumer.py`.
- `docker-compose.yml` and `infra/kafka/topics.yaml`.
- Terraform Kafka variables, environment variables, task permissions, alarms, and documentation.

**Common work for either SQS FIFO or Kinesis**

- Define one transport-neutral `AuditEvent` contract and version it.
- Keep PostgreSQL append plus outbox insertion in one transaction.
- Publish only committed outbox records.
- Use `tenant_id` as the ordering key.
- Use the immutable audit record ID as the deduplication/idempotency key.
- Make ClickHouse writes idempotent by event ID and tenant sequence.
- Do not mark an outbox row published until the transport accepts it.
- Preserve retry, poison-message, DLQ, and metrics behaviour.
- Preserve the no-stream local-development fallback.
- Add a transport adapter so business services do not import Kafka, SQS, or Kinesis clients directly.

**If SQS FIFO is selected**

- Create the FIFO queue and FIFO DLQ in Terraform.
- Set `MessageGroupId=tenant_id` and `MessageDeduplicationId=audit_record_id` explicitly.
- Configure visibility timeout longer than worst-case processing time.
- Configure redrive count and retention.
- Add least-privilege send, receive, delete, visibility-change, and queue-attribute permissions to the correct service roles.
- Replace the Kafka consumer loop with long polling and delete only after a successful ClickHouse write.
- Alarm on DLQ messages, oldest message age, visible backlog, processing failures, and PostgreSQL outbox age.

**If Kinesis is selected**

- Create the stream, encryption, retention, capacity mode, consumer, DLQ/failure sink, IAM, and alarms in Terraform.
- Use `tenant_id` as the partition key.
- Store and monitor checkpoints.
- Handle partial batch failures without skipping records.
- Define how poison records leave the shard-blocking path.
- Prove resharding does not violate the required tenant sequence handling.

**Migration and removal**

- Run the new publisher in shadow mode using non-authoritative test events or a controlled duplicate sink.
- Compare the new sink with PostgreSQL event IDs and tenant sequences.
- Cut consumers over before removing Kafka infrastructure.
- Drain all Kafka offsets/outbox backlog and reconcile counts.
- Remove Kafka libraries, environment variables, topics, MSK instructions, and runbooks only after rollback retention expires.
- Keep the old deployment digest and transport configuration available for the agreed rollback window.

**Done when**

- Every committed outbox row reaches ClickHouse exactly once logically, despite retries.
- Tenant sequence has no unexplained gaps or reordering.
- DLQ handling and PostgreSQL-to-ClickHouse replay are demonstrated.
- The ACL-21 chain verifier produces the same result before and after migration.

### P0-03 — Consolidate PostgreSQL safely

**What needs to be done**

- Select separate databases or schemas inside one RDS instance.
- Create separate backend and agent roles, ownership, connection secrets, and default privileges.
- Update Terraform so `agent_database_url` points to the shared RDS endpoint but the agent-owned database/schema and role.
- Reconcile the backend Alembic migrations with the agent's custom migration system without giving either system ownership of the other's objects.
- Inventory agent data volume, extensions, sequences, constraints, and integer tenant references.
- Create a repeatable agent data export/import or replication procedure.
- Rehearse migration using a production-shaped snapshot in non-production.
- Validate record counts, checksums, constraints, indexes, and application smoke paths.
- Test pool reuse directly: tenant A connection, return to pool, tenant B acquisition, then prove tenant A rows are invisible.
- Verify session tenant variables are set and reset on every checkout/check-in path.
- Test backup, point-in-time recovery, RDS snapshot restore, and cross-region recovery.
- Keep the separate agent RDS instance read-only and recoverable during the rollback window.
- Remove `aws_db_instance.agent` only after verification and rollback expiry.

**Done when**

- Both services run concurrently against one RDS instance using different roles.
- Neither role can read or mutate the other's owned data.
- Migration validation and pool/RLS isolation evidence pass.
- Restore and rollback drills meet the agreed RPO/RTO.

### P0-04 — Make every runtime image ARM64-ready

**What needs to be done**

- Preserve the completed Python wheel compatibility audit as release evidence.
- Verify every base image and external image, including OPA and Presidio, has the required ARM64 manifest.
- Build backend, agent, gateway, console, audit consumer, and OPA bundle for `linux/arm64`; use multi-architecture images where rollback to x86 is required.
- Compile and test the Go gateway for `linux/arm64`.
- Run Python import/startup smoke tests inside the ARM64 backend and agent images.
- Add an ARM64 CI build and smoke-test lane.
- Publish manifest lists and record per-platform digests.
- Add ECS `runtime_platform` with `cpu_architecture = "ARM64"` and Linux OS family.
- Deploy one non-production service at a time and retain the x86 task definition for rollback.

**Done when**

- Every production image resolves to an ARM64 manifest and starts successfully on the chosen ECS launch type.
- CI blocks an image that lacks ARM64 support.
- Rollback to the previous x86 digest/task definition is documented and tested.

### P0-05 — Decide and, if approved, implement ECS on EC2 Graviton

This task is required only if ADR-2 chooses ECS on EC2. It is not required merely to run ARM64.

**What needs to be done**

- Add an ARM64 ECS-optimized launch template.
- Add a private-subnet Auto Scaling group across the required Availability Zones.
- Add the ECS capacity provider, managed scaling, and managed termination protection.
- Associate capacity-provider strategies with services.
- Set instance minimum, desired, and maximum capacity from measured reservations plus failure headroom.
- Configure instance IAM, Systems Manager access, logging, patching, AMI refresh, disk encryption, IMDSv2, and no public IP.
- Configure task draining and prevent scale-in from killing insufficiently replicated services.
- Decide whether an x86 capacity provider remains temporarily available.
- Add cluster-capacity, pending-task, instance-health, and placement-failure alarms.
- Rehearse loss and replacement of one container instance.

**Done when**

- Tasks place successfully after an Availability Zone or instance failure.
- Scale-out, scale-in, draining, patching, and AMI replacement are demonstrated.
- The team accepts ownership of the additional host-operating burden.

### P0-06 — Co-locate gateway, OPA, and Presidio

**What needs to be done**

- Replace the three separate task definitions/services with one task containing three containers.
- Route gateway calls to `http://127.0.0.1:8181` for OPA and `http://127.0.0.1:3000` for Presidio.
- Expose only the gateway port through the load balancer.
- Remove OPA and Presidio from service discovery after cutover.
- Remove their security-group ingress rules and target groups if present.
- Add container-level health checks and startup dependencies.
- Decide failure semantics: whether unhealthy OPA or Presidio makes the entire task unhealthy, and whether the gateway must fail closed.
- Allocate task-level and container-level CPU/memory so one sidecar cannot starve the gateway.
- Verify from another task that OPA and Presidio cannot be reached.
- Update the existing production Terraform precondition that currently expects internal HTTPS service-discovery URLs; localhost HTTP inside one task is a different trust boundary.
- Retain the three-service task definitions for rollback during the agreed window.

**Done when**

- Only the gateway is externally reachable.
- Policy and redaction requests work over loopback.
- OPA/Presidio failure produces the approved fail-closed behaviour.
- Scaling and rollback operate at the combined-task level.

### P0-07 — Fix public ingress and environment URL boundaries

**Current risk**

Terraform currently treats console, backend, and gateway as public ALB services on separate listener ports. Production routing, origin restriction, and the final public URL model must be resolved before launch.

**What needs to be done**

- Finalize the Route 53, ACM, CloudFront/WAF, ALB, and public-path design from ADR 0002.
- Use one documented public entry model and remove accidental alternate origins.
- Restrict ALB ingress to the approved edge path where CloudFront/WAF is used.
- Do not expose internal agent, OPA, Presidio, database, Redis, ClickHouse, or queue endpoints.
- Set production CORS allowlists, cookie domains, secure attributes, callback URLs, public console URL, backend API URL, and gateway URL from the approved domains.
- Prove direct-origin denial, TLS validity, redirect behaviour, health routes, and tenant-safe authentication.
- Enable ALB/edge access logs with redaction and retention.

**Done when**

- There is no undocumented public port or origin.
- Staging and production URLs, cookies, OAuth callbacks, and certificates are isolated.
- Origin-denial and WAF evidence are attached to the release.

### P0-08 — Add private AWS-service network paths

**What needs to be done**

- Inventory actual runtime calls to AWS services before creating endpoints.
- Add an S3 gateway endpoint for workloads that use S3 and for the chosen ECR pull design.
- Add interface endpoints as required for ECR API, ECR registry, CloudWatch Logs, Secrets Manager, and KMS.
- Add SQS or Kinesis endpoints if the selected transport and cost/resilience model require them.
- Add an STS endpoint if runtime role-assumption uses it.
- Do not add a DynamoDB endpoint unless a runtime dependency is confirmed; the current core stack does not establish that requirement.
- Create endpoint security groups and least-privilege endpoint policies.
- Update private route tables and private DNS settings.
- Verify image pulls, secret retrieval, logs, KMS operations, and audit transport with NAT temporarily unavailable in staging.
- Keep NAT only for real public destinations such as model providers and customer integrations.

**Done when**

- AWS-service traffic uses the intended private endpoints.
- NAT failure does not break the covered AWS control/data paths.
- The endpoint inventory and remaining public egress destinations are recorded.

### P0-09 — Decide production NAT resiliency and egress control

**What needs to be done**

- Record the current one-NAT-per-regional-stack topology.
- Decide whether production requires a NAT Gateway per Availability Zone; if yes, create per-AZ public route tables and route each private subnet to its same-AZ NAT.
- Keep a single NAT in lower environments if the accepted availability/cost tradeoff allows it.
- Restrict task egress by destination/security group where practical instead of allowing every task unrestricted `0.0.0.0/0` access.
- Record public model-provider and customer-integration destinations that cannot use VPC endpoints.
- Add NAT error, port-allocation, byte-count, and cost monitoring.

**Done when**

- NAT failure behaviour matches the environment's availability target.
- Every remaining NAT dependency is intentional and documented.

### P0-10 — Separate IAM execution and task permissions

**Current risk**

The regional Terraform uses one shared task execution role and its inline policy can read many service secrets. Application task roles are not defined per service.

**What needs to be done**

- Keep the execution role limited to image pull, log delivery, and only the secrets injected for that task.
- Create separate task roles for backend, agent, gateway, audit consumer, and any other AWS-calling workload.
- Scope secret ARNs and KMS decrypt permissions per service.
- Scope S3, SQS/Kinesis, ClickHouse connectivity, STS, and customer-cloud operations to the minimum actions/resources.
- Add permission boundaries and explicit denies where the organization requires them.
- Ensure the console, OPA, and Presidio have no AWS permissions unless a concrete call requires them.
- Add IAM policy validation and access-analyzer review to the release evidence.

**Done when**

- Compromise of one task role does not grant access to another service's database secret or unrelated AWS resources.
- Every granted action maps to a repository runtime call or documented operational requirement.

### P0-11 — Complete secrets and key management

**What needs to be done**

- Inventory JWT, session, envelope, agent encryption, redaction, internal-service, database, provider, email, ClickHouse, and signing secrets.
- Define ownership, rotation interval, active/previous version behaviour, and emergency rotation procedure.
- Stop Terraform from managing secret values that must be supplied by a secure external process where exposure through state is unacceptable.
- Verify tasks receive secrets at runtime and no image layer, build argument, log, plan output, or repository file contains a value.
- Test JWT/session/envelope dual-key rotation using the existing v1/v2 configuration.
- Separate staging and production keys and secrets.
- Configure KMS key policies, rotation, deletion protection, and break-glass access.

**Done when**

- Rotation and rollback are tested without invalidating required sessions or encrypted data unexpectedly.
- A secret inventory exists without containing secret values.

### P0-12 — Harden images and ECS task definitions

**Build controls**

- Pin base images by digest.
- Use multi-stage builds and minimal runtime images.
- Run every application as a non-root user.
- Generate an SBOM for every platform image.
- Scan filesystem, dependencies, configuration, secrets, and final images.
- Define vulnerability severity and exception-expiry policy.
- Sign promoted image digests and verify signatures before Terraform deployment.
- Stamp commit/release metadata and report image-size change.

**Runtime controls**

- Reference images only by digest in controlled environments.
- Set read-only root filesystems where supported.
- Mount explicit writable paths only where required.
- Drop all Linux capabilities unless a reviewed exception exists.
- Disable privilege escalation and privileged mode.
- Set container health checks, stop timeouts, log limits, and resource limits.
- Create a per-service task role.
- Enable ECS Exec only through audited break-glass access, or leave it disabled.

**Done when**

- CI produces scan, SBOM, provenance/signature, per-platform digest, and image-size evidence.
- Deployment rejects unsigned, unscanned, mutable, or wrong-architecture images.
- Runtime hardening exceptions are explicit and reviewed.

### P0-13 — Make ECR retention rollback-safe

**What needs to be done**

- Inventory all deployed task-definition digests in staging and production.
- Record the immediate rollback digest and the agreed deeper rollback set per repository.
- Introduce protected release/rollback tag prefixes that lifecycle rules do not expire.
- Keep untagged-image expiration separate from tagged-release retention.
- Simulate the lifecycle policy against the real inventory before applying it.
- Decide whether 30 retained images remains appropriate; do not reduce to ten until protected digests and release frequency prove ten is safe.
- Add a deployment step that tags/protects the new and previous digests atomically with promotion records.
- Remove protection only after the rollback window and database compatibility window close.

**Done when**

- No lifecycle rule can remove a currently deployed or approved rollback digest.
- A rollback drill succeeds using a retained prior digest.

### P0-14 — Add service scaling and availability controls

**What needs to be done**

- Set minimum production task counts so a single task or Availability Zone failure does not remove the service.
- Add ECS service auto-scaling using CPU, memory, ALB request count, or queue backlog as appropriate.
- Configure deployment minimum/maximum healthy percentages, circuit breaker, and automatic rollback.
- Add graceful shutdown and connection draining.
- Set database, Redis, and queue client timeouts, retries, and bounded backoff.
- Size RDS connections against the combined backend and agent pool limits.
- Add RDS Proxy only if measured connection behaviour justifies it; if used, re-run tenant-session/RLS isolation tests.
- Configure Redis failover and verify the application behaviour during failover.
- If ECS on EC2 is chosen, reserve enough instance capacity for an instance/AZ failure.

**Done when**

- Task, Availability Zone, Redis primary, and connection-pool failure drills meet recovery thresholds.
- Scaling cannot exceed database or downstream capacity.

### P0-15 — Complete observability, alerting, and log hygiene

**What needs to be done**

- Add dashboards for task desired/running/pending count, CPU, memory, restarts, deployment state, ALB target health, HTTP errors, and response time.
- Add RDS CPU, memory, storage, connections, locks, slow queries, replica lag, backup, and failover signals.
- Add Redis memory, eviction, connection, replication, and failover signals.
- Add transport backlog/age, delivery failures, retries, DLQ depth, and consumer processing failures.
- Add PostgreSQL audit outbox depth/oldest age, tenant-sequence gaps, ClickHouse drift, replay failures, and chain-verification failures.
- Add NAT bytes/errors/port allocation and VPC endpoint failure signals.
- Correlate logs with environment, service, release digest, tenant-safe request ID, and trace ID.
- Redact tokens, credentials, provider payloads, PII, PHI, and document contents from logs.
- Define retention, access, alert routing, acknowledgement, and escalation ownership.
- Test every critical alarm before production.

**Done when**

- Operators can identify the failing release, service, tenant-safe trace, and recovery action without accessing sensitive payloads.
- Critical alarm tests reach the real on-call destination.

### P0-16 — Define the migration and release sequence

Do not combine transport replacement, PostgreSQL consolidation, co-location, and compute migration in one release.

**Required sequence**

1. Freeze decisions and capture current configuration/evidence.
2. Complete CI supply-chain controls and rollback-digest protection.
3. Establish staging AWS foundation, identity, state, network, edge, secrets, and observability.
4. Deploy the existing architecture to staging using immutable digests.
5. Introduce the transport abstraction without changing transport.
6. Migrate Kafka to the selected transport and verify/reconcile it.
7. Co-locate gateway, OPA, and Presidio on the current launch type.
8. Publish and canary ARM64 images on Fargate.
9. Consolidate PostgreSQL in staging and complete data/isolation/recovery verification.
10. Move to ECS on EC2 Graviton only if ADR-2 still requires it.
11. Run staging security, failover, recovery, and rollback drills.
12. Promote the exact tested digests and configuration to production.

Each step must have its own rollback point. Database migrations must use expand/contract compatibility so the previous application digest can still run during the rollback window.

### P0-17 — Create production deployment and rollback runbooks

**What needs to be done**

- Define pre-deployment checks, approvers, change window, and communication channel.
- Record current and target task-definition revisions and image digests.
- Run database migrations as an explicit one-off task and block service rollout on failure.
- Enable ECS deployment circuit breaker and health-based rollback.
- Define rollback for application images, task configuration, transport, database schema/data, DNS/edge, secrets, and regional failover.
- State which migrations are irreversible and how old application versions are fenced from incompatible schemas.
- Define stop conditions and who has authority to invoke rollback.
- Drill rollback by redeploying a previous digest and verifying health, authentication, gateway, audit publication, and ClickHouse consistency.

**Done when**

- Another qualified engineer can execute the deploy and rollback from the runbook without undocumented knowledge.
- The rollback drill uses real retained artifacts and meets the threshold.

### P0-18 — Complete non-performance validation

Gateway performance benchmarking is outside this task list, but the following validation is still required:

- Full repository CI passes for the release commit.
- Terraform format, validation, static security scan, and reviewed plans pass.
- ARM64 image startup and health checks pass.
- Authentication, authorization, CORS, cookies, OAuth callbacks, tenant isolation, and fail-closed paths pass.
- Audit append, outbox, selected transport, DLQ, ClickHouse projection, export, replay, and chain verification pass.
- Database migration, pool/RLS isolation, backup, restore, and rollback pass.
- Task failure, Availability Zone failure, queue failure, Redis failover, and database failover drills pass as applicable.
- Direct-origin denial, internal-port isolation, IAM least privilege, secret rotation, and log-redaction checks pass.
- Deployed and rollback digests remain protected in ECR.

**Done when**

- A single release-evidence package links every check to raw output, environment, commit, image digest, time, and approver.

## P1 Work That Should Be Completed Before General Availability

These items may follow an explicitly limited internal/staging deployment, but should not be silently deferred for customer production.

### P1-01 — Cost governance

- Apply complete owner, environment, service, data-classification, and cost-center tags.
- Create budgets and anomaly alerts.
- Estimate and then measure NAT, endpoints, RDS, Redis, ECS, ECR, logs, transport, and cross-region costs.
- Define log, snapshot, audit mirror, and image retention from compliance requirements rather than defaults.

### P1-02 — Disaster recovery and regional failover

- Validate RDS replica promotion and application write recovery.
- Decide how Redis, SQS/Kinesis, ClickHouse, secrets, and image access behave in the secondary region.
- Verify DNS failover and TTL assumptions.
- Run a full regional exercise and record actual RPO/RTO.
- Define failback, reconciliation, and split-brain prevention.

### P1-03 — Operational ownership and support

- Assign owners for infrastructure, application, database, audit pipeline, security, and incident command.
- Document access request and break-glass procedures.
- Create incident runbooks for database outage, audit backlog/DLQ, bad deployment, secret compromise, provider outage, and regional failure.
- Define maintenance, patching, dependency updates, vulnerability exceptions, and certificate renewal ownership.

## Explicitly Not Required or Not Yet Proven

- **Do not build Kinesis merely because Kafka is being removed.** Select it only if retained-stream replay or measured throughput requires it.
- **Do not move to ECS on EC2 merely to obtain ARM64 or localhost sidecars.** Fargate supports both; EC2 must have a separate operational/cost justification.
- **Do not create a DynamoDB endpoint without a confirmed runtime dependency.**
- **Do not reduce ECR retention to ten releases before deployed and rollback digests are protected.**
- **Do not merge backend and agent tables under one unrestricted role.** One PostgreSQL instance still requires ownership isolation.
- **Do not combine the event-transport, database, co-location, and compute cutovers.** Separate releases are necessary for diagnosis and rollback.
- **Do not treat local NAT estimates, local image IDs, or local CPU/memory as production evidence.**

## Production Go/No-Go Checklist

- [ ] Audit-transport ADR approved and selected transport implemented.
- [ ] Transport cutover, DLQ, idempotency, tenant ordering, and PostgreSQL replay verified.
- [ ] One-RDS topology migrated and pool/RLS tenant isolation proved.
- [ ] Every production image supports ARM64 and the target task architecture is explicit.
- [ ] Compute launch model ADR approved; EC2 operational work complete if selected.
- [ ] Gateway, OPA, and Presidio co-located and internal ports unreachable.
- [ ] Public ingress, DNS, TLS, CORS, cookies, callbacks, WAF, and origin restriction approved.
- [ ] Required VPC endpoints work and remaining NAT dependencies are documented.
- [ ] Production NAT availability model approved.
- [ ] Per-service IAM roles and secret/KMS boundaries verified.
- [ ] Images are immutable, scanned, SBOM-attached, signed, and verified before deployment.
- [ ] Deployed and rollback digests are protected from lifecycle deletion.
- [ ] ECS, RDS, Redis, transport, audit, NAT, and application alarms are tested.
- [ ] Auto-scaling and downstream capacity limits are configured.
- [ ] Backup, restore, failover, and rollback drills meet agreed thresholds.
- [ ] Staging has run the exact production-bound digests and configuration.
- [ ] Release evidence identifies commit, images, environment, raw results, approvers, and rollback point.
- [ ] Separate performance benchmark gate has passed.

## Repository Evidence Used

- `docker-compose.yml`: local PostgreSQL, Kafka/Redpanda, ClickHouse, OPA, Presidio, and audit-consumer topology.
- `gateway/kafka.go` and `gateway/audit.go`: Kafka-specific publisher, tenant-keyed messages, fallback, and outbox publication.
- `backend/app/services/event_backbone.py`: Kafka-specific backend publisher and stable audit event identifiers.
- `services/agent/services/event_pipeline.py`: Kafka REST-specific agent event path.
- `audit_consumer/consumer.py`: Kafka consumer groups, offsets, lag, DLQ, and ClickHouse projection.
- `backend/app/db/models.py`, `docs/adr/0009-acl-21-immutable-audit-evidence.md`, and `docs/runbooks/ACL_21_AUDIT_EVIDENCE.md`: PostgreSQL authority, outbox, tenant sequence, ClickHouse replay, and recovery semantics.
- `infra/terraform/modules/regional_stack/main.tf`: Fargate services, separate OPA/Presidio discovery, separate agent RDS, one NAT per region, shared execution role, current alarms, and missing VPC endpoints/ARM64 runtime platform.
- `infra/terraform/registry.tf`: immutable KMS-encrypted repositories, scan-on-push, and existing 30-image lifecycle policy.
- `.github/workflows/ci.yml`: current tests, image builds, and vulnerability scans.
- `.github/workflows/deploy-controlled-beta.yml`: digest-based ECR promotion and controlled-beta Terraform deployment.
- `docs/adr/0002-aws-url-environment-boundary.md`: intended public edge, environment isolation, deployment, and rollback boundary.

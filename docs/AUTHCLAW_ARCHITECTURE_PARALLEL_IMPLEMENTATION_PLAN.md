# AuthClaw Architecture Parallel Implementation Plan

## Objective

Move AuthClaw toward the verified target architecture while allowing three engineers to work safely in parallel.

The target includes:

- One PostgreSQL instance shared by the backend and agent, with separate schemas or databases and separate roles.
- ARM64 images running on an ECS EC2 Graviton capacity provider.
- Gateway, OPA, and Presidio co-located in one ECS task.
- AWS service traffic routed through appropriate VPC endpoints.
- Safe ECR lifecycle management that protects deployed and rollback images.
- Measured performance, tenant isolation, audit recovery, and container hardening.

Architecture changes must be released separately so that failures can be attributed to one change and rolled back safely.

## Engineer Ownership

| Engineer | Primary ownership | Main deliverables |
| --- | --- | --- |
| Engineer 1 — Platform | AWS, Terraform, CI/CD, and container supply chain | ARM64 builds, Graviton capacity provider, VPC endpoints, safe ECR retention, and container hardening |
| Engineer 2 — Data | Shared PostgreSQL migration and audit guarantees | Database consolidation, schemas and roles, data migration, tenant-isolation tests, and audit ordering/replay validation |
| Engineer 3 — Runtime | Gateway, OPA, Presidio, and performance | Co-located task, localhost communication, port isolation, resource sizing, and latency benchmarks |

Engineer 1 owns shared Terraform and deployment workflow files. Engineers 2 and 3 provide their infrastructure requirements to Engineer 1 instead of all three engineers editing the regional Terraform stack simultaneously.

## Phase 1: Establish the Baseline

Before changing the architecture, record:

- Gateway p50, p95, and p99 latency for plain, redacted, and streaming requests.
- CPU p95 and peak usage for every service.
- Memory p95 and peak usage for every service.
- Audit events per second, average event size, and consumer lag.
- Current container image sizes.
- NAT traffic and cost.
- PostgreSQL sizes, migration versions, connection counts, and pool configuration.
- Currently deployed and rollback image digests.

Each engineer records the baseline for their area. These measurements become the acceptance and rollback thresholds.

Production migration must not begin without this baseline.

## Phase 2: Parallel Implementation

### Engineer 1: ARM64, Infrastructure, and Registry

Engineer 1 can prepare the compute and network foundation independently in non-production.

#### Work

1. Update CI to build ARM64 or multi-architecture images.
2. Run backend and agent dependency installation during real ARM64 image builds.
3. Add an ECS EC2 Graviton capacity provider:
   - ARM64 launch template.
   - Auto Scaling Group.
   - ECS capacity provider.
   - Managed scaling configuration.
   - ARM64 task runtime configuration.
4. Keep the existing Fargate deployment path available for rollback.
5. Add VPC endpoints for:
   - S3.
   - DynamoDB.
   - ECR API.
   - ECR Docker registry.
   - CloudWatch Logs.
   - Secrets Manager.
   - KMS.
6. Protect currently deployed and rollback digests before reducing ECR retention.
7. Add SBOM generation, image signing, and deployment-time signature verification.
8. Add read-only filesystems, dropped Linux capabilities, and per-service task roles where supported.

#### Acceptance Criteria

- ARM64 images build successfully.
- Containers start and pass health checks on Graviton.
- Fargate remains a tested rollback option.
- VPC endpoints do not break image pulls, secrets, logs, or application startup.
- Lifecycle cleanup cannot delete deployed or rollback images.
- Signed images are verified before deployment.

### Engineer 2: One PostgreSQL Instance for Backend and Agent

The required target is one PostgreSQL instance with isolated service ownership:

```text
One PostgreSQL instance
├── Backend database or schema
│   └── Dedicated backend role
└── Agent database or schema
    └── Dedicated agent role
```

Sharing an instance does not mean sharing tables, credentials, or unrestricted permissions.

#### Work

1. Inventory both migration histories, extensions, table names, sequences, roles, and permissions.
2. Decide between:
   - Separate databases inside one PostgreSQL instance; or
   - Separate schemas inside one database.
3. Prefer separate databases inside one instance unless the application requires cross-schema queries. This provides simpler isolation while still meeting the one-instance target.
4. Provision the shared instance in non-production.
5. Create dedicated backend and agent roles with least-privilege permissions.
6. Run both migration sets from an empty state.
7. Copy representative data from both current databases.
8. Validate:
   - Migration versions.
   - Row counts.
   - Constraints.
   - Sequences.
   - Permissions.
   - Tenant isolation.
9. Run a real pooled-connection test:
   - Tenant A uses a connection.
   - The connection returns to the pool.
   - Tenant B receives the same physical connection.
   - Tenant B cannot see tenant A's data or session context.
10. Prepare and rehearse the production cutover:
    - Create a backup.
    - Stop writes.
    - Perform the final data copy.
    - Validate data.
    - Update database secrets.
    - Restart services.
    - Run smoke tests.
11. Retain the old agent database until the rollback window expires.

#### Audit Responsibilities

- Confirm audit ordering remains tenant-scoped.
- Verify duplicate events are harmless.
- Verify replayed records appear in audit history and analytics.
- Exercise DLQ, recovery, and gateway fallback paths.
- Do not replace Kafka during the PostgreSQL migration.

#### Acceptance Criteria

- Backend and agent migrations work independently on the shared PostgreSQL instance.
- The backend role cannot access agent-owned data.
- The agent role cannot access backend-owned data.
- The real tenant A to tenant B pooled-connection isolation test passes.
- Row counts and critical data checks match after migration.
- Backup restoration and rollback have been rehearsed.

### Engineer 3: Gateway, OPA, Presidio, and Performance

Co-location should first be deployed on the current compute platform. This separates its effects from the later Graviton migration.

#### Work

1. Create one multi-container ECS task containing:
   - Gateway.
   - OPA.
   - Presidio.
2. Configure the gateway to use:
   - `http://localhost:8181` for OPA.
   - `http://localhost:3000` for Presidio.
3. Give each container an appropriate health check.
4. Allocate CPU and memory using measured usage rather than uniform defaults.
5. Remove unnecessary service discovery for OPA and Presidio.
6. Ensure OPA and Presidio ports are not reachable outside the task.
7. Test:
   - OPA unavailable.
   - Presidio unavailable.
   - Slow sidecar response.
   - Sidecar restart.
   - Large redaction request.
   - Streaming request.
8. Run before-and-after gateway benchmarks.

#### Acceptance Criteria

- OPA and Presidio cannot be reached from another ECS task.
- Gateway health correctly reflects required sidecar health.
- Plain, redacted, and streaming performance remain within their agreed scenario-specific budgets.
- Memory peaks fit within the task limit with the agreed safety margin.
- Existing policy and redaction tests pass.

## Integration and Release Order

Release changes in this order:

```text
1. Baseline measurements
        ↓
2. ARM64 image builds without deployment
        ↓
3. VPC endpoints and supply-chain controls
        ↓
4. Gateway + OPA + Presidio co-location on Fargate
        ↓
5. Graviton canary, one service at a time
        ↓
6. Shared PostgreSQL non-production rehearsal
        ↓
7. Shared PostgreSQL production cutover
        ↓
8. ECR retention reduction
        ↓
9. Audit transport change, only if still justified
```

Do not combine the following changes in one production release:

- Co-location and Graviton migration.
- PostgreSQL consolidation and compute migration.
- PostgreSQL consolidation and Kafka replacement.
- ECR retention reduction before deployment and rollback digest protection.

## Pull Request and Coordination Rules

Each change must be delivered through a small, independently reversible pull request.

- Engineer 1 owns shared Terraform, CI, and deployment workflows.
- Engineer 2 owns migrations, database permissions, and tenant-isolation tests.
- Engineer 3 owns gateway task composition and performance tests.
- Every pull request includes rollback instructions.
- Infrastructure pull requests include a reviewed Terraform plan.
- A pull request must not change both database topology and application runtime topology.
- Non-production capability and production activation must be separate pull requests.
- One engineer reviews a production change, and a different engineer executes the cutover.

The daily coordination meeting should cover only:

1. Interfaces changed.
2. Shared files affected.
3. Acceptance gates passed or failed.
4. New rollback risks.
5. What is safe to merge that day.

## Definition of Complete

The architecture migration is complete only when:

- Backend and agent use one PostgreSQL instance with separate roles and isolated ownership.
- ARM64 images run successfully on Graviton.
- Gateway, OPA, and Presidio are co-located and internally isolated.
- Required AWS traffic uses VPC endpoints.
- Deployed and rollback images cannot be removed by lifecycle cleanup.
- Performance meets scenario-specific budgets.
- Audit ordering, replay, deduplication, DLQ, and recovery tests pass.
- Fargate and the previous PostgreSQL deployment remain recoverable during the agreed rollback period.

## Known Outdated or Unsupported Claims

The implementation plan must not rely on these outdated or unsupported assumptions:

- **Outdated:** There is no ECR lifecycle policy. The repository already retains the latest 30 images.
- **Incorrect:** Moving to Graviton is only a small task-definition edit. ARM64 image builds and ECS EC2 infrastructure are required.
- **Unproven:** The two PostgreSQL databases are accidental merge residue. Their separation is deliberate in the current Compose and Terraform configuration, even though the original design reason is not recorded.
- **Unsupported:** Current latency is already close to the proposed limit. A benchmark harness exists, but no committed production baseline proves this claim.

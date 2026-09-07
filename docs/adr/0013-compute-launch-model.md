# ADR-0013: Compute launch model and EC2 evidence gate

- Status: Proposed - ARM64 Fargate first; ECS on EC2 deferred
- Date: 2026-09-02
- Decision owner: Binod / AgentsArchitects
- Approvers: Pending - Binod (final decision and production promotion), Kunal
  (AWS infrastructure and operations), and a named Security approver who is eligible
  to review under CODEOWNERS
- Review/revisit trigger: Progress only through the authorization stages in
  [Staged EC2 approval and reopening gate](#staged-ec2-approval-and-reopening-gate);
  production selection requires successful Stage B evidence and an approved Stage C
  revision of this ADR

## Context

P0-05 asks whether AuthClaw should run on ARM64 Fargate or on ECS using
Graviton EC2 instances in an Auto Scaling group (ASG) capacity provider. This ADR is
the decision and evidence gate. Terraform now contains a default-off ASG/capacity
provider implementation so an approved future plan needs no new production code;
its presence does not authorize activation or a live AWS change. P0-04 also publishes
and locally smoke-tests multi-platform images, while a live ARM64 Fargate canary is
still required.

The older `AuthClaw architecture plan (1).docx` recommends EC2 Graviton for
placement control, native ARM64, host tuning, and packing density. It also says that
several decisions depend on measurements that had not been taken. The architecture
document is historical input, not an approval or a source of measured production
facts. The repository-grounded readiness list corrects its assumptions and makes
P0-05 conditional on this ADR:
[AWS_DEPLOYMENT_READINESS_TASK_LIST.md](../AWS_DEPLOYMENT_READINESS_TASK_LIST.md#p0-05--decide-and-if-approved-implement-ecs-on-ec2-graviton).

## Current repository state

### Compute and task topology

- Fargate remains the default. The default-off `ecs_ec2_graviton.enabled` switch
  changes task compatibility and services to the gated capacity provider only after
  this ADR is revised and approved.
- Every task definition now sets Linux and an explicit per-service CPU architecture.
  ARM64 can therefore be canaried on Fargate without selecting EC2.
- The default-off `enable_policy_sidecar_colocation` switch prepares the separate
  step-7 release. It uses `awsvpc` loopback, essential healthy dependencies and no
  policy-sidecar port mappings; the default retains standalone services as the
  pre-cutover rollback topology.
- The primary regional desired-count default is 2 per service and the secondary
  default is 1. The optional audit consumer has a fixed desired count of 1. The
  controlled-beta workflow overrides the primary desired count to 1. These are
  configuration values, not measured capacity requirements.
- The services do not set an explicit rolling-deployment minimum healthy percentage
  or maximum percentage. The repository therefore contains no approved deployment
  surge quantity to use for EC2 instance sizing.

### Configured sizing, not measured sizing

| Task | Task CPU units | Task memory (MiB) | Container CPU total | Container soft-memory reservation total (MiB) | Evidence status |
| --- | ---: | ---: | ---: | ---: | --- |
| Gateway + OPA + Presidio | 2048 | 4096 | 1792 | 2816 | Terraform defaults; staging measurement explicitly pending |
| Backend + Presidio | 2048 | 4096 | 1792 | 2560 | Terraform defaults; staging measurement explicitly pending |
| Agent + OPA | 1024 | 2048 | 1024 | 1280 | Terraform defaults; staging measurement explicitly pending |
| Generic single-container task, including console and optional audit consumer | 512 | 1024 | Not set | Not set | Terraform default; not a utilization measurement |

These values are reservations and limits selected in configuration. They do not show
CPU or memory utilization, peaks, task density, or safe instance counts.

### Images, deployment, and rollback

- CI uses Buildx but specifies no `platforms` value, loads one builder-native image,
  scans it, and pushes it. It does not publish or verify an ARM64 or multi-platform
  manifest. See [ci.yml](../../.github/workflows/ci.yml).
- The deployment workflow promotes those images to ECR by digest. It records current
  ECS task-definition ARNs before an apply and, on failure, updates the same services
  back to those task definitions. It does not record or restore launch type, capacity
  provider strategy, ASG state, or instance architecture. See
  [deploy-controlled-beta.yml](../../.github/workflows/deploy-controlled-beta.yml).
- No tested ARM64 Fargate/x86 Fargate compute rollback artifact is committed.
  Existing task-definition rollback is useful but is not evidence for a compute-model
  rollback.

### Observability and measurement artifacts

- ECS Container Insights is enabled. Terraform creates 30-day service and failed-
  deployment log groups; public-target health; ECS CPU, memory, running-task and
  pending-task alarms; and a circuit-breaker deployment-failure alarm. Live alarm
  delivery and rollback-event evidence is still required.
- The default-off EC2 foundation additionally defines placement-failure,
  container-instance health, ASG capacity and capacity-provider reservation alarms.
  Those EC2-only signals cannot be exercised unless Stage A authorizes Stage B.
- The repository contains local gateway load and recovery artifacts, and those
  artifacts explicitly distinguish local validation from hosted beta evidence. They
  do not contain representative per-service CPU/memory measurements or an EC2 versus
  Fargate cost comparison and cannot size an ASG.
- No repository artifact names a host-operations owner or demonstrates host patching,
  AMI refresh, instance draining, instance/AZ loss recovery, or EC2 recovery
  objectives.

## Corrected AWS constraints

### ARM64 and task-local sidecars

EC2 is not required for ARM64. AWS documents that Linux ARM64 workloads can run on
either Fargate or EC2, with Fargate platform version 1.4.0 or later. The task
definition must specify `runtimePlatform.cpuArchitecture = ARM64`. AWS also documents
that containers in the same `awsvpc` task share a network stack and can communicate
over `localhost`. Therefore neither ARM64 nor the repository's task-local OPA and
Presidio topology justifies EC2:

- [Amazon ECS task definitions for 64-bit ARM workloads](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-arm64.html)
- [Specifying ARM architecture in an ECS task definition](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-arm-specifying.html)
- [Task networking with `awsvpc`](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-networking-awsvpc.html)

### Current service-migration behavior

The claim that AWS categorically forbids an existing service from switching between
Fargate and an ASG capacity provider is outdated. AWS announced this capability on
2025-06-12. The current `UpdateService` API documentation lists Fargate launch type to
ASG capacity provider, Fargate capacity provider to ASG capacity provider, and EC2
capacity provider to Fargate capacity provider as valid transitions. A capacity
provider strategy cannot combine Fargate and ASG capacity providers in one strategy,
but a cluster can contain both kinds:

- [AWS announcement: updating capacity providers for ECS services](https://aws.amazon.com/about-aws/whats-new/2025/06/amazon-ecs-capacity-provider-configuration-ecs/)
- [`UpdateService` capacity-provider transitions](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_UpdateService.html)
- [ECS launch types and capacity providers](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/capacity-launch-type-comparison.html)

Some AWS developer-guide pages still contain the pre-2025 statement that the
transition is unsupported. For this decision, the dated feature announcement and the
current API transition list are authoritative. The target account and region must
still rehearse the exact API/Terraform transition before any production approval.

AuthClaw nevertheless requires a parallel/replacement-service migration rather than
an in-place production switch. This is a repository safety decision, not a current AWS
API limitation. A replacement service provides an independently observable canary and
keeps the current Fargate service intact because the current rollback workflow cannot
restore a capacity-provider strategy. Migration must:

1. create a separate non-production or production-canary EC2-backed service with a
   distinct name and target group or otherwise isolated routing;
2. run the same immutable application digests where architecture compatibility
   permits, with separately registered ARM64 task definitions;
3. verify health, audit integrity, load, placement, instance/AZ failure, draining, and
   recovery before shifting traffic;
4. shift traffic in controlled increments while the Fargate service remains healthy;
5. roll back by routing traffic to the retained Fargate service, not merely by
   restoring a task-definition ARN; and
6. remove the old service or capacity only after the approved bake and rollback window.

## Options and decision matrix

`Unproven` means the repository has no approved measurement that makes one option win.

| Criterion | ARM64 Fargate | ECS on EC2 Graviton with ASG capacity provider | Parallel/mixed migration and rollback arrangement |
| --- | --- | --- | --- |
| Cost | Task-level cost must be measured from representative task counts and runtime; no repository comparison exists | Instance, unused headroom, storage, data, support, and operations cost must be measured; density benefit is unproven | Temporarily pays for both paths; overlap cost must be included in the migration comparison |
| Operational burden | AWS operates and patches compute infrastructure | Team owns instances, ECS agent, AMI, ASG, refresh, draining, capacity, and incidents | Highest during overlap; acceptable only for a bounded canary and rollback window |
| Patching | AWS patches the Fargate infrastructure; team still owns images and application dependencies | Team owns host patch policy and safe replacement/draining | Retained Fargate path avoids making host recovery the only rollback path |
| AMI lifecycle | No customer-managed host AMI | Requires approved ECS-optimized ARM64 AMI source, refresh cadence, deprecation response, and rollback | New AMI/capacity provider must be validated before traffic; old capacity retained through rollback window |
| Scaling latency | No EC2 instance provisioning step; application task startup still must be measured | Can use warm headroom, but cold scale-out includes instance launch, registration, and configured warmup; measure it | Canary must test cold and warm paths without relying on the Fargate service to hide a failure |
| Placement | Fargate controls host placement; service/AZ configuration remains available | Placement strategies/constraints and packing are available, subject to CPU, memory, ENI, port, and instance constraints | Separate services permit explicit traffic allocation; one strategy cannot mix Fargate and ASG providers |
| Host tuning | No host kernel, storage, or agent tuning | Available, but no concrete AuthClaw requirement is documented | Use only to validate a named requirement; tuning opportunity alone is not evidence |
| Failure recovery | AWS replaces underlying Fargate capacity; service/task recovery still requires tests | Team must prove instance and AZ loss, replacement capacity, draining, and task rescheduling | Rollback routes to the healthy Fargate service; EC2 failure must not consume rollback headroom |
| Security | Fargate isolates tasks and AWS maintains the compute layer; team owns images, IAM, network, and data controls | Adds host IAM, IMDS, host hardening, disk, agent, SSH/SSM, vulnerability, and tenant-density concerns | Two compute paths expand the temporary review surface and credential/route inventory |
| Observability | Container Insights, service logs, CPU/memory, running/pending-task, target-health and deployment-failure alarms are configured; live delivery evidence is pending | Requires all Fargate signals plus ASG, instance, capacity-provider, placement, draining, and AMI-age signals | Dashboards and alarms must distinguish old/new services and compute paths |
| Rollback | Prefer a tested x86 Fargate task/service path while ARM64 compatibility is proved | In-place task-definition rollback is insufficient if capacity configuration or architecture changed | Preferred: keep x86 Fargate service/digests and route traffic back; do not create x86 EC2 capacity without a blocker |

AWS assigns the underlying compute patching to AWS for Fargate and the ECS agent,
EC2 AMI, patching, and hardening to the customer for EC2. AWS also documents that ASG
managed scaling can leave unplaceable tasks in `PROVISIONING`, that scale-out observes
an instance warmup period, and that managed draining/termination protection affect
safe replacement:

- [AWS shared responsibility model for Amazon ECS](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/security-shared-model.html)
- [Amazon ECS managed scaling behavior](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/managed-scaling-behavior.html)
- [Managed instance draining](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/managed-instance-draining.html)
- [Amazon ECS-optimized Linux AMIs](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-optimized_AMI.html)

## Decision

**ARM64 Fargate first; ECS on EC2 deferred.**

The repository does not contain sufficient measured and approved evidence for a
quantified EC2 benefit, a concrete host-tuning requirement, or explicit host
operational ownership. P0-05 EC2 implementation is therefore **not currently
applicable**. This ADR does not claim P0-05 complete.

ARM64 enablement remains separate P0-04 work. Multi-platform build, local ARM64
startup/health checks, and per-service Linux/ARM64 runtime configuration are present;
the hosted Fargate canary and retained x86 Fargate rollback still require live evidence.
The sidecar topology remains on the current launch model and is not a reason to reopen
this decision.

The next currently authorized compute activity is the P0-04 ARM64 Fargate canary and
rollback drill under its own review and deployment controls. No P0-05 EC2 experiment
or foundation work is authorized until Stage A below passes.

No temporary x86 EC2 capacity provider is approved. The preferred compatibility and
rollback arrangement is a tested x86 Fargate service using retained immutable x86
digests and task definitions. An x86 EC2 provider may be considered only when a
documented dependency or runtime test proves a specific ARM64 compatibility blocker,
identifies the affected service and duration, and passes the same cost, ownership,
security, observability, recovery, and rollback gates as the ARM64 EC2 provider.

## Evidence status

| Required evidence | Repository evidence used | Current result | Gate stage |
| --- | --- | --- | --- |
| P0-04 ARM64 compatibility | CI contains explicit multi-platform build/manifest gates and local ARM64 startup/health evidence | Local controls complete; hosted Fargate canary and x86 rollback evidence missing | Stage A |
| Tested x86 Fargate rollback | Workflow restores task definitions but does not demonstrate architecture rollback | Missing | Stage A |
| Representative Fargate CPU and memory utilization | No hosted per-service utilization artifact found | Missing | Stage A |
| Task counts by service and environment | Terraform defaults and controlled-beta override | Configured counts exist; representative steady/peak requirements missing | Stage A |
| Deployment surge | No explicit service deployment percentages or measured surge artifact | Missing | Stage A |
| Preliminary EC2 capacity and cost models | No workload-based instance model or environment-scoped comparison found | Missing | Stage A |
| Concrete EC2 justification or evaluation hypothesis | Older plan lists possible placement, density, and tuning benefits | Missing; possible benefits are not a testable hypothesis | Stage A |
| Experiment budget, scope, expiry, and cleanup | No bounded experiment authorization found | Missing | Stage A |
| Named platform, operations, and Security owners | General CODEOWNERS coverage does not accept experiment or host-lifecycle duties | Missing | Stage A |
| Reviewed host-security and observability design | No approved experimental design found | Missing | Stage A |
| Placement, scale-out, and failure-headroom results | No EC2 capacity provider or exercise exists | Collect only after Stage A | Stage B |
| Recovery, draining, patching, and AMI-refresh results | Local/regional recovery material is not an EC2 container-instance drill | Collect only after Stage A | Stage B |
| ASG, capacity-provider, instance, and task alarm evidence | Fargate service alarms and conditional EC2 alarms are configured; live delivery remains unproven | Collect only after Stage A | Stage B |
| Parallel canary and x86 Fargate rollback rehearsal | No EC2 canary exists | Collect only after Stage A | Stage B |
| Quantified EC2 benefit and accepted host ownership | No experimental result or written host-operations acceptance exists | Requires successful Stage B | Stage C |
| Final Security and architecture approval | No EC2 production selection is approved | Requires successful Stage B | Stage C |

## Staged EC2 approval and reopening gate

The stages deliberately separate evidence available on Fargate from evidence that can
only be produced by a bounded EC2 experiment. Completing Stage A authorizes an
experiment; it does not change the Fargate-first decision. Only Stage C can change the
production launch model.

### Stage A - Authorization for a bounded non-production EC2 experiment

Before creating any P0-05 EC2 infrastructure, one reviewable authorization package
must contain all of the following:

1. **P0-04 compatibility and rollback:** ARM64 images and dependencies pass their
   required build, manifest, startup, health, and application checks on Fargate, and a
   retained immutable x86 Fargate service/digest rollback is successfully rehearsed.
2. **Measured Fargate utilization and task counts:** for every service and sidecar
   container, record configured reservations and limits alongside timestamped p50,
   p95, and peak CPU and memory plus steady and peak task counts from an approved
   production-like staging workload. Record the environment, image digests, duration,
   request mix, and raw metric source.
3. **Approved deployment-surge assumptions:** define and approve minimum healthy and
   maximum deployment task counts per service and per AZ instead of relying on an AWS
   or Terraform default.
4. **Preliminary capacity and cost models:** use the measured Fargate workload and
   approved surge assumptions to propose instance types, task packing, ASG bounds,
   instance/AZ failure-headroom assumptions, and a like-for-like preliminary Fargate
   versus EC2 cost model. Mark all untested EC2 inputs as hypotheses.
5. **Concrete justification or evaluation hypothesis:** state the specific cost,
   placement, scaling, density, or host-tuning claim the experiment will test, the
   metric that could falsify it, and why repository/Fargate evidence cannot answer it.
   A generic opportunity to tune hosts is insufficient.
6. **Bounded authorization:** specify the non-production account/environment, allowed
   resources and instance families, maximum spend, experiment duration, expiry and
   cleanup date, data restrictions, and an inventory/checklist for deleting or
   retaining experimental resources.
7. **Named owners:** name the platform owner, primary and backup operations owners,
   and a named Security approver who is eligible to review under CODEOWNERS. Record
   who can stop the experiment and who owns cleanup and cost review.
8. **Reviewed design:** approve the proposed host-security and observability design,
   including instance IAM, IMDS protection, encrypted storage, administrative access,
   AMI source, vulnerability/age tracking, logs, dashboards, alarms, and evidence
   retention. Stage A reviews the design; it does not require controls that can only be
   demonstrated on the experimental infrastructure.

The decision owner, named platform owner, named operations owner, and named Security
approver must explicitly authorize this bounded experiment. Their authorization does
not select EC2 for production and does not permit production traffic migration.

### Stage B - Non-production EC2 foundation and exercises

After Stage A passes, P0-05 may create only the bounded non-production foundation
described in the approved experiment package: an ARM64 ECS-optimized AMI selection,
launch template, private multi-AZ ASG, capacity provider, managed scaling, managed
draining and termination protection, host IAM/hardening, experimental task definitions,
and a separate parallel/replacement service. The experiment must collect:

1. task placement and warm/cold scaling evidence under steady load, peak load, and the
   approved deployment surge;
2. placement and recovery evidence after loss of the largest container instance and
   after loss of one AZ, including CPU, memory, ENI, port, storage, and constraint fit;
3. measured task recovery, instance replacement, scale-out, drain, AMI-refresh, and
   AZ-recovery times for later Stage C objective approval;
4. managed draining and termination-protection behavior, including safe scale-in and
   forced instance replacement;
5. host patching and ECS-optimized AMI refresh, rollback, vulnerability, and age
   evidence;
6. working ASG, capacity-provider reservation, container-instance health,
   running/pending task, placement-failure, drain, application, and rollback alarms;
7. a parallel canary with health and application/audit checks using recorded immutable
   digests; and
8. traffic shift and return to the retained, healthy x86 Fargate replacement service.

This stage supplies the successful exercises formerly required before infrastructure
could exist: recovery evidence (former item 6), demonstrated security/observability
controls (former item 8), and migration/rollback rehearsal (former item 9). It is
experimental authorization only, not a production EC2 decision. The experiment must
stop and clean up on its approved expiry date unless the Stage A approvers record a
bounded extension.

AuthClaw's parallel/replacement-service policy applies throughout Stage B even though
AWS now permits in-place capacity-provider transitions. An in-place transition is not
an approved substitute for the canary or x86 Fargate rollback exercise.

### Stage C - Final EC2 selection

Production selection remains blocked until all of the following are true:

1. every Stage B exercise has successful, reproducible evidence and no unresolved
   placement, recovery, security, observability, or rollback failure;
2. the preliminary models are replaced with a quantified ARM64 Fargate versus EC2
   comparison for the same measured workload, availability target, discounts, storage,
   data transfer, monitoring, idle/failure headroom, deployment overlap, patching labor,
   and incident ownership;
3. the decision owner has set and approved the minimum benefit threshold before
   reviewing the result, and the measured EC2 result meets it or a concrete host-tuning
   requirement demonstrates an independently approved need;
4. task-recovery, instance-replacement, scale-out, drain, AMI-refresh, and AZ-recovery
   objectives are approved and the Stage B results meet them;
5. the primary and backup host-operations owners accept AMI tracking, patching,
   instance refresh, draining, scaling, security response, on-call alarms, capacity
   incidents, and runbook maintenance;
6. the named Security approver accepts the implemented host controls and Stage B
   evidence; and
7. the decision owner, platform owner, operations owner, and Security approver approve
   a revision of this ADR that explicitly selects ECS on EC2 before any production
   migration.

The final approval formerly represented by item 10 belongs here. Stage A approval
authorizes only the experiment; Stage C approval is the production compute decision.
Configured reservations, synthetic examples, local laptop measurements, list prices
without the workload model, or the older architecture recommendation do not satisfy
Stage C.

## Implementation-stream gates and follow-up work

### Gate to start P0-04 ARM64 Fargate work

P0-04 may proceed under its own review controls and must remain on Fargate. The
repository supplies multi-platform builds, dependency and manifest verification,
Linux/ARM64 task runtime configuration, and local startup/health checks. Stage A still
requires the live Fargate canary and tested x86 Fargate rollback. It must not add
P0-05 EC2 infrastructure or combine the compute-model experiment with the ARM64 rollout.

### Gate to start a non-production P0-05 EC2 experiment

No P0-05 EC2 infrastructure may be created until every Stage A requirement is present
and the decision owner plus named platform, operations, and Security owners explicitly
authorize the bounded experiment. That authorization opens Stage B only; it does not
select EC2 for production.

### Gate to start production EC2 migration

Production migration may start only after Stage B succeeds and Stage C approves a
revised ADR that explicitly selects ECS on EC2. The migration must use AuthClaw's
parallel/replacement-service traffic shift and retained x86 Fargate rollback path;
AWS's support for in-place capacity-provider transitions does not waive this policy.

### Follow-up work under the current decision

- Complete P0-04 live evidence separately: Fargate canary and x86 Fargate rollback
  drill using the already gated multi-platform images and runtime configuration.
- Capture hosted per-service CPU/memory/task-count and deployment-surge evidence without
  treating local load results as production sizing.
- Capture live Fargate memory, running/pending task-count and circuit-breaker rollback
  alarm delivery during the staging drills.
- Keep compute migration separate from audit transport, database consolidation, and
  sidecar topology releases.
- Recheck current AWS API and target-region behavior when the ADR is reopened because
  the service-mutation documentation changed after the older architecture plan.

## Consequences

- AuthClaw keeps the lower host-operating burden of Fargate while ARM64 compatibility
  and workload measurements are established.
- No speculative EC2 infrastructure, cost saving, density, availability, or tuning
  claim is accepted.
- The current configured reservations remain explicitly provisional and must not be
  used to calculate production EC2 instance counts.
- A future EC2 decision is possible, but it carries named ownership, quantified benefit,
  failure-headroom, recovery, observability, security, and parallel rollback gates.
- The rollback default remains x86 Fargate; x86 EC2 is an exception requiring a proven
  service-specific ARM64 blocker.
- P0-05 remains open but not applicable under the current decision; completing this ADR
  is not completion of P0-05.

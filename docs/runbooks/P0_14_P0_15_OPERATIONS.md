# P0-14/P0-15 Scaling, Availability, and Observability

Status: **P0-14 Coding/IaC COMPLETE; P0-15 Coding/IaC COMPLETE.** Only AWS connection/configuration and staging validation remain.

## Architecture and capacity

The regional stack keeps its existing architecture: Fargate by default, with the optional Graviton ECS capacity provider retained. Console, backend, gateway, and agent run as separate ECS services; the audit consumer is optional. All services use awsvpc networking across at least two private subnets in staging and production. Public services retain their dedicated ALBs and target groups.

Staging and production use a minimum of two tasks for every enabled service. Application Auto Scaling has explicit per-service floors and ceilings:

| Service | Minimum | Maximum | Scaling signals | Rationale |
| --- | ---: | ---: | --- | --- |
| console | 2 | 4 | CPU, memory, ALB requests/target | web rendering and request concurrency |
| backend | 2 | 5 | CPU, memory, ALB requests/target | API saturation while preserving the DB budget |
| gateway | 2 | 6 | CPU, memory, ALB requests/target | proxy throughput and redaction load |
| agent | 2 | 4 | CPU, memory | no ALB; model/document work is compute and memory bound |
| audit consumer | 2 | 4 | CPU, memory, SQS backlog when selected | consumer processing plus native queue pressure |

Scale-out waits 60 seconds and scale-in waits 300 seconds by default. All values are Terraform inputs and must be tuned from staging metrics. Deployment settings are 100% minimum healthy, 200% maximum, a circuit breaker with rollback, 60-second target deregistration, and a 60-second ECS stop timeout. The gateway stops advertising readiness before bounded shutdown; backend and agent use bounded server shutdown and dispose their shared Redis clients and database engines; the audit consumer stops polling and closes the transport and metrics server.

When the optional EC2 launch model is selected, the existing capacity provider uses managed scaling, managed draining, termination protection, multiple private subnets, and a four-instance minimum split across two AZs. Terraform validates that one half of both the minimum and maximum ASG capacity can place the corresponding service task mix after an AZ loss. A state-backed staging plan must still demonstrate placement with the selected instance type before production.

## PostgreSQL connection budget

| Consumer | Calculation | Connections |
| --- | --- | ---: |
| backend | 5 tasks × (10 pool + 5 overflow) | 75 |
| gateway | 6 tasks × 10 open | 60 |
| agent | 4 tasks × (5 pool + 5 overflow) | 40 |
| runtime subtotal |  | 175 |
| migrations, monitoring, administration, recovery reserve | explicit reserve | 25 |
| configured PostgreSQL maximum |  | 200 |

Terraform fails its capacity precondition if runtime maxima plus reserve exceed rds_max_connections. The applications use a five-second connect and pool-acquisition timeout and recycle connections after 300 seconds. These are fail-fast pool controls, not query replay: non-idempotent database operations are not retried automatically.

RDS Proxy: **NOT USED**.

Reason: the bounded direct pools fit the explicit RDS budget, and the repository contains no measured connection-churn or exhaustion evidence showing that multiplexing is necessary. Adding a proxy would also alter transaction/session semantics at the RLS trust boundary. Reconsider only after staging measurements show connection churn or saturation that bounded pools cannot solve; if introduced, rerun backend tenant-session, agent tenant-context, restricted-role PostgreSQL, and RLS isolation suites.

## Redis and transport behavior

The primary ElastiCache replication group has two cache nodes, Multi-AZ, automatic failover, encrypted transit/storage, snapshots, and maintenance windows. Clients use the replication-group primary endpoint so DNS reconnection follows failover. Gateway Redis connect/read/write/pool timeouts are 2/2/2/3 seconds. Atomic rate-limit writes deliberately have zero automatic retries because a lost response is ambiguous; replay could increment twice. Reconnection uses a fresh pooled connection and requests fail closed while mandatory abuse-control state is unavailable.

SQS uses three standard SDK attempts, a three-second connect timeout, a 25-second read timeout compatible with 20-second long polling, visibility renewal, redrive, native backlog/age/DLQ alarms, and one-task bounded scale-out steps. ClickHouse uses a three-second connect timeout, ten-second read timeout, at most three insert attempts, and exponential delays capped at two seconds. Kafka remains the default when SQS is not selected; no fake managed Kafka resources were added.

## Dashboards and alarms

Terraform enables ECS Container Insights with enhanced observability and creates four dashboards per regional stack:

- services: desired/running/pending/restart counts, CPU, memory, deployment events, ALB health, requests, 4xx/5xx, and p95 response time.
- data: RDS CPU/memory/storage/connections/queue/deadlock/replica signals; Redis memory/evictions/connections/replication/CPU/network; SQS and safe audit custom metrics.
- network: NAT bytes/errors/drops and VPC endpoint packet drops.
- NAT: the existing detailed NAT dashboard.

RDS Enhanced Monitoring, Performance Insights, PostgreSQL slow-query/lock logging, Redis alarms, ECS availability alarms, native SQS alarms, audit integrity alarms, NAT alarms, VPC endpoint alarms, and EventBridge-derived ECS deployment/RDS/Redis event alarms are configured. Audit consumer and gateway emit payload-free CloudWatch Embedded Metric Format events. Metric dimensions contain environment, service, and release only—never tenant IDs, prompts, documents, credentials, or provider payloads.

All alarm and recovery actions use the existing edge_alarm_action_arns integration. Terraform does not invent an SNS/PagerDuty destination. Before production, the platform owner must populate that input with the approved real destination and record:

| Field | Required evidence |
| --- | --- |
| on-call owner | named team/rotation approved by operations |
| acknowledgement | expected acknowledgement time from the incident policy |
| escalation | secondary rotation/incident commander route |
| recovery action | this runbook plus the service-specific diagnostic |
| notification proof | CloudWatch alarm history and destination receipt |
| recovery proof | OK transition and recovery notification receipt |

Critical alarm families are: service running below minimum; ECS deployment failed; RDS failure/failover and replica lag; Redis availability/replication pressure; VPC endpoint packet drops; audit outbox failure/stall; sequence gaps; ClickHouse drift/replay failures; and chain-verification failures. Warning alarms cover sustained high CPU, storage/memory headroom, slow queries, deadlocks, evictions, and NAT anomalies.

## Logging policy

Service log groups retain 90 days by default (configurable). AWS encrypts CloudWatch Logs at rest; access remains outside application task roles, which receive write-only log delivery through the execution role and no log-read permissions. Release values come from immutable image references through AUTHCLAW_RELEASE.

Logs and metrics may include environment, service, release, a validated opaque request ID/trace ID, operation, status, and latency. They must not include Authorization/Cookie headers, JWTs, API keys, passwords, provider bodies, prompts, messages, PII/PHI, document contents, or raw request/response bodies. Backend and agent entry points install JSON formatting and centralized redaction; the agent wrapper also catches legacy standard-output paths. Obvious raw exception/payload logging paths found in the focused repository scan were replaced with safe error categories. Provider and exception paths must keep errors summarized by type/status. CloudWatch EMF emitters are explicitly payload-free and tested for forbidden fields.

## Staging failure drills

Use the existing NFR 99.99% availability evidence and ACL-24 gateway p95 limit of 900 ms where applicable. The thresholds below are explicit staging acceptance thresholds for these previously undefined drills and require operational approval before becoming production SLOs.

### A. ECS task failure

1. Record desired/running counts, healthy targets, error rate, and p95 latency.
2. Stop one task with the AWS CLI or console.
3. Confirm the remaining target serves traffic and ECS starts a replacement in the other available subnet/AZ.
4. Pass when there is no interval with zero healthy targets, no sustained 5xx increase beyond two one-minute periods, and desired count recovers within five minutes.

### B. Availability Zone loss

1. In an approved game-day window, remove one AZ from service capacity or block its test targets without modifying production.
2. Confirm ALB routes only to healthy targets and ECS reaches the minimum in another AZ.
3. Pass when at least one healthy target remains, no zero-target interval occurs, and minimum capacity recovers within ten minutes.

### C. Redis primary failover

1. Trigger test-failover for the staging replication group.
2. Observe replication/failover alarms and gateway Redis error metrics.
3. Confirm fail-closed requests recover through the primary endpoint without process restart.
4. Pass when retries remain bounded, there is no duplicate rate-limit increment evidence, and normal requests recover within five minutes.

### D. Database pool pressure/outage

1. Load each service to its configured pool ceiling, then temporarily deny new staging connections.
2. Confirm acquisition/connect timeouts occur in five seconds, task connection counts never exceed the Terraform budget, and recovery does not create a connection storm.
3. Pass when RDS connections remain at or below 200, the 25-connection reserve remains usable before the deliberate denial, and health recovers within five minutes after restoration.

### E. Failed deployment

1. Deploy a staging-only revision whose health command fails.
2. Observe the ECS deployment-failed event and critical alarm.
3. Confirm the circuit breaker rolls back and the previous revision retains healthy targets.
4. Pass when the bad revision never becomes the sole healthy revision and rollback stabilizes within ten minutes.

## Critical alarm validation record

For every critical alarm, record: alarm ARN/name, exact safe trigger, ALARM timestamp, configured destination, receipt timestamp, acknowledgement, recovery timestamp, OK notification receipt, operator, release digest, and links to non-sensitive CloudWatch evidence. Static Terraform tests are not notification evidence.

| Alarm family | Trigger tested | Destination | Received | Recovery verified | Status |
| --- | --- | --- | --- | --- | --- |
| ECS running below minimum | not run | not configured in repository | no | no | NOT RUN |
| ECS deployment failed | not run | not configured in repository | no | no | NOT RUN |
| RDS failure/failover/lag | not run | not configured in repository | no | no | NOT RUN |
| Redis event/replication | not run | not configured in repository | no | no | NOT RUN |
| VPC endpoint packet drop | not run | not configured in repository | no | no | NOT RUN |
| audit integrity/delivery | not run | not configured in repository | no | no | NOT RUN |
| SQS DLQ/backlog/age (when enabled) | not run | audit_sqs_alarm_action_arns not configured in repository | no | no | NOT RUN |

## Requirement/evidence checklist

| Requirement | Implementation | File/resource | Test/evidence | Status |
| --- | --- | --- | --- | --- |
| multi-task/AZ service floor | two-task staging/prod minimum and two-AZ precondition | p014_scaling.tf | Terraform P0 contract test | IMPLEMENTED, drill NOT RUN |
| autoscaling and ceilings | CPU/memory/ALB/SQS policies | p014_scaling.tf | Terraform P0 contract test | IMPLEMENTED |
| deployment rollback/draining | 100/200, circuit breaker, rollback, 60s drain/stop | regional main.tf | Terraform P0 contract test; gateway unit test | IMPLEMENTED |
| bounded clients/pools | PostgreSQL, Redis, SQS limits | application client files | focused unit tests | IMPLEMENTED |
| RDS budget | 175 + 25 <= 200 precondition | p014_scaling.tf | Terraform output assertion | IMPLEMENTED; staging load NOT RUN |
| RDS Proxy decision | direct pools retained | this runbook | design evidence above | NOT USED |
| Redis failover | Multi-AZ automatic failover and alarms | regional main.tf, p015_observability.tf | staging drill C | IMPLEMENTED, drill NOT RUN |
| ECS/RDS/Redis/queue/audit/network visibility | dashboards, alarms, EMF | p015_observability.tf, application emitters | Terraform P0 contract test | IMPLEMENTED; live metrics NOT VERIFIED |
| log retention/access/hygiene | 90-day configurable groups, no task log-read grant, structured/redacted runtime logs and safe EMF | regional main.tf, safe logging modules, this runbook | focused logging and EMF unit tests | IMPLEMENTED; live log inspection NOT RUN |
| alert routing/on-call | action ARN inputs and owner/ack/escalation metadata | Terraform variables and alarm tags | live alarm receipt | CODE COMPLETE; destination configuration pending |
| critical alarm validation | procedure and record table | this runbook | real staging evidence | CODE COMPLETE; staging validation NOT RUN |

## Remaining work after deployment

Only the following AWS connection/configuration and staging-validation work remains:

1. Set the approved SNS/PagerDuty action ARNs, named on-call owner, acknowledgement target, and escalation path in the deployment inputs.
2. Confirm deployed task placement across Availability Zones, dashboard population, log fields/redaction, retention, and operator read access.
3. Execute the ECS task-loss, Availability Zone, Redis-primary-failover, database-pool-pressure, and failed-deployment rollback drills above and capture recovery evidence against their thresholds.
4. Safely trigger every critical alarm, verify delivery to the real on-call destination and acknowledgement/escalation behavior, then verify its OK/recovery notification.
5. Measure production-like database connection churn and pool saturation in staging. Keep RDS Proxy absent unless those measurements justify it; if introduced later, rerun tenant-session and RLS isolation tests.

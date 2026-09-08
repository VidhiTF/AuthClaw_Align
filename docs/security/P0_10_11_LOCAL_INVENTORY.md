# P0-10 / P0-11 implementation and release gates

Status: local implementation and tests, NOT a production certification.
No AWS apply, secret replacement, state mutation or real Access Analyzer run was performed.

## IAM contract

- Execution roles are per task, including database jobs. Injection and GetSecretValue grants share one map. ECR grants use configured repositories; logs use task log groups; KMS decrypt requires Secrets Manager plus exact SecretARN context.
- Backend, agent, the isolated SQS audit producer, and enabled audit consumer have independent runtime roles. A co-located gateway/OPA/Presidio task has no task role; backend and agent retain separate policy services so policy containers never inherit their AWS permissions.
- Runtime roles explicitly deny reading task-injected secrets. Execution-role credentials are not application credentials.
- SQS producer policies attach only to the backend and isolated `audit_producer`; consumer permissions attach only to the enabled consumer. The gateway has no task role and publishes to the isolated producer over authenticated internal HTTPS. All SQS grants target the selected queue and KMS key. Kafka has no SQS grants.
- Agent customer operations use only explicitly approved exact role ARNs. Configure customer-side trust (including ExternalId where supported) and customer-side least privilege separately. No wildcard STS, S3, Kinesis or customer-account permissions are granted.
- Optional organization boundary applies to execution/runtime roles. Organization SCPs and additional denies require the actual organization policy, not invented defaults.

| Workload | Runtime call sites | Permission rationale |
| --- | --- | --- |
| Backend | app/services/audit_transport.py | SQS send/queue lookup |
| Isolated audit producer | gateway/audit_producer.go; gateway/sqs_fifo.go | Authenticated internal HTTPS ingestion followed by SQS send/queue lookup |
| Gateway | gateway/audit_producer.go | Authenticated HTTPS to the isolated producer; no task role or direct SQS permission |
| Consumer | audit_consumer/transport.py | SQS receive/delete/visibility/queue lookup |
| Agent | services/agent/document_processing/connectors.py; services/remediation_runtime.py | STS assumption of approved customer roles |
| Backend connectors | app/services/cloud_connectors.py; app/api/v1/endpoints/aws.py | Tenant-supplied credentials; no ambient platform grant |
| Optional managed crypto | backend/app/core/crypto.py; services/agent/services/secret_manager.py | direct_aws grants exact retained backend KMS decrypt keys; agent data-key generation/decryption uses the database-field encryption context; provider secret CRUD is exact-ARN, without create or forced deletion |
| Optional S3 | services/agent/document_processing/connectors.py; services/remediation_runtime.py | Exact approved bucket configuration reads and object reads only; account-wide inventory and customer operations require customer STS permissions |
| ClickHouse | backend/consumer clients | Network and password authentication, not IAM |

## Secret lifecycle baseline

The following are implementation baselines; the organization must assign named owners and approve overrides before release. Intervals are maximum planned review/rotation periods, not automatic rotation already deployed. Incident rotation is immediate. Never roll back to compromised material.

| Family / names | Accountable team | Interval | Overlap / rollback |
| --- | --- | --- | --- |
| JWT_SECRET_V1/V2 | Identity | 90 days | Preload both, switch AUTHCLAW_JWT_KEY_VERSION, retain prior key through maximum issued-token TTL plus clock skew |
| WORKER_TOKEN_HMAC_KEY_V1 | Worker platform + security | 90-day review; follow worker cutover runbook | Backend and worker-preflight only; externally provision consistently across failover regions, never across staging/production. Preserve upstream issuance pause and 32-minute cutover barrier; do not substitute JWT/session keys |
| SESSION_SECRET_V1/V2 | Identity | 90 days | Preload both, switch AUTHCLAW_SESSION_KEY_VERSION, retain through cookie/OTP TTL; opaque DB sessions are separate |
| ENVELOPE_KEY_V1/V2 | Security + database | 180 days | Preload both, switch AUTHCLAW_SECRET_KEY_VERSION; retain every key referenced by ciphertext/backups; retirement preflight must pass |
| AWS_KMS_ENCRYPTED_DATA_KEY_V1/V2; AUTHCLAW_AWS_KMS_KEY_ID_V1/V2 | Security | 180 days | Optional KMS provider now selects each envelope's referenced version; restore active selector without deleting retained versions |
| AUTHCLAW_ENCRYPTION_KEY | Agent + security | 180 days | Unversioned agent AES/Fernet key is NOT a dual-key switch. Drain, re-encrypt and verify full data/backups before retirement; optional managed-envelope path has separate tests |
| AUTHCLAW_REDACTION_SALT; REDACTION_HASH_SALT | Privacy + security | 180 days | Coordinate deterministic-token compatibility; do not replace independently during active workloads |
| AUTHCLAW_INTERNAL_SERVICE_SECRET; BFF_CLIENT_IP_SECRET; OIDC_BFF_EXCHANGE_SECRET | Identity | 90 days | Single-key boundaries require coordinated drain/cutover, not a claimed overlap mechanism |
| DATABASE_URL; bootstrap/migrator URLs; PLATFORM_AUTH_DATABASE_URL | Database + identity | 90 days | Rotate DB role first under a reviewed pool/drain plan, provision matching URL, restart consumers; platform issuer is separate |
| Provider credentials | Tenant integration owner | 90-day review or provider expiry | Revoke at provider, update encrypted tenant record, verify connector |
| SMTP_USERNAME/PASSWORD | Delivery | 90 days | External provision, test actual invitation delivery, drain/restart if provider lacks overlap |
| CLICKHOUSE_PASSWORD | Audit | 90 days | Coordinate backend/consumer, verify ingestion/replay and rollback account |
| Release signing / GitHub OIDC | Release + security | Every job for ephemeral credentials; trust review every 90 days | Reuse existing CI signing/OIDC flow, retain verification trust for released artifacts |
| Regional KMS CMK | Security | AWS automatic annual rotation enabled | Ciphertexts remain decryptable; 30-day deletion window and Terraform prevent_destroy; disabling/deletion denied except configured approved emergency roles with their own IAM authorization |

## External provisioning and migration

1. Review a saved plan privately with the infrastructure owner. New code contains secret metadata only, no secret-version resources/data sources or generated application values. Removed blocks use destroy=false to hand off old values without deleting them. Historical state versions/backups remain sensitive and require restricted retention; this is not retroactive scrubbing.
2. The RDS primary changes to RDS-managed master credentials. This is an operational credential migration, not a harmless refactor. Coordinate master rotation, externally refresh bootstrap URL, and verify runtime/migrator credentials before rollout. A replica must receive region-correct URLs from the provisioner.
3. Provision every ARN from required_secret_arns using the organization's secure external process. Never put values in tfvars, Terraform outputs, build args or repository files. Database URLs must select the intended DB role and require TLS (sslmode=require); the gateway URL uses its supported PostgreSQL driver scheme.
4. Populate regional BFF/OIDC keys consistently where cross-region failover needs compatibility, but NEVER share material between staging and production. Use separate AWS accounts/state backends, environment-qualified secret names and regional keys.
5. The release workflow refuses to proceed unless IAM_SECRETS_MIGRATION_APPROVED is explicitly true and every required secret has AWSCURRENT. A fresh installation paused for external provisioning may be bootstrapped on retry only with BOOTSTRAP_DATABASE_APPROVED and no prior runtime services. Existing deployments keep their original preflight-only behavior.
6. Preserve legacy execution-role permissions needed by retained rollback task definitions through an independently reviewed state handoff/retirement procedure before approving migration. Old task definitions are retained using non-destructive removed blocks, but that alone does not preserve their old IAM roles. Do not approve rollback until the retained definitions' roles and secret versions are verified.
7. Release planning sends rendered IAM/KMS policy documents to Access Analyzer. ERROR or SECURITY_WARNING blocks runtime apply; issue codes (not secret values or raw plans) become iam-review.json. Runner requires access-analyzer validation and Secrets Manager DescribeSecret permissions. Local mock plans are not IAM authorization simulation.
8. Before a planned key switch, preload versions everywhere, run compatibility tests and ciphertext inventory, canary, switch only the active selector, verify traffic/sessions/decryption, then retire after the retention window. Rollback changes the selector while retaining both keys. Emergency procedure: contain workload, revoke compromised credentials/sessions, provision fresh material externally, restore service, verify evidence and audit all actions.

## Remaining release gates

- Supply system-trusted certificate chains and matching private keys externally for the internal TLS tasks, configure DNS namespace, and verify deployed clients, ALB targets and ECS network boundaries. Local certificates are test-only. No private-CA trust bundle distribution or mutual TLS is claimed.
- Approve exact optional AWS resource inventories, customer-role trust/ExternalId and permissions. The configuration and policies exist, but actual AWS authorization is not proven by mocks.
- Run real cross-service deny/positive authorization tests, Access Analyzer review, external provisioning, RDS credential migration, SMTP delivery, and full failover/rollback in staging.
- Inspect the ACTUAL released image layers, build logs and deployment logs with the existing secret scanners. Repository/fixture checks cannot certify artifacts not built here.
- Assign named owners, organization boundaries/break-glass roles and verify staging/production account separation.
- Single-key agent/redaction/internal-service families need coordinated operational rotation; do not claim the JWT/session/envelope tests cover those families.

## Local implementation and evidence (2026-09-04)

- `internal_tls = { enabled = true, namespace = "internal.example.com" }` enables the pinned unprivileged NGINX proxy in each console/backend/agent/gateway/OPA/Presidio task. Port 8443 is the remote entry point; application ports are local upstreams and blocked by security-group ingress. Task-specific cert/key Secrets Manager metadata is included in the existing provisioning gate. Certificates must contain the respective `service.namespace` SAN and a chain trusted by application system CAs. Provision new secret versions externally and replace ECS tasks to rotate; retain previous versions for rollback. Certificate owner: platform/security, renew before issuer expiry with at least a 30-day operational alert.
- The console remains behind its existing ALB-only ingress, now using the same HTTPS target configuration, without an AWS runtime role. Internal application clients verify server certificates; this is not mTLS. ALB target HTTPS is encryption, not a claim of ALB certificate validation. Existing application authorization remains required. Production guards still reject private HTTP service endpoints.
- `direct_aws` configures primary-region resources; `secondary_direct_aws` is independent and defaults empty. KMS/Secrets Manager ARNs must match the task region. `backend_kms_versions` maps retained v1/v2 keys; `agent_kms_key` and `agent_previous_kms_keys` select write/read keys; `agent_secrets`, `agent_secret_kms_keys`, `agent_s3_buckets` and `agent_s3_objects` are exact allowlists. `document_role_arn` must be in `agent_customer_role_arns`; `document_external_id` is forwarded to STS.
- Shared backend/gateway records still use environment-key envelopes: the Go gateway cannot consume backend KMS envelopes. Backend optional KMS configuration supports retained backend-only reads, not a global write-provider switch. Encrypted S3 objects needing additional customer KMS access should use the approved customer role, not an invented platform-wide grant.
- Agent `ecs_injected` reads static application secrets from ECS-injected environment without fallback generation or writes. Provider references use the explicit AWS allowlist; their secret metadata must already exist. Runtime roles cannot read task-injected deployment secrets. Provider secrets cannot be created implicitly or force-deleted. Injected secrets rotate through external provisioning plus task replacement.
- SMTP uses a verifying TLS context. Both `production` and `prod` reject plaintext SMTP and missing SMTP configuration instead of writing verification codes to a local outbox.
- Existing CI workflow runs the real NGINX/SMTP tests and direct-AWS contracts in a disposable container. Existing PostgreSQL recovery tests now bind `POSTGRES_DB` to the generated disposable database as well as its connection URL. No new deployment workflow was introduced.

Fresh local checks: 5 mocked Terraform plans; 7 TLS/SMTP tests; 4 direct-AWS/agent KMS rotation, rollback and denial tests; 39 backend crypto/migration tests (including populated pre-040 upgrade and interrupted migration recovery); 34 console unit tests; 18 repository/IAM evidence controls. Total: 107 passing tests. Terraform validate/fmt and workflow structure checks pass. Full actionlint also reports two existing SC2129 style warnings outside the changed steps; these are not hidden as a clean full lint run.

Backend and agent images were built locally and scanned with Trivy filesystem/image-configuration secret scanning; no embedded-secret findings were reported. The saved backend, agent and pinned TLS proxy layers were additionally scanned with Gitleaks archive traversal (741 MB, no findings). Some base-image compressed documentation symlinks/whiteout entries produced traversal warnings, so this is not an exhaustive absence-of-secrets guarantee. Registry artifacts and production logs were not scanned. Release images must still be scanned and their deployed digests verified. The disposable PostgreSQL rehearsal is not an RDS master-secret/state migration or staging rollback rehearsal.

## Follow-up local verification (2026-09-04)

- `scripts/check_internal_tls.py HOST --port 8443 --min-days 30` is a read-only certificate gate. It verifies the current chain and hostname using system trust (or explicitly supplied `--ca-file`), rejects an expiring leaf certificate, and emits only status, public fingerprint and remaining lifetime. Run it from the VPC/reachable deployment environment; it does not issue certificates, rotate production secrets, or create a scheduled monitor. CA/intermediate lifecycle remains the certificate owner's responsibility.
- `scripts/test_internal_tls_containers.py` creates a uniquely named internal Docker network, starts the repository OPA image with the exact Terraform NGINX proxy configuration, and uses the backend image's HTTPS client. It verifies health and an actual deny decision, rejects wrong-host/untrusted certificates, replaces the proxy with a renewed certificate, rolls back to the exact prior fingerprint, and rejects the renewal window. All certificates are synthetic; no host ports are published. Cleanup runs after success or failure. This verifies the backend-image client/OPA path, not every production service endpoint or AWS security-group enforcement.
- Existing single-key agent encryption, redaction fingerprinting and control-plane signature functions now have synthetic cutover/rollback rehearsals. Encryption rollback requires retaining the old ciphertext snapshot as well as the old key. Salt cutover changes deterministic fingerprints and needs matching token state. Mixed internal-service signing keys fail closed: drain and coordinate sender/receiver updates. These tests do not introduce seamless dual-key support or a production data-rewrite command.
- The existing CI workflow builds the backend/OPA images and runs the container rehearsal. The two previously reported ShellCheck style warnings are fixed without changing release behavior; full actionlint now passes.

Reproduce the container rehearsal after building `authclaw-security-backend:local` with `backend/Dockerfile.demo` and `authclaw-security-opa:local` with `infra/opa/Dockerfile`: `python scripts/test_internal_tls_containers.py`. Optional `TLS_TEST_BACKEND_IMAGE` / `TLS_TEST_OPA_IMAGE` select other locally built images.

Fresh follow-up evidence: 9 real TLS/SMTP/expiry tests, 7 secret/AWS/rotation tests, 1 actual-container lifecycle scenario, and 18 repository/IAM control tests passed (35 total). Full workflow lint, diff whitespace checks and scripts Gitleaks scan passed. Earlier image-layer archive warnings remain disclosed above; they were not fixed by weakening scanner rules. Private-CA distribution and gateway KMS-envelope support remain conditional architecture work, not enabled features. Live certificate renewal/alert scheduling, IAM/RDS migration and authorization, actual email delivery, and deployed image verification remain external release gates.

## Review findings and fixes (2026-09-04)

1. TLS target groups had fixed names and destroy-first replacement. Changing HTTP/port to HTTPS/8443 requires replacement while listeners still reference the old group. Fixed with generated service-specific name prefixes and create-before-destroy. This enables replacement ordering; it is not a zero-downtime guarantee, and listener/ECS health cutover still needs staging verification.
2. Targeted bootstrap included execution policies but could omit the crypto-preflight runtime KMS policy. Database task definitions now explicitly depend on execution and runtime role policies. The generated Terraform graph confirms both edges in both regions, so targeted job planning includes those policies. AWS IAM propagation and actual authorization remain live checks.
3. Backend retained KMS read keys were incorrectly required to contain the active environment-encryption write version. Removed that coupling. The production-mode mocked plan now covers env v2 writes with only retained KMS v1 reads configured.

Regression evidence: 5 Terraform tests plus validate, 19 repository/IAM checks, 9 TLS/SMTP tests, 7 secret/AWS/rotation tests, and 1 actual-container TLS/OPA lifecycle scenario passed (41 fresh checks/tests). Full actionlint passed. The review covered the P0-10/P0-11 change surface and its integration paths; it is not a repository-wide security certification or a substitute for the external gates above. No live state, database or secret values were changed.

## Master integration (2026-09-04)

Pulled `align/master` from `VidhiTF/AuthClaw_Align`, advancing `f58ba4a` to `2f8ec32` (9 commits). Four stash-restoration conflicts were reconciled in CI, controlled-beta deployment, root Terraform and regional Terraform. Upstream CI selection/smoke behavior, CodeQL removal, worker lifecycle migration 046, issuance pause and worker preflight are preserved. Worker HMAC metadata/injection uses the local per-task execution-role map and external value provisioning; non-destructive removed blocks retain any previously managed secret versions. The worker PostgreSQL fixture now sets its generated database name explicitly, matching its isolated connection URL.

Original local changes remain uncommitted; the pre-pull stash is retained as a recovery backup. No live migration or AWS apply was performed during integration.

References:
- https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html
- https://docs.aws.amazon.com/secretsmanager/latest/userguide/security-encryption.html
- https://developer.hashicorp.com/terraform/language/block/removed
- https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_ValidatePolicy.html

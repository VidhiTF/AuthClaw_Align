# P0-16–18: migration, production deployment and rollback

Owner: release manager; execution: on-call platform engineer; approval: service owner,
security owner and database owner. The incident commander or on-call engineer may
stop or roll back immediately without waiting for further approval. Production
execution requires the approved change record; this document does not authorize a
deployment. Use the existing CI, Terraform modules, database jobs and ECR controls.
Gateway performance benchmarking is excluded.

## Release sequence (each row is a separate checkpoint)

Do not combine rows 6–10 in one release. Finish and approve a row before starting
the next. Record a release ID, UTC completion time, approver, raw evidence and
rollback checkpoint for every row in `release.json`. A checkpoint contains current
task-definition ARNs/revisions and all container digests, approved tfvars/configuration,
state version, schema revisions, recovery snapshot/PITR time, transport offsets and
chain heads, DNS/edge configuration, secret version IDs and restoration commands.
Never capture secret values. Unavailable evidence blocks advancement.

| Step | Change and exit evidence | Rollback point/action |
| --- | --- | --- |
| 1 | Freeze the compute decision (P0-16 ADR-2, represented in this repository by ADR-0013), ADR-0011 transport decision, and inventory all current configuration and dependencies. | Signed baseline inventory/configuration; abandon proposal. |
| 2 | CI signatures, provenance, SBOM, scans and rollback digest retention verified. | Retained current/deeper images; retain protection even if CI changes revert. |
| 3 | Staging AWS identity, remote state/locking, network, edge, secrets and telemetry ready. | Saved state version and reviewed reverse infrastructure plan; preserve data. |
| 4 | Existing architecture runs on staging at immutable digests. | Baseline task revisions/configuration from row 1. |
| 5 | Transport abstraction deployed with the existing transport unchanged. | Previous application digests; unchanged broker and offsets. |
| 6 | Kafka to selected transport cutover, drain and reconciliation approved. | Kafka/task/configuration checkpoint; preserve both queues and replay safely. |
| 7 | Gateway/OPA/Presidio co-location on the current launch type; verify the gateway task has no task role and SQS uses the isolated producer. | Disable gateway sidecars; retain independent policy services and producer until Terraform restores the prior topology. |
| 8 | Publish ARM64 images; startup, health and canary on Fargate. | Retained X86_64 task revisions and matching image indexes. |
| 9 | PostgreSQL consolidation only in staging; migration, pools/RLS, isolation, restore and rollback proven. | Original databases/endpoints preserved; stop writers before reversal/reconciliation. |
| 10 | EC2 Graviton only if the frozen compute ADR requires it. Otherwise attach an approved NOT_APPLICABLE decision. | Fargate capacity and previous revisions retained. |
| 11 | All non-performance checks and security/failure/recovery/rollback drills below pass. | Latest known-good full checkpoint; drill previous retained digests. |
| 12 | Promote precisely the tested digests and approved configuration; production smoke passes. | Immediately previous compatible production checkpoint. |

The current Terraform supports Fargate, a gated Graviton capacity provider, and a
default-off `enable_policy_sidecar_colocation` switch. The default keeps independently
isolated OPA/Presidio services as the step-4 rollback topology. Step 7 alone sets the
switch to `true`: gateway gets task-local OPA and Presidio with no task role or ENI
ports. Backend and agent continue using the independent OPA/Presidio services so
their AWS roles are never exposed to policy containers. With SQS selected, gateway
publishes through the separate HMAC-authenticated `audit_producer` task; only that
task receives the narrow SQS producer role, and only those two containers receive
the dedicated producer secret. In controlled beta, set the
protected environment variable `ENABLE_POLICY_SIDECAR_COLOCATION=true`; set it back
to `false` in a reviewed reverse Terraform plan to restore the checkpoint. Do not
rely on task-definition-only rollback for this topology change. ADR-0013 currently
selects ARM64 Fargate first and defers EC2; capture its approved status at step 1.
Repository ADR-0002 concerns URL boundaries, not compute.

The controlled-beta environment also exposes `AUDIT_STREAM_TRANSPORT` (`kafka` or
`sqs_fifo`), `INTERNAL_TLS_JSON`, `ENABLE_AUDIT_CONSUMER`, `CLICKHOUSE_HOST`,
`AUDIT_SQS_ALARM_ACTION_ARNS_JSON`, and `SERVICE_CPU_ARCHITECTURES_JSON`. Keep the
protected `EDGE_ALARM_ACTION_ARNS_JSON` list populated with the approved incident
destinations for edge, ECS health, capacity and deployment-failure alarms. Keep the
architecture map empty for the x86 baseline, then canary one service with ARM64 per
step-8 checkpoint before expanding the map. These protected values are part of the
configuration checksum and must change only in their numbered release. Transport
selection still requires the step-6 reconciliation evidence; a variable change is
not proof of a successful cutover. SQS selection requires `INTERNAL_TLS_JSON` to
enable internal TLS with the issued namespace and immutable proxy digest. Provision
the gateway and audit-producer certificates and dedicated producer-secret value
before applying that release; Terraform blocks an HTTP producer path.

Set protected `ROLLBACK_TFVARS_JSON` to the reviewed previous values for co-location,
service CPU architectures, transport, internal TLS, audit consumer/ClickHouse, alarm destinations,
and all seven immutable container image digests. The workflow accepts only those
runtime keys, applies them as a reverse Terraform plan after a failed runtime rollout,
then requires every restored service revision and deployed digest to match Terraform
state and that retained configuration. Update this value at each rollback checkpoint.

For step 7, retain `ecs list-services` JSON and the active gateway
`ecs describe-task-definition` JSON, then run the offline check below. Its output is
the raw `colocation` check; retain its referenced inputs beside it.

```bash
python3 scripts/verify_ecs_colocation.py --gateway gateway-task.json \
  --services services.json \
  --architecture-map "$SERVICE_CPU_ARCHITECTURES_JSON" \
  > colocation-verification.json
```

The controlled-beta workflow performs this capture and check automatically. The
manual command is the recovery path and is also suitable for independently checking
downloaded workflow artifacts. Use `{}` for the architecture map before the ARM64
canary; during the canary, provide the exact protected service map.

## Prepare the single release-evidence package

Use a restricted, encrypted artifact location. Include raw command outputs, exit
statuses, CI run logs/job list, Terraform plans and reviews, task results, ECR
verification/protection records, drill timeline and approvals. Terraform plans/state
can contain secrets: retain them only in the restricted location, never public logs.
Hash the final redacted evidence bytes; an approver must review originals where
redaction removes relevant information. Keep artifacts beyond both rollback windows.

```bash
set -euo pipefail
mkdir -p release-evidence
python3 scripts/release_evidence.py init release-evidence/release.json
```

Populate the frozen release block once, then attach each raw result with the recorder;
PENDING is deliberately not a successful result. The first check in each step must
include that step's rollback checkpoint. Later checks in the same step reuse it.

```bash
python3 scripts/release_evidence.py record release-evidence/release.json \
  --step 1 --name decisions --raw decisions.txt --rollback-point baseline.json \
  --release-id CHG-123-step-1 --approver "Named reviewer"
```

The recorder accepts only files already inside `release-evidence`, hashes their exact
bytes, and copies the frozen commit, image map and configuration reference into the
check. It refuses to overwrite recorded evidence unless `--replace` is explicit.
Use `--status NOT_APPLICABLE --reason "approved reason"` only for eligible checks.
For `rollback_drill`, add `--duration-seconds N --retained-artifacts --verified-all`
only after every required verification actually passed; the recorder copies the
frozen previous image map.

Every `raw`, `configuration` and `rollback_point` is `{ "path": "relative/file",
"sha256": "64 lowercase hex characters" }` inside this package; use `sha256sum`.
Every check records environment, full Git commit, complete service-to-image digest
map, configuration checksum, timezone-aware time, named approver and raw output.
Steps 1–10 refer to their own historical releases. Step 11 must refer to the exact
candidate commit, images and configuration. Re-run these checks after any change.
Step 12 refers to those same values in production. `configuration` is the frozen
bundle of runtime settings **and** reviewed staging/production bindings (domains,
ARNs, secret version IDs, account/region, network and state coordinates); no
unrecorded production override is permitted. Verify rendered task definitions and
the plan against this bundle, including every sidecar, before accepting evidence.

Set release approvers, rollback owner, UTC change-window start/end, incident channel,
previous/current images, rollback expiry and database compatibility expiry in the
ledger. Before step 12, populate `current_task_definitions` from the retained
pre-deployment inventory and `target_task_definitions` from the reviewed production
plan. Both maps must contain the same service names and full revision-qualified ECS
task-definition ARNs; the checker rejects missing, partial or family-only values.
Set `migration_mode=expand` and `previous_digest_compatible=true` only after
the database owner reviews old/new application verification against the new schema.
For `rollback_drill`, also record `duration_seconds` (positive, at most **300**),
`retained_artifacts=true`, `redeployed_images` equal to `release.previous_images`,
and `verified` with `health`, `authentication`, `gateway`, `audit_publication` and
`clickhouse_consistency` all true. Measure from rollback invocation to all checks
passing. The existing HA targets are RTO ≤240 s, RPO ≤30 s and DNS ≤60 s; do not
relax them after the drill. NOT_APPLICABLE needs an architectural reason, raw
decision evidence and approval and is allowed only for conditional compute/failure
checks, never authentication, isolation, recovery or audit checks.

```bash
python3 scripts/release_evidence.py check release-evidence/release.json --through 11
```

The checker verifies evidence linkage/checksums, order, separate disruptive releases,
compatibility windows and exact promotion identity. It does not authenticate an
approver or prove AWS behavior from a JSON assertion. Required environment reviewers
and restricted artifact access provide that authority. Never upload fixture test
output as live release evidence.

## Pre-deployment and explicit database tasks

Use Bash, Python 3.12+, AWS CLI v2, Terraform at the CI-pinned version, jq, cosign,
gh and the tested repository revision. Assume the approved short-lived production
role. The change record must supply: AWS account/region, cluster, service list,
Terraform state bucket/key/KMS ID, approved configuration bundle, task-definition
ARNs, migration gate JSON, incident channel, window, release/security/database
approvers and rollback owner. No production default is implied.

1. Announce start/commit/checkpoint in the recorded channel; confirm approvers and
   rollback owner are online and the window is open. Hold the existing deployment
   concurrency lock/change freeze; disable competing auto-deploys for this window.
2. `aws sts get-caller-identity` and `aws configure get region` must match the change
   record. Initialize the existing encrypted/locked S3 Terraform backend with the
   recorded production key. Verify workspace/state identity before planning.
3. Run the existing **AuthClaw Required CI** via workflow_dispatch at the candidate
   commit with `full_regression=true` and `arm64=true`. Download all job logs and
   confirm no required suite skipped; a lightweight master CI run is insufficient.
4. Run `terraform -chdir=infra/terraform fmt -check -recursive`, `validate` and the
   existing CI Terraform security scan. Review saved plans and IAM evidence. No
   destroy/replacement of data, transport, edge or compute is allowed as a side
   effect of an application release. Split such changes into their sequence row.
5. Capture current inventory using the command below. Save full `describe-services`
   and `describe-task-definition` outputs, target revisions and all image digests.
   Verify targets against the staged bundle; do not rebuild images for production.
6. Reuse [container controls](CONTAINER_RELEASE_AND_ROLLBACK.md): verify signatures,
   scans, every platform digest and ECR protection; protect both current/deeper
   rollback inventories and candidate images before rollout. Confirm rollback image
   compatibility includes strict crypto and worker-token retirement barriers.
7. Take and restore-test a backup using [the recovery procedure](../compliance/ACL_24_RECOVERY_LOAD_EVIDENCE.md).
   Record revisions, snapshot/PITR identifiers, old/new application checks and tenant
   chain heads. Confirm no critical alarm, active incident or incomplete reconciliation.

```bash
# CLUSTER is the exact cluster in the approved change record.
: "${CLUSTER:?required}"
python3 scripts/ecr_release_control.py inventory --cluster "$CLUSTER" \
  --output release-evidence/current-inventory.json
# Export only after provisioning the reviewed database job definitions/dependencies,
# using the workflow's targeted preparation; do not apply runtime services yet.
terraform -chdir=infra/terraform output -json crypto_preflight > release-evidence/database-gate.json
for job in backend_migrations agent_migrations database_security_check crypto_preflight worker_preflight; do
  python3 scripts/ecs_database_job.py release-evidence/database-gate.json "$job" \
    --output "release-evidence/database-${job}-task.json"
done
```

Each task must start once, stop with all expected containers at exit code 0 and use
the recorded immutable task definition. A timeout, failed start, missing result or
nonzero exit blocks rollout. Preserve task ARN/logs, diagnose and review migration
idempotency before retrying; never start overlapping migrations. Empty installations
use the existing workflow's prepare/migrate/finalize/security-check bootstrap path.
Existing installations require `DATABASE_EXPAND_COMPATIBILITY_APPROVED=true` in the
controlled-beta environment. The workflow runs migrations before runtime apply.

## Deploy, observe and close

After migration success, save and review the complete runtime Terraform plan. Apply
only that saved plan under the approved change window; the workflow's IAM analyzer
must accept it. Enable no new release dimensions. ECS public/private/audit services
use deployment circuit breaker with rollback; ALB/container health gates deployment.
The breaker needs a previously completed healthy deployment; it cannot recover a
first installation or roll back database/data/DNS changes.

```bash
terraform -chdir=infra/terraform plan -input=false -out=runtime.tfplan
# Review in restricted storage, including exact task digests/configuration and IAM.
terraform -chdir=infra/terraform show -json runtime.tfplan | \
  python3 scripts/iam_release_evidence.py --access-analyzer > release-evidence/iam-review.json
python3 scripts/release_evidence.py check release-evidence/release.json --through 11
terraform -chdir=infra/terraform apply -input=false runtime.tfplan
mapfile -t services < <(jq -er '.services[].service' release-evidence/current-inventory.json)
test "${#services[@]}" -gt 0
aws ecs wait services-stable --cluster "$CLUSTER" --services "${services[@]}"
aws ecs describe-services --cluster "$CLUSTER" --services "${services[@]}" > release-evidence/target-services.json
python3 scripts/ecr_release_control.py inventory --cluster "$CLUSTER" \
  --output release-evidence/target-inventory.json
```

Service stability alone can mean ECS rolled back: compare **every** target revision
and container digest to the approved targets, require rolloutState COMPLETED and no
unexpected deployments. Verify public health and alarms, then authenticated canary,
gateway and audit-to-ClickHouse probes below. Observe for at least 15 minutes with
no failed functional check, unhealthy task, new DLQ item or active alarm. Populate
step 12 and run `release_evidence.py check ... --through 12`. Announce completion
with package checksum, commit/digests, approvers and remaining rollback window.

## Stop conditions and rollback execution

Stop immediately for migration failure/unknown outcome, changed plan/digest,
authentication or tenant isolation failure, direct-origin access, secret leakage,
audit gap/chain mismatch, rising DLQ, unhealthy deployment or alarm. Quiesce writes
if data integrity is uncertain. Announce incident and rollback start time. The
on-call/incident commander chooses the last compatible checkpoint with the database
owner; do not run schema downgrade automatically.

For the application/configuration drill, use the **real retained** inventory and
approved previous tfvars saved before deployment. Reverify ECR protection and
signatures using the container runbook. Restore version-pinned secret bindings first
if changed. `ROLLBACK_TFVARS` and its checksum come from that checkpoint. Review the
generated reverse plan and record the named approver before applying it; this plan
restores services, discovery, IAM, networking, transport and task configuration.

```bash
set -euo pipefail
trap 'rm -f infra/terraform/rollback.tfplan' EXIT
date -u +%FT%TZ > release-evidence/rollback-start.txt
: "${ROLLBACK_TFVARS:?checkpoint tfvars path required}"
: "${ROLLBACK_TFVARS_SHA256:?checkpoint tfvars checksum required}"
test "$(sha256sum "$ROLLBACK_TFVARS" | cut -d' ' -f1)" = "$ROLLBACK_TFVARS_SHA256"
terraform -chdir=infra/terraform plan -input=false \
  -var-file="$ROLLBACK_TFVARS" -out=rollback.tfplan
terraform -chdir=infra/terraform show -json rollback.tfplan \
  > release-evidence/rollback-plan.json
python3 scripts/iam_release_evidence.py --access-analyzer \
  < release-evidence/rollback-plan.json > release-evidence/rollback-iam-review.json
: "${ROLLBACK_PLAN_APPROVED_BY:?named reverse-plan approver required}"
printf '%s\n' "$ROLLBACK_PLAN_APPROVED_BY" > release-evidence/rollback-plan-approver.txt
terraform -chdir=infra/terraform apply -input=false rollback.tfplan

primary="$(terraform -chdir=infra/terraform output -json primary)"
test "$(jq -er '.ecs_cluster_name' <<<"$primary")" = "$CLUSTER"
mapfile -t services < <(jq -r '.ecs_service_names[]' <<<"$primary")
test "${#services[@]}" -gt 0
aws ecs wait services-stable --cluster "$CLUSTER" --services "${services[@]}"
terraform -chdir=infra/terraform show -json | jq -r '
  .values.root_module.child_modules[] | select(.address == "module.primary") |
  .. | objects | select(.type? == "aws_ecs_service") |
  .values | [.name, .task_definition] | @tsv' \
  > release-evidence/rollback-task-definitions.tsv
test -s release-evidence/rollback-task-definitions.tsv
while IFS=$'\t' read -r service definition; do
  aws ecs describe-services --cluster "$CLUSTER" --services "$service" |
    jq -e --arg definition "$definition" '(.failures | length) == 0 and
      (.services | length) == 1 and .services[0].taskDefinition == $definition and
      any(.services[0].deployments[]; .status == "PRIMARY" and
        .taskDefinition == $definition and .rolloutState == "COMPLETED")' >/dev/null
done < release-evidence/rollback-task-definitions.tsv
python3 scripts/ecr_release_control.py inventory --cluster "$CLUSTER" \
  --output release-evidence/rollback-inventory.json
jq -e --slurpfile config "$ROLLBACK_TFVARS" '
  ([.services[].images[].image] | unique | sort) ==
  ((($config[0].container_images | [.agent, .backend, .gateway, .console, .opa, .presidio]) +
    (if ($config[0].enable_audit_consumer // false) then [$config[0].container_images.audit_consumer] else [] end) +
    (if ($config[0].internal_tls.enabled // false) then [$config[0].internal_tls.proxy_image] else [] end)) |
    unique | sort)' release-evidence/rollback-inventory.json >/dev/null
jq -e '.alarm_names | select(type == "array" and length > 0)' <<<"$primary" \
  > release-evidence/rollback-expected-alarms.json
mapfile -t alarms < <(jq -r '.[]' release-evidence/rollback-expected-alarms.json)
aws cloudwatch describe-alarms --alarm-names "${alarms[@]}" \
  > release-evidence/rollback-alarms.json
jq -e --slurpfile expected release-evidence/rollback-expected-alarms.json '
  ((.MetricAlarms | map(.AlarmName) | sort) == ($expected[0] | sort)) and
  all(.MetricAlarms[]; .StateValue == "OK")' \
  release-evidence/rollback-alarms.json >/dev/null
```

The checkpoint must materialize the internal TLS proxy digest when TLS is enabled.
Load the short-lived tenant access token and gateway key from the approved credential
source into the variables below without echoing them. `GATEWAY_CANARY_BODY_FILE` is
a reviewed, non-sensitive request whose exact expected status is recorded there.

```bash
set -euo pipefail
set +x
: "${CONSOLE_URL:?required}" "${BACKEND_HEALTH_URL:?required}"
: "${BACKEND_API_BASE:?required}" "${GATEWAY_URL:?required}"
: "${BACKEND_ACCESS_TOKEN:?required}" "${GATEWAY_API_KEY:?required}"
: "${EXPECTED_TENANT_ID:?required}" "${EXPECTED_GATEWAY_STATUS:?required}"
: "${GATEWAY_CANARY_BODY_FILE:?required}"
test -s "$GATEWAY_CANARY_BODY_FILE"
CANARY_REQUEST_ID="rollback-$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM"
backend_curl="$(mktemp)"; gateway_curl="$(mktemp)"
trap 'rm -f "$backend_curl" "$gateway_curl"' EXIT
chmod 600 "$backend_curl" "$gateway_curl"
printf 'header = "Authorization: Bearer %s"\n' "$BACKEND_ACCESS_TOKEN" > "$backend_curl"
printf 'header = "Authorization: Bearer %s"\nheader = "Content-Type: application/json"\nheader = "X-Request-ID: %s"\n' \
  "$GATEWAY_API_KEY" "$CANARY_REQUEST_ID" > "$gateway_curl"

curl -fsS "${CONSOLE_URL%/}/" > release-evidence/rollback-console-health.html
curl -fsS "$BACKEND_HEALTH_URL" > release-evidence/rollback-backend-health.json
curl -fsS "${GATEWAY_URL%/}/health" > release-evidence/rollback-gateway-health.json
curl -fsS --config "$backend_curl" "${BACKEND_API_BASE%/}/auth/me" \
  > release-evidence/rollback-authentication.json
jq -e --arg tenant "$EXPECTED_TENANT_ID" \
  '.tenant_id == $tenant and .is_active == true' \
  release-evidence/rollback-authentication.json >/dev/null

gateway_status="$(curl -sS --config "$gateway_curl" -o release-evidence/rollback-gateway-canary.json \
  -w '%{http_code}' --data-binary "@$GATEWAY_CANARY_BODY_FILE" "${GATEWAY_URL%/}/v1/chat/completions")"
test "$gateway_status" = "$EXPECTED_GATEWAY_STATUS"
for attempt in {1..30}; do
  curl -fsS --config "$backend_curl" \
    "${BACKEND_API_BASE%/}/audit-logs?limit=1000&integrity_check=true" \
    > release-evidence/rollback-audit-canary.json
  jq -e --arg request "$CANARY_REQUEST_ID" '
    .source == "clickhouse" and .integrity_checked == true and
    any(.records[]; .request_id == $request and .chain_valid == true)' \
    release-evidence/rollback-audit-canary.json >/dev/null && break
  sleep 2
done
jq -e --arg request "$CANARY_REQUEST_ID" '
  any(.records[]; .request_id == $request and .chain_valid == true)' \
  release-evidence/rollback-audit-canary.json >/dev/null
curl -fsS --config "$backend_curl" "${BACKEND_API_BASE%/}/audit-logs/store/consistency" \
  > release-evidence/rollback-clickhouse-consistency.json
jq -e '.consistent == true and .postgres_chain_valid == true and .clickhouse_chain_valid == true' \
  release-evidence/rollback-clickhouse-consistency.json >/dev/null
date -u +%FT%TZ > release-evidence/rollback-finish.txt
rollback_seconds="$(( $(date -u +%s) - $(date -u -d "$(cat release-evidence/rollback-start.txt)" +%s) ))"
printf '%s\n' "$rollback_seconds" > release-evidence/rollback-duration-seconds.txt
test "$rollback_seconds" -le 300
```

Require completion ≤300 seconds and no active alarms. If exceeded, record FAIL and
escalate; do not relabel the run. The reverse Terraform apply leaves state aligned
with the restored topology, so never reapply the stale forward plan.

| Surface | Recovery procedure |
| --- | --- |
| Images/task config | Redeploy retained revisions above, including sidecars, architecture, IAM, environment, health checks and discovery. Restore network/service-level settings through the checkpoint's reviewed reverse Terraform plan. |
| Transport | Follow [SQS/Kafka cutover](SQS_FIFO_AUDIT_CUTOVER.md); stop producers, capture outbox/offsets, restore producer+consumer config, retain both queues/DLQs, reconcile IDs/sequence/hash chains before reopening writes. Never purge or decommission during the window. |
| Schema | Leave additive expansion in place; run the previous verified application. Contract (column/table removal, type narrowing, dropping compatibility views) is a separate release after both windows expire. Never use blanket `alembic downgrade`. |
| Data | Stop/fence writers, restore to a new private encrypted DB using the linked recovery commands, verify RLS/pools/chain heads, reconcile acknowledged writes from durable audit/outbox evidence, then switch versioned DB secrets and tasks. Keep the original for investigation; owner approves any measured loss. |
| DNS/edge | Save Route53 records and CloudFront/WAF/ALB configuration/ETags at checkpoint. Prepare the reviewed inverse Route53 change batch and edge Terraform plan there. Use `aws route53 change-resource-record-sets --hosted-zone-id "$ZONE_ID" --change-batch file://release-evidence/dns-rollback.json`, wait for INSYNC; apply the reviewed edge plan, verify authoritative/public DNS, TLS, origin denial and prior TTL expiry. Never bypass WAF/origin restrictions. |
| Secrets | Prefer task references pinned to approved secret version IDs. If stages changed, use `aws secretsmanager update-secret-version-stage --secret-id "$SECRET_ARN" --version-stage AWSCURRENT --move-to-version-id "$PREVIOUS_VERSION" --remove-from-version-id "$CURRENT_VERSION"`, then redeploy affected tasks. Do not restore compromised credentials or retired decryptors; use forward rotation and retain necessary decryption keys until data verification. |
| Region | Fence primary writes first; measure replica lag against RPO, promote only the approved replica with `aws rds promote-read-replica --db-instance-identifier "$REPLICA_ID"`, wait `db-instance-available`, update regional DB secret bindings and deploy retained regional tasks. Run write/auth/audit probes before approved DNS failover. Never resume writes in the old region; failback requires a rebuilt replica and a separate reviewed operation. |

All shell variables in recovery commands are exact identifiers/version IDs supplied
by the checkpoint, checked against AWS describe output before mutation. For regional
drills record writer fencing, promotion, observed DNS time, RTO/RPO and audit chains.

Existing irreversible boundaries: migrations **041**, **042**, **044** and **046**
explicitly reject downgrade. Migration **040** does not restore legacy ciphertext.
Crypto/key retirement and worker-token issuance barriers must remain enforced.
Fence incompatible application digests by removing them from the approved deployment
and rollback inventory, retaining only tested strict-crypto/schema-compatible images,
and prohibiting their task revisions in the deployment change review. Before an
incompatible contract migration, stop old tasks/jobs and revoke their dedicated DB
role access; confirm no old sessions remain before changing schema. Do not revoke a
shared role needed by the new version. Pre-contract backup restore requires isolated
recovery and renewed security review, never an automatic rollback to unsafe code.

## Non-performance validation sources and remaining live work

The generated ledger names every required check separately. Reuse these suites and
collect real staging probes/drills; repository unit tests alone cannot satisfy them.

| Checks | Existing source / required raw evidence |
| --- | --- |
| Full CI, Terraform, ARM64 | `.github/workflows/ci.yml` full regression + ARM64 jobs, all logs and job outcomes; reviewed plans, static scan, startup/health output. |
| Authentication/authorization/CORS/cookies/OAuth/tenant/fail-closed | Backend auth/tenant suites, console tests, gateway tests; repeat real login, logout, expired token, forbidden role/cross-tenant requests and registered OAuth callbacks on staging. Record status and redacted cookie/CORS headers; demo/mocked routes are not live authorization proof. |
| Audit append/outbox/transport/DLQ/ClickHouse/export/replay/chain | Backend audit tests, audit_consumer tests, transport readiness collector; unique canary IDs through append→outbox→transport→projection, DLQ failure/redrive, export verification via `backend/scripts/verify_audit_export.py`, replay twice and compare IDs/counts/hash chains. |
| Database migration/pool/RLS/backup/restore/rollback | Existing CI PostgreSQL integration, `verify_database_security.py` one-off job and linked recovery procedure; run previous and new images against migrated/restored schema under concurrent tenant reuse. |
| Task/AZ/queue/Redis/DB/region failures | Record approved AWS fault-injection template IDs and exact targets in checkpoint; inject one failure at a time in staging, record CloudWatch/task/DB/queue outputs and recovery probes. Restore the checkpoint before the next injection; do not invent a passing simulation. |
| Origin/internal ports/IAM/rotation/redaction | TLS/private path tests, IAM analyzer, boundary probes from public and authorized private clients, rejected unauthorized AWS calls, rotated-version startup and redacted application/log samples. |
| ECR retention | `ecr_release_control.py inventory`, `verify`, `protect`, `preview`; deployed and rollback indexes and platform children still exist with protected tags after lifecycle preview. |

AWS foundation, actual retained registry images, staging faults/data restoration,
production promotion and named approvals require live access and execution. Until
those raw results populate the package, P0-16–18 are not operationally complete.

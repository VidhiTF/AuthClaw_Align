# ADR-0006: ACL-14 controlled-beta delivery

- Jira: ACL-14 / F09
- Status: Implemented for repository controls; live AWS and GitHub enforcement pending
- Decision date: 2026-07-16
- Owner: Kunal
- Review owner: Binod / AgentsArchitects

## Context

ACL-14 requires one reproducible local startup command, merge-blocking CI checks, and a
controlled-beta deployment that uses immutable builds, managed secrets, encrypted
storage, health verification, telemetry, and rollback.

The repository can implement and validate those controls without AWS access. It cannot
claim a live deployment, DNS routing, or active GitHub branch protection until the
required cloud resources, credentials, and repository-owner authentication exist.
[ADR-0002](0002-aws-url-environment-boundary.md) remains the authority for the final AWS
edge and DNS design. [ADR-0005](0005-acl-11-canonical-agent-api.md) defines the canonical
agent contract consumed by this delivery baseline.

## 2026-07-31 execution-policy amendment

To minimize GitHub Actions usage, repository automation now executes only for pushes
to `master`. Pull requests, feature branches, schedules, and manual dispatches do not
trigger Actions. `ACL-14 Required Checks` is therefore a post-merge release gate rather
than a merge-blocking status check. Owner review, Code Owner review, resolved
conversations, linear history, and force-push/deletion protections remain required.

This intentionally changes the pre-merge portion of the original decision below.
Applicable local tests must be run before review, and a failed master run blocks release
and controlled-beta deployment.

## Decision

1. The canonical local startup command is:

   ```bash
   docker compose --env-file .env.full -f docker-compose.full.yml up -d --build --wait
   ```

   CI renders the same Compose model, starts it with the `ci` profile, waits for service
   health, and runs the repository smoke checks.
2. `ACL-14 Required Checks` is the single stable required GitHub status. It succeeds
   only after the existing build, test, secret, dependency, compliance, integration,
   benchmark, and image-scan jobs succeed. The checked-in `master` protection payload
   requires that status, pull-request review, Code Owner review, resolved conversations,
   linear history, and prevents force pushes and deletion.
3. A successful `master` hard-gate workflow triggers the controlled-beta workflow. The
   deployment job runs only when the `controlled-beta` environment variable
   `CONTROLLED_BETA_ENABLED` is exactly `true`; otherwise it is intentionally skipped.
4. GitHub Actions obtains short-lived AWS credentials by OIDC. Long-lived AWS access
   keys are not stored in GitHub or the repository.
5. Tested `ci-<commit>` images, including ACL-11's private agent service, are promoted to
   KMS-encrypted ECR repositories with immutable tags. Terraform requires every deployed
   runtime image to use an ECR digest in the form `image@sha256:<digest>`.
6. Terraform uses KMS-encrypted, lock-protected S3 state. Runtime secrets remain in AWS
   Secrets Manager, and the controlled-beta data, logs, caches, and registries use KMS
   encryption through the existing Terraform baseline.
7. After each apply, the workflow waits for ECS stability and the private agent's
   canonical readiness check, checks every published health endpoint, and rejects active
   CloudWatch unhealthy-host or ECS CPU alarms.
8. Before applying a release, the workflow records the current ECS task definition for
   every service. A failed apply or verification restores those task definitions, waits
   for stability, and retains deployment and rollback evidence for 30 days.

The state bucket, state KMS key, GitHub OIDC provider and role, DNS, and ACM certificate
are account bootstrap inputs. They are intentionally not created by this delivery
workflow. ACL-29 and ACL-30 remain responsible for the broader approved edge and DNS
implementation and are not prerequisites for committing the independent ACL-14 controls.

## Enablement gates

The controlled-beta deployment must remain disabled until all variables documented in
[`infra/terraform/BETA_DEPLOYMENT.md`](../../infra/terraform/BETA_DEPLOYMENT.md) exist and
the OIDC role has least-privilege deployment access. Enabling the flag without complete
inputs fails before Terraform changes infrastructure.

Branch protection must be applied only after this workflow has merged to `master` and
`ACL-14 Required Checks` has run there at least once. Applying the payload earlier could
require a status context that GitHub has not yet observed.

## Evidence

- [`README.md`](../../README.md) and [`startup_guide.md`](../../startup_guide.md) contain
  the canonical Compose command.
- [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) implements the aggregate
  required check and full-stack proof.
- [`.github/workflows/deploy-controlled-beta.yml`](../../.github/workflows/deploy-controlled-beta.yml)
  implements OIDC deployment, digest promotion, verification, evidence, and rollback.
- [`infra/terraform/registry.tf`](../../infra/terraform/registry.tf) and the regional
  Terraform stack implement immutable encrypted registries and deployment telemetry.
- [`.github/branch-protection-master.json`](../../.github/branch-protection-master.json)
  records the required `master` protection policy.
- [`scripts/test_acl14_delivery_controls.py`](../../scripts/test_acl14_delivery_controls.py)
  checks the delivery controls without AWS credentials.

## Consequences

- Merges can be blocked by one stable status instead of coupling branch protection to
  every internal CI job name.
- Default-branch CI remains safe before cloud bootstrap because deployment is opt-in.
- Releases are traceable to a tested commit and immutable image digests, and a failed
  release has an automated application rollback path.
- Repository validation is not live acceptance evidence. ACL-14 remains incomplete
  until an authorized owner applies branch protection and records a successful AWS
  deployment, health/alarm verification, and rollback drill.

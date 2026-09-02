# ACL-14 controlled-beta deployment

Merges to `master` run the hard-gate workflow. A successful run triggers
`Deploy Controlled Beta`, which:

1. obtains short-lived AWS credentials through GitHub OIDC;
2. promotes the tested `ci-<commit>` images, including the ACL-11 agent, from GHCR into
   immutable, KMS-encrypted ECR repositories;
3. applies Terraform using KMS-encrypted, lock-protected S3 state;
4. waits for ECS stability and the private agent readiness check, then verifies every
   public health endpoint;
5. rejects active CloudWatch alarms; and
6. restores the previous ECS task definitions if deployment verification fails.

No AWS credentials are stored in GitHub. Before enabling the deployment, create the
`controlled-beta` GitHub environment and define:

| Variable | Purpose |
| --- | --- |
| `CONTROLLED_BETA_ENABLED` | Set to `true` only after every bootstrap input below exists |
| `AWS_REGION` | Primary controlled-beta region |
| `AWS_ROLE_ARN` | OIDC-assumable deployment role |
| `TF_STATE_BUCKET` | Existing private versioned S3 state bucket |
| `TF_STATE_KEY` | Optional state key; defaults to `authclaw/controlled-beta.tfstate` |
| `TF_STATE_KMS_KEY_ID` | KMS key protecting Terraform state |
| `BETA_DOMAIN_NAME` | Certificate-covered controlled-beta hostname |
| `BETA_CERTIFICATE_ARN` | ACM certificate in `AWS_REGION` |
| `BETA_PRESIDIO_IMAGE` | Presidio image pinned as `name@sha256:<digest>` |

The OIDC role needs the least-privilege Terraform deployment permissions plus access to
the state bucket/key. The bucket, state KMS key, OIDC provider, DNS, and ACM certificate
are account bootstrap inputs and are intentionally not created by this repository.
Until `CONTROLLED_BETA_ENABLED=true`, successful default-branch CI runs leave the
deployment job safely skipped.

## Branch protection

The master-only CI workflow exposes one stable post-merge context,
`ACL-14 Required Checks`, after the affected components pass their essential checks.
When controlled beta is enabled, the same workflow also builds the seven immutable
release images required by deployment. The context is release/deployment evidence,
not a pre-merge required status check.
An authenticated repository owner can apply the checked-in protection configuration:

```powershell
gh api --method PUT repos/AgentsArchitects/AuthClaw/branches/master/protection --input .github/branch-protection-master.json
```

## Rollback

Before Terraform applies a release, the workflow records every current ECS task
definition. A failed apply, stability wait, endpoint check, or alarm check redeploys
those task definitions and waits for the rollback to stabilize. Both the release
evidence and rollback map are retained as workflow artifacts for 30 days.

## ARM64 one-service rollout

All deployment fields below remain `LIVE-EVIDENCE-PENDING` until an authorized AWS run.
Before rollout, require green required CI, the matching release manifest artifacts,
immutable multi-architecture `name@sha256:<index>` image references, no active ECS
deployment, and a record of the current X86_64 task-definition revision and image digest.

1. Start with one non-production service. Change only its `container_images` digest and
   `service_cpu_architectures` entry to `ARM64`; leave every unselected entry X86_64.
2. Run the manifest inventory checker with the release artifact directory, deployment
   tfvars, selected service, and source commit. Stop on any FAIL.
3. Create and review a saved Terraform plan. Reject changes outside the intended task
   definition runtime platform, revision, image digest, and ECS service revision reference.
4. Obtain explicit human approval before `terraform apply`.
5. Wait until desired count equals running count and ECS reaches steady state. Confirm
   Linux/ARM64, the expected image digest, passing health checks, clean startup/import
   logs, and all relevant alarms in OK state.

Stop immediately on placement or image-pull failure, crash loops, failed health checks,
an alarm transition, or unexpected task-definition changes.

## ARM64 rollback and evidence

Restore the recorded service architecture to `X86_64` and the prior immutable
AMD64-compatible image or task revision. Save and review the rollback plan, obtain human
approval, apply it, and wait for the same stability, health, log, and alarm gates.

Record environment, region, service, source commit, release tag, index digest, ARM64 and
AMD64 child digests, old/new task-definition revisions, runtime architecture, rollout
timestamps, health/alarm verdict, and rollback verdict. Fargate placement, image
resolution, startup, stabilization, health, logs, alarms, deployed digest, and live
rollback remain `LIVE-EVIDENCE-PENDING` until captured from AWS.

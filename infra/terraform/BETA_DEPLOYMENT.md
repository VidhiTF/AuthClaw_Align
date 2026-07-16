# ACL-14 controlled-beta deployment

Merges to `master` run the hard-gate workflow. A successful run triggers
`Deploy Controlled Beta`, which:

1. obtains short-lived AWS credentials through GitHub OIDC;
2. promotes the tested `ci-<commit>` images from GHCR into immutable,
   KMS-encrypted ECR repositories;
3. applies Terraform using KMS-encrypted, lock-protected S3 state;
4. waits for ECS stability and verifies every public health endpoint;
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

The CI workflow exposes one stable required context, `ACL-14 Required Checks`, after
all build, test, secret, dependency, integration, compliance, and image-scan jobs pass.
An authenticated repository owner can apply the checked-in protection configuration:

```powershell
gh api --method PUT repos/AgentsArchitects/AuthClaw/branches/master/protection --input .github/branch-protection-master.json
```

## Rollback

Before Terraform applies a release, the workflow records every current ECS task
definition. A failed apply, stability wait, endpoint check, or alarm check redeploys
those task definitions and waits for the rollback to stabilize. Both the release
evidence and rollback map are retained as workflow artifacts for 30 days.

# Container release and rollback

For migration checkpoints, production execution, rollback authority and the full
evidence gate, use [P0-16–18 production release](PRODUCTION_RELEASE.md).

The controlled deployment accepts only immutable multi-platform ECR indexes. GitHub Actions builds `linux/amd64` and `linux/arm64`, attaches SBOM and provenance attestations, scans both child images, signs the GHCR index, and records compressed size changes. The deployment verifies that signature, copies the complete index to ECR, signs it again with the deployment identity, waits for ECR scans, and verifies the configured ECS architecture before Terraform runs.

## Required environment inputs

- `ROLLBACK_PROTECTED_UNTIL`: ISO date through which the immediate rollback images remain protected.
- `DATABASE_COMPATIBLE_UNTIL`: ISO date through which the prior images remain database-compatible.
- `DEEP_ROLLBACK_INVENTORY_JSON`: approved inventory using the `inventory` command's `{ "services": [...] }` format. Use an empty array only when no deeper rollback release has been approved.

The longer of the two dates controls removal. Vulnerability exceptions belong in `infra/security/container-vulnerability-policy.json` and require a vulnerability ID, affected services, owner, reason, and expiry date. Expired or incomplete exceptions fail CI. Runtime exceptions belong in `infra/security/runtime-hardening-exceptions.json` and require review before deployment.

## Inventory and lifecycle rehearsal

Capture every staging and production cluster before the first policy apply:

```bash
python3 scripts/ecr_release_control.py inventory \
  --cluster authclaw-staging-primary-cluster \
  --cluster authclaw-production-primary-cluster \
  --output deployed-image-inventory.json
```

The deployment creates unique `release-<commit>` and `rollback-<commit>-<service>` tags. The lifecycle policy expires only `candidate-` tags beyond 30 retained builds and handles untagged images in a separate 14-day rule. It cannot select `release-` or `rollback-` tags. Before Terraform applies the policy, the workflow runs an ECR lifecycle preview and rejects any result that would expire a deployed or protected digest.

Protection behaves as a transaction: every protected tag must be created before candidate tags are removed and the promotion record is written; a partial failure removes tags created by that attempt. Existing protected tags are never overwritten because repositories are immutable.

## Protection removal

After both compatibility windows close, capture the current deployment inventory and run:

```bash
python3 scripts/ecr_release_control.py unprotect \
  --record promotion-record.json \
  --current-inventory current-deployment-inventory.json
```

The command refuses early removal and refuses to unprotect any currently deployed digest. Retain the promotion record and lifecycle preview with the release evidence.

## Rollback drill

Use `previous-task-definitions.tsv` from the deployment artifact. Confirm each referenced image digest is present and carries its recorded rollback tag, verify the signature and scan evidence, update each ECS service to the recorded task definition, wait for service stability, and run health, authentication, gateway, audit publication, and ClickHouse consistency checks. Record start/end times, task definitions, image digests, checks, alarms, operator, and approver. Do not remove rollback protection until the drill succeeds and both compatibility windows close.
